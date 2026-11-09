package boxengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/telemetry"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// NodeProvider abstracts the dynamic discovery of active nodes and their Outbounds.
type NodeProvider interface {
	GetCandidates(poolTag string) []string
	GetOutbound(nodeID string) (adapter.Outbound, bool)
	IsSidecar(nodeID string) bool
}

// PoolOutboundOptions defines configuration for a PoolOutbound instance.
type PoolOutboundOptions struct {
	Tag               string
	PoolTag           string
	Tracker           *telemetry.Tracker
	FailureMonitor    *telemetry.FailureMonitor
	NodeProvider      NodeProvider
	OnTelemetryUpdate func()
	Blocker           *blocker.Engine
}

// PoolOutbound implements sing-box adapter.Outbound to dynamically route traffic across node pools.
type PoolOutbound struct {
	tag               string
	poolTag           string
	tracker           *telemetry.Tracker
	failureMonitor    *telemetry.FailureMonitor
	provider          NodeProvider
	onTelemetryUpdate func()
	blocker           *blocker.Engine
	mu                sync.RWMutex
}

// NewPoolOutbound creates a new adaptive proxy pool outbound.
func NewPoolOutbound(opts PoolOutboundOptions) *PoolOutbound {
	return &PoolOutbound{
		tag:               opts.Tag,
		poolTag:           opts.PoolTag,
		tracker:           opts.Tracker,
		failureMonitor:    opts.FailureMonitor,
		provider:          opts.NodeProvider,
		onTelemetryUpdate: opts.OnTelemetryUpdate,
		blocker:           opts.Blocker,
	}
}

func (p *PoolOutbound) Type() string {
	return "pool"
}

func (p *PoolOutbound) Tag() string {
	return p.tag
}

func (p *PoolOutbound) Network() []string {
	return []string{"tcp", "udp"}
}

func (p *PoolOutbound) Dependencies() []string {
	return nil
}

func extractTargetHost(ctx context.Context, destination M.Socksaddr) string {
	if destination.IsFqdn() || destination.Fqdn != "" {
		return destination.Fqdn
	}
	if ctx != nil {
		if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Domain != "" {
			return inboundCtx.Domain
		}
	}
	if destination.IsIP() {
		return destination.Addr.String()
	}
	return destination.AddrString()
}

// orderCandidates sorts candidate node IDs according to tracker affinity and quality score.
func (p *PoolOutbound) orderCandidates(candidates []string, targetHost string) []string {
	if len(candidates) <= 1 || p.tracker == nil {
		return candidates
	}

	bestID, _, hasBest := p.tracker.PeekBest(candidates, targetHost)

	// Sort remaining by score
	type candidateScore struct {
		id    string
		score float64
	}
	scores := make([]candidateScore, 0, len(candidates))
	for _, c := range candidates {
		sc := p.tracker.GetScore(c)
		scores = append(scores, candidateScore{id: c, score: sc.Score})
	}
	sort.SliceStable(scores, func(i, j int) bool {
		return scores[i].score < scores[j].score
	})

	ordered := make([]string, 0, len(candidates))
	if hasBest {
		ordered = append(ordered, bestID)
	}
	for _, s := range scores {
		if hasBest && s.id == bestID {
			continue
		}
		ordered = append(ordered, s.id)
	}
	return ordered
}

// SelectCandidate returns the top-ranked candidate node ID for targetHost in this pool.
func (p *PoolOutbound) SelectCandidate(targetHost string) string {
	if p.provider == nil {
		return ""
	}
	tagKey := p.poolTag
	if tagKey == "" {
		tagKey = p.tag
	}
	candidates := p.provider.GetCandidates(tagKey)
	if len(candidates) == 0 {
		return ""
	}
	ordered := p.orderCandidates(candidates, targetHost)
	if len(ordered) == 0 {
		return ""
	}
	return ordered[0]
}

func (p *PoolOutbound) resolveNodeName(candID string) string {
	if np, ok := p.provider.(interface{ GetNodeName(string) string }); ok {
		if name := np.GetNodeName(candID); name != "" {
			return name
		}
	}
	return candID
}

func formatConnectionError(err error) string {
	if err == nil {
		return ""
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "no active proxy") || strings.Contains(errStr, "no candidates") {
		return "节点未启动"
	}
	if errors.Is(err, errFirstPacketAborted) {
		return "首包未响应中断"
	}
	if errors.Is(err, io.EOF) || strings.Contains(errStr, "unexpected eof") || strings.Contains(errStr, "eof") {
		return "远端断开: EOF"
	}
	if strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "reset by peer") {
		return "连接重置: RST"
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return "连接超时"
	}
	if strings.Contains(errStr, "connection refused") {
		return "拒绝连接"
	}
	if strings.Contains(errStr, "handshake") || strings.Contains(errStr, "tls") {
		return "TLS握手失败"
	}
	return "连接失败"
}

func (p *PoolOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if p.provider == nil {
		return nil, errors.New("node provider is nil")
	}

	sourceKey := ""
	if inboundCtx := adapter.ContextFrom(ctx); inboundCtx != nil && inboundCtx.Source.Port != 0 {
		sourceKey = inboundCtx.Source.String()
	}

	tagKey := p.poolTag
	if tagKey == "" {
		tagKey = p.tag
	}

	candidates := p.provider.GetCandidates(tagKey)

	targetHost := extractTargetHost(ctx, destination)
	if p.blocker != nil && targetHost != "" && p.blocker.ShouldBlock(targetHost) {
		return nil, syscall.EPERM
	}
	if len(candidates) == 0 {
		err := fmt.Errorf("no active proxy candidates available for pool %s", tagKey)
		if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
			p.blocker.Logger().AnnotateBySource(sourceKey, "节点未启动")
		}
		if p.onTelemetryUpdate != nil {
			p.onTelemetryUpdate()
		}
		if p.failureMonitor != nil {
			p.failureMonitor.Record(telemetry.FailureEvent{
				Category:       telemetry.FailureProxy,
				Target:         targetHost,
				Port:           destination.Port,
				OriginalAction: p.tag,
				Error:          err,
			})
		}
		return nil, err
	}

	ordered := p.orderCandidates(candidates, targetHost)
	var lastErr error

	for _, candID := range ordered {
		ob, ok := p.provider.GetOutbound(candID)
		if !ok || ob == nil {
			continue
		}

		isSidecar := false
		if p.provider != nil {
			isSidecar = p.provider.IsSidecar(candID)
		}

		start := time.Now()
		conn, err := ob.DialContext(ctx, network, destination)
		rtt := time.Since(start)

		if err != nil {
			if p.tracker != nil {
				if isSidecar {
					p.tracker.RecordDial(candID, targetHost, 0, err)
				} else {
					p.tracker.RecordDial(candID, targetHost, rtt, err)
				}
			}
			if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
				p.blocker.Logger().AnnotateFailureBySource(sourceKey, formatConnectionError(err), rtt)
			}
			lastErr = err
			continue
		}

		if isSidecar && network == "tcp" {
			// Sidecar outbounds connect to localhost (127.0.0.1:allocPort).
			// Local loopback TCP acceptance does not mean the remote proxy tunnel succeeded.
			// Defer both dial success/failure and real internet TTFB RTT recording to wrapFirstRTTConn
			// so remote timeouts, resets, and blackholes accurately update SuccessRate and CircuitBreaker.
			destPort := destination.Port
			poolTag := p.tag
			singleCandidate := len(ordered) == 1
			var wasStalled bool
			conn = wrapFirstRTTConn(conn, func(realRTT time.Duration, firstErr error) {
				if p.tracker != nil {
					if !wasStalled || firstErr == nil {
						p.tracker.RecordDial(candID, targetHost, realRTT, firstErr)
					}
				}
				if firstErr != nil && sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
					p.blocker.Logger().AnnotateFailureBySource(sourceKey, formatConnectionError(firstErr), realRTT)
				} else if firstErr == nil && sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
					p.blocker.Logger().AnnotateDurationBySource(sourceKey, realRTT)
				}
				if firstErr != nil && p.failureMonitor != nil && singleCandidate {
					p.failureMonitor.Record(telemetry.FailureEvent{
						Category:       telemetry.FailureProxy,
						Target:         targetHost,
						Port:           destPort,
						OriginalAction: poolTag,
						Error:          firstErr,
					})
				}
				if p.onTelemetryUpdate != nil {
					p.onTelemetryUpdate()
				}
			}, func() {
				wasStalled = true
				if p.tracker != nil {
					p.tracker.RecordStall(candID, targetHost)
				}
				if p.onTelemetryUpdate != nil {
					p.onTelemetryUpdate()
				}
			})
		} else {
			if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
				p.blocker.Logger().AnnotateDurationBySource(sourceKey, rtt)
			}
			if p.tracker != nil {
				if isSidecar {
					p.tracker.RecordDial(candID, targetHost, 0, nil)
				} else {
					p.tracker.RecordDial(candID, targetHost, rtt, nil)
				}
			}
			if p.onTelemetryUpdate != nil {
				p.onTelemetryUpdate()
			}
		}
		return conn, nil
	}

	if lastErr == nil {
		lastErr = errors.New("all candidates skipped")
	}

	if sourceKey != "" && p.blocker != nil && p.blocker.Logger() != nil {
		p.blocker.Logger().AnnotateBySource(sourceKey, formatConnectionError(lastErr))
	}
	if p.onTelemetryUpdate != nil {
		p.onTelemetryUpdate()
	}

	if p.failureMonitor != nil {
		p.failureMonitor.Record(telemetry.FailureEvent{
			Category:       telemetry.FailureProxy,
			Target:         targetHost,
			Port:           destination.Port,
			OriginalAction: p.tag,
			Error:          lastErr,
		})
	}

	return nil, fmt.Errorf("all candidates failed in %s: %w", p.tag, lastErr)
}

func (p *PoolOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if p.provider == nil {
		return nil, errors.New("node provider is nil")
	}

	tagKey := p.poolTag
	if tagKey == "" {
		tagKey = p.tag
	}

	candidates := p.provider.GetCandidates(tagKey)

	targetHost := extractTargetHost(ctx, destination)
	if p.blocker != nil && targetHost != "" && p.blocker.ShouldBlock(targetHost) {
		return nil, syscall.EPERM
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no active proxy candidates for UDP packet in pool %s", tagKey)
	}

	ordered := p.orderCandidates(candidates, targetHost)
	var lastErr error

	for _, candID := range ordered {
		ob, ok := p.provider.GetOutbound(candID)
		if !ok || ob == nil {
			continue
		}

		conn, err := ob.ListenPacket(ctx, destination)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New("all candidates skipped for UDP")
	}
	return nil, fmt.Errorf("all candidates failed UDP in %s: %w", p.tag, lastErr)
}

const (
	minValidFirstRTT = 2 * time.Millisecond
	maxValidFirstRTT = 10 * time.Second
)

var (
	firstPacketTimeout = 8 * time.Second
	firstPacketStall   = 3500 * time.Millisecond
)

var errFirstPacketAborted = errors.New("connection closed before receiving first response byte")

type firstRTTConn struct {
	net.Conn
	onResult   func(rtt time.Duration, err error)
	onStall    func()
	writeTime  time.Time
	hasWritten bool
	done       bool
	stalled    bool
	stallTimer *time.Timer
	mu         sync.Mutex
}

func wrapFirstRTTConn(conn net.Conn, onResult func(rtt time.Duration, err error), onStall ...func()) net.Conn {
	if conn == nil {
		return nil
	}
	var stallFn func()
	if len(onStall) > 0 {
		stallFn = onStall[0]
	}
	return &firstRTTConn{
		Conn:     conn,
		onResult: onResult,
		onStall:  stallFn,
	}
}

func (c *firstRTTConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		c.mu.Lock()
		if !c.hasWritten {
			c.hasWritten = true
			c.writeTime = time.Now()
			if firstPacketTimeout > 0 {
				_ = c.Conn.SetReadDeadline(time.Now().Add(firstPacketTimeout))
			}
			if c.onStall != nil && firstPacketStall > 0 {
				c.stallTimer = time.AfterFunc(firstPacketStall, func() {
					c.mu.Lock()
					if !c.done && c.hasWritten && !c.stalled {
						c.stalled = true
						c.mu.Unlock()
						if c.onStall != nil {
							c.onStall()
						}
						return
					}
					c.mu.Unlock()
				})
			}
		}
		c.mu.Unlock()
	}
	n, err := c.Conn.Write(b)
	if err != nil {
		c.mu.Lock()
		if !c.done && c.hasWritten {
			c.done = true
			if c.stallTimer != nil {
				c.stallTimer.Stop()
			}
			_ = c.Conn.SetReadDeadline(time.Time{})
			var elapsed time.Duration
			if !c.writeTime.IsZero() {
				elapsed = time.Since(c.writeTime)
			}
			c.mu.Unlock()
			if c.onResult != nil {
				c.onResult(elapsed, err)
			}
			return n, err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *firstRTTConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if !c.done && c.hasWritten && !c.writeTime.IsZero() {
			c.done = true
			if c.stallTimer != nil {
				c.stallTimer.Stop()
			}
			_ = c.Conn.SetReadDeadline(time.Time{})
			rtt := time.Since(c.writeTime)
			c.mu.Unlock()
			if c.onResult != nil {
				sampleRTT := rtt
				if sampleRTT < minValidFirstRTT {
					sampleRTT = 0
				} else if sampleRTT > maxValidFirstRTT {
					sampleRTT = maxValidFirstRTT
				}
				c.onResult(sampleRTT, nil)
			}
		} else {
			c.mu.Unlock()
		}
		return n, err
	}
	if err != nil {
		c.mu.Lock()
		if !c.done && c.hasWritten {
			c.done = true
			if c.stallTimer != nil {
				c.stallTimer.Stop()
			}
			_ = c.Conn.SetReadDeadline(time.Time{})
			var elapsed time.Duration
			if !c.writeTime.IsZero() {
				elapsed = time.Since(c.writeTime)
			}
			c.mu.Unlock()
			if c.onResult != nil {
				c.onResult(elapsed, err)
			}
			return n, err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *firstRTTConn) Close() error {
	c.mu.Lock()
	if c.stallTimer != nil {
		c.stallTimer.Stop()
	}
	_ = c.Conn.SetReadDeadline(time.Time{})
	if !c.done && c.hasWritten {
		c.done = true
		var elapsed time.Duration
		if !c.writeTime.IsZero() {
			elapsed = time.Since(c.writeTime)
		}
		c.mu.Unlock()
		if c.onResult != nil {
			c.onResult(elapsed, errFirstPacketAborted)
		}
	} else {
		c.mu.Unlock()
	}
	return c.Conn.Close()
}

func (c *firstRTTConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
