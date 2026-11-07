package boxengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

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
	OnDialSuccess     func(targetHost string, nodeID string)
	OnTelemetryUpdate func()
}

// PoolOutbound implements sing-box adapter.Outbound to dynamically route traffic across node pools.
type PoolOutbound struct {
	tag               string
	poolTag           string
	tracker           *telemetry.Tracker
	failureMonitor    *telemetry.FailureMonitor
	provider          NodeProvider
	onDialSuccess     func(targetHost string, nodeID string)
	onTelemetryUpdate func()
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
		onDialSuccess:     opts.OnDialSuccess,
		onTelemetryUpdate: opts.OnTelemetryUpdate,
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

func (p *PoolOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if p.provider == nil {
		return nil, errors.New("node provider is nil")
	}

	tagKey := p.poolTag
	if tagKey == "" {
		tagKey = p.tag
	}

	candidates := p.provider.GetCandidates(tagKey)

	targetHost := extractTargetHost(ctx, destination)
	if len(candidates) == 0 {
		err := fmt.Errorf("no active proxy candidates available for pool %s", tagKey)
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
			lastErr = err
			continue
		}

		if p.onDialSuccess != nil {
			p.onDialSuccess(targetHost, candID)
		}

		if isSidecar && network == "tcp" {
			// Sidecar outbounds connect to localhost (127.0.0.1:allocPort).
			// Local loopback TCP acceptance does not mean the remote proxy tunnel succeeded.
			// Defer both dial success/failure and real internet TTFB RTT recording to wrapFirstRTTConn
			// so remote timeouts, resets, and blackholes accurately update SuccessRate and CircuitBreaker.
			destPort := destination.Port
			poolTag := p.tag
			singleCandidate := len(ordered) == 1
			conn = wrapFirstRTTConn(conn, func(realRTT time.Duration, firstErr error) {
				if p.tracker != nil {
					p.tracker.RecordDial(candID, targetHost, realRTT, firstErr)
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
			})
		} else {
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
			if p.onDialSuccess != nil {
				p.onDialSuccess(targetHost, candID)
			}
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

var errFirstPacketAborted = errors.New("connection closed before receiving first response byte")

type firstRTTConn struct {
	net.Conn
	onResult   func(rtt time.Duration, err error)
	writeTime  time.Time
	hasWritten bool
	done       bool
	mu         sync.Mutex
}

func wrapFirstRTTConn(conn net.Conn, onResult func(rtt time.Duration, err error)) net.Conn {
	if conn == nil {
		return nil
	}
	return &firstRTTConn{
		Conn:     conn,
		onResult: onResult,
	}
}

func (c *firstRTTConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		c.mu.Lock()
		if !c.hasWritten {
			c.hasWritten = true
			c.writeTime = time.Now()
		}
		c.mu.Unlock()
	}
	n, err := c.Conn.Write(b)
	if err != nil {
		c.mu.Lock()
		if !c.done && c.hasWritten {
			c.done = true
			c.mu.Unlock()
			if c.onResult != nil {
				c.onResult(0, err)
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
			c.mu.Unlock()
			if c.onResult != nil {
				c.onResult(0, err)
			}
			return n, err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *firstRTTConn) Close() error {
	c.mu.Lock()
	if !c.done && c.hasWritten {
		c.done = true
		c.mu.Unlock()
		if c.onResult != nil {
			c.onResult(0, errFirstPacketAborted)
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
