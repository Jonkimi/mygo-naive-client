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
}

// PoolOutboundOptions defines configuration for a PoolOutbound instance.
type PoolOutboundOptions struct {
	Tag            string
	PoolTag        string
	Tracker        *telemetry.Tracker
	FailureMonitor *telemetry.FailureMonitor
	NodeProvider   NodeProvider
	OnDialSuccess  func(targetHost string, nodeID string)
}

// PoolOutbound implements sing-box adapter.Outbound to dynamically route traffic across node pools.
type PoolOutbound struct {
	tag            string
	poolTag        string
	tracker        *telemetry.Tracker
	failureMonitor *telemetry.FailureMonitor
	provider       NodeProvider
	onDialSuccess  func(targetHost string, nodeID string)
	mu             sync.RWMutex
}

// NewPoolOutbound creates a new adaptive proxy pool outbound.
func NewPoolOutbound(opts PoolOutboundOptions) *PoolOutbound {
	return &PoolOutbound{
		tag:            opts.Tag,
		poolTag:        opts.PoolTag,
		tracker:        opts.Tracker,
		failureMonitor: opts.FailureMonitor,
		provider:       opts.NodeProvider,
		onDialSuccess:  opts.OnDialSuccess,
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

func extractTargetHost(destination M.Socksaddr) string {
	if destination.IsFqdn() || destination.Fqdn != "" {
		return destination.Fqdn
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

	targetHost := extractTargetHost(destination)
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

		start := time.Now()
		conn, err := ob.DialContext(ctx, network, destination)
		rtt := time.Since(start)

		if p.tracker != nil {
			p.tracker.RecordDial(candID, targetHost, rtt, err)
		}

		if err == nil {
			if p.onDialSuccess != nil {
				p.onDialSuccess(targetHost, candID)
			}
			return conn, nil
		}
		lastErr = err
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

	targetHost := extractTargetHost(destination)
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
