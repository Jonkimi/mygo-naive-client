package warp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/wireguard-go/tai64n"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/http2"
)

const (
	defaultEndpointCacheTTL = 30 * time.Minute
	defaultFailCooldown     = 2 * time.Minute
	defaultProbeTimeout     = 1500 * time.Millisecond
	defaultRaceWindow       = 80 * time.Millisecond
	defaultRuntimeBatch     = 8
	defaultScanSamples      = 64
	defaultScanConcurrency  = 24
	defaultScanProbeTimeout = 2500 * time.Millisecond
	defaultScanProbeRounds  = 3
)

var (
	// MASQUEQUICAnycastCIDRs lists Cloudflare Consumer MASQUE QUIC (H3) Anycast IPv4 addresses.
	// Only .1 and .2 serve QUIC+TLS handshakes; other addresses in the /24 reject TLS over QUIC.
	MASQUEQUICAnycastCIDRs = []string{
		"162.159.198.1/32",
		"162.159.198.2/32",
	}

	// MASQUEQUICAnycastCIDRsV6 lists Cloudflare Consumer MASQUE QUIC (H3) Anycast IPv6 addresses.
	MASQUEQUICAnycastCIDRsV6 = []string{
		"2606:4700:103::1/128",
		"2606:4700:103::2/128",
		"2606:4700:104::1/128",
		"2606:4700:104::2/128",
	}

	// MASQUEAnycastCIDRs lists Cloudflare Consumer MASQUE HTTP/2 (TCP) Anycast IPv4 subnets.
	MASQUEAnycastCIDRs = []string{
		"162.159.198.0/24",
		"162.159.199.0/24",
	}

	// MASQUEAnycastCIDRsV6 lists Cloudflare Consumer MASQUE HTTP/2 (TCP) Anycast IPv6 subnets.
	MASQUEAnycastCIDRsV6 = []string{
		"2606:4700:103::/48",
		"2606:4700:104::/48",
	}

	// MASQUEPorts lists Cloudflare's official WARP MASQUE endpoint ports returned by the device API.
	MASQUEPorts = []int{443, 500, 1701, 4500, 4443, 8443, 8095}

	// WireGuardAnycastCIDRs lists Cloudflare WARP WireGuard Anycast IPv4 subnets.
	WireGuardAnycastCIDRs = []string{
		"162.159.192.0/24",
		"162.159.193.0/24",
		"162.159.195.0/24",
		"188.114.96.0/24",
		"188.114.97.0/24",
		"188.114.98.0/24",
		"188.114.99.0/24",
	}

	// WireGuardAnycastCIDRsV6 lists Cloudflare WARP WireGuard Anycast IPv6 subnets.
	WireGuardAnycastCIDRsV6 = []string{
		"2606:4700:d0::/48",
		"2606:4700:d1::/48",
	}

	// WireGuardPorts lists Cloudflare's official WARP WireGuard UDP ports (including anti-QoS ports).
	WireGuardPorts = []int{
		2408, 500, 1701, 4500,
		854, 859, 864, 878, 880, 890, 891, 894, 903, 908,
		928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988,
		1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506,
		3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956,
		7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}

	// DefaultMASQUERuntimeCandidates provides a starter pool of QUIC+H2-capable Anycast endpoints
	// across official MASQUE ports.
	DefaultMASQUERuntimeCandidates = []string{
		"162.159.198.1:443",
		"162.159.198.2:443",
		"162.159.198.1:8443",
		"162.159.198.2:4443",
		"162.159.198.1:500",
		"162.159.198.2:4500",
		"162.159.198.1:1701",
		"162.159.198.2:8095",
	}

	// DefaultMASQUEH2RuntimeCandidates provides a diverse starter pool across both HTTP/2 MASQUE subnets.
	DefaultMASQUEH2RuntimeCandidates = []string{
		"162.159.198.1:443",
		"162.159.199.1:443",
		"162.159.198.2:8443",
		"162.159.199.2:4443",
		"162.159.198.1:500",
		"162.159.199.1:4500",
		"162.159.198.2:1701",
		"162.159.199.2:8095",
	}

	// DefaultWireGuardRuntimeCandidates provides a diverse cross-subnet/cross-port starter pool.
	DefaultWireGuardRuntimeCandidates = []string{
		"162.159.192.1:2408",
		"162.159.193.1:2408",
		"162.159.195.1:2408",
		"188.114.96.1:2408",
		"188.114.97.1:500",
		"188.114.98.1:4500",
		"188.114.99.1:894",
		"162.159.195.2:7103",
	}

	masqueH2Subnet198 = netip.MustParsePrefix("162.159.198.0/24")
	masqueH2Subnet199 = netip.MustParsePrefix("162.159.199.0/24")
	masqueH2SubnetV6A = netip.MustParsePrefix("2606:4700:103::/48")
	masqueH2SubnetV6B = netip.MustParsePrefix("2606:4700:104::/48")
	masqueQUICHostSet = map[netip.Addr]bool{
		netip.MustParseAddr("162.159.198.1"):  true,
		netip.MustParseAddr("162.159.198.2"):  true,
		netip.MustParseAddr("2606:4700:103::1"): true,
		netip.MustParseAddr("2606:4700:103::2"): true,
		netip.MustParseAddr("2606:4700:104::1"): true,
		netip.MustParseAddr("2606:4700:104::2"): true,
	}
)

// isKnownMASQUEH2OnlyEndpoint reports whether endpoint's IP belongs to Cloudflare's MASQUE Anycast
// blocks yet is not one of the dedicated ::1/::2 addresses that accept QUIC+TLS handshakes.
func isKnownMASQUEH2OnlyEndpoint(endpoint string) bool {
	host := strings.TrimSpace(endpoint)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if masqueQUICHostSet[addr] {
		return false
	}
	return masqueH2Subnet198.Contains(addr) ||
		masqueH2Subnet199.Contains(addr) ||
		masqueH2SubnetV6A.Contains(addr) ||
		masqueH2SubnetV6B.Contains(addr)
}

// EndpointCacheKey isolates cached optimal endpoints per egress node scope and transport mode.
type EndpointCacheKey struct {
	ScopeKey string // "direct" or node tag (e.g. "node-us-1", "node-jp-1")
	Mode     Mode   // ModeMASQUE / ModeWireGuard
	TCPOnly  bool
}

// EndpointCandidateResult represents a probed WARP endpoint, its measured handshake RTT, and packet loss rate.
type EndpointCandidateResult struct {
	Endpoint string        `json:"endpoint"`
	Protocol string        `json:"protocol"` // "h3", "h2", "wireguard"
	RTT      time.Duration `json:"rtt"`
	LossRate float64       `json:"lossRate"` // 0.0 .. 1.0
	Sent     int           `json:"sent,omitempty"`
	Received int           `json:"received,omitempty"`
}

// Score ranks endpoints by preferring low packet loss first and low RTT second.
func (r EndpointCandidateResult) Score() time.Duration {
	return r.RTT + time.Duration(r.LossRate*float64(2*time.Second))
}

// ScanOptions configures deep scanning of Cloudflare Anycast endpoints.
type ScanOptions struct {
	Mode           Mode
	PreferH2       bool
	TCPOnly        bool
	IncludeIPv6    *bool // nil = auto-detect global IPv6 connectivity; non-nil forces on/off
	Dialer         Dialer
	Account        *Account
	Candidates     []string      // optional explicit candidate override (useful in tests)
	SampleCount    int           // defaults to 64 when Candidates is empty
	Concurrency    int           // defaults to 24
	ProbeRounds    int           // defaults to 3; number of probe rounds for packet-loss measurement
	PerProbeTimout time.Duration // defaults to 2500ms
	TopN           int           // defaults to 8 (<=0 returns all)
}

type cachedEndpointEntry struct {
	endpoint  string
	protocol  string
	rtt       time.Duration
	expiresAt time.Time
}

// EndpointSelector caches and concurrently selects the lowest-RTT healthy WARP endpoint per scope.
type EndpointSelector struct {
	mu          sync.RWMutex
	cache       map[EndpointCacheKey]cachedEndpointEntry
	failedUntil map[EndpointCacheKey]map[string]time.Time

	ttl          time.Duration
	failCooldown time.Duration
	probeTimeout time.Duration
	raceWindow   time.Duration

	masqueCandidates []string
	wgCandidates     []string

	masqueProbeFn func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, opts MASQUEOptions) (string, time.Duration, error)
	wgProbeFn     func(ctx context.Context, dialer Dialer, endpoint string, acc *Account) (time.Duration, error)
	nowFn         func() time.Time
}

// NewEndpointSelector creates an EndpointSelector with standard 30m cache TTL and 2m failure cooldown.
func NewEndpointSelector() *EndpointSelector {
	return &EndpointSelector{
		cache:            make(map[EndpointCacheKey]cachedEndpointEntry),
		failedUntil:      make(map[EndpointCacheKey]map[string]time.Time),
		ttl:              defaultEndpointCacheTTL,
		failCooldown:     defaultFailCooldown,
		probeTimeout:     defaultProbeTimeout,
		raceWindow:       defaultRaceWindow,
		masqueCandidates: append([]string(nil), DefaultMASQUERuntimeCandidates...),
		wgCandidates:     append([]string(nil), DefaultWireGuardRuntimeCandidates...),
		masqueProbeFn:    probeMASQUEEndpoint,
		wgProbeFn:        probeWireGuardEndpoint,
		nowFn:            time.Now,
	}
}

var defaultEndpointSelector = NewEndpointSelector()

// DefaultEndpointSelector returns the shared process-wide runtime EndpointSelector.
func DefaultEndpointSelector() *EndpointSelector {
	return defaultEndpointSelector
}

func (s *EndpointSelector) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

func (s *EndpointSelector) getCachedEntry(key EndpointCacheKey) (cachedEndpointEntry, bool) {
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.cache[key]
	if !ok || entry.endpoint == "" || now.After(entry.expiresAt) {
		return cachedEndpointEntry{}, false
	}
	if cooldowns := s.failedUntil[key]; cooldowns != nil {
		if until, bad := cooldowns[entry.endpoint]; bad && now.Before(until) {
			return cachedEndpointEntry{}, false
		}
	}
	return entry, true
}

func (s *EndpointSelector) isOnCooldown(key EndpointCacheKey, ep string) bool {
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if cooldowns := s.failedUntil[key]; cooldowns != nil {
		if until, bad := cooldowns[ep]; bad && now.Before(until) {
			return true
		}
	}
	return false
}

// GetCached returns the cached endpoint for key if present and unexpired.
func (s *EndpointSelector) GetCached(key EndpointCacheKey) (string, bool) {
	entry, ok := s.getCachedEntry(key)
	if !ok {
		return "", false
	}
	return entry.endpoint, true
}

// SetCached stores an endpoint in cache for key.
func (s *EndpointSelector) SetCached(key EndpointCacheKey, endpoint, protocol string, rtt time.Duration) {
	if strings.TrimSpace(endpoint) == "" {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[key] = cachedEndpointEntry{
		endpoint:  endpoint,
		protocol:  protocol,
		rtt:       rtt,
		expiresAt: now.Add(s.ttl),
	}
}

// MarkFailed invalidates any cached endpoint matching failedEndpoint for key and places it on cooldown.
func (s *EndpointSelector) MarkFailed(key EndpointCacheKey, failedEndpoint string) {
	failedEndpoint = strings.TrimSpace(failedEndpoint)
	if failedEndpoint == "" {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.cache[key]; ok && cur.endpoint == failedEndpoint {
		delete(s.cache, key)
	}
	if s.failedUntil[key] == nil {
		s.failedUntil[key] = make(map[string]time.Time)
	}
	s.failedUntil[key][failedEndpoint] = now.Add(s.failCooldown)
}

// InvalidateScope removes all cached entries for a given scopeKey.
func (s *EndpointSelector) InvalidateScope(scopeKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.cache {
		if k.ScopeKey == scopeKey {
			delete(s.cache, k)
		}
	}
	for k := range s.failedUntil {
		if k.ScopeKey == scopeKey {
			delete(s.failedUntil, k)
		}
	}
}

func (s *EndpointSelector) activeCandidates(key EndpointCacheKey, base []string) []string {
	now := s.now()
	s.mu.RLock()
	cooldowns := s.failedUntil[key]
	var healthy []string
	var cooled []string
	for _, ep := range base {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		if cooldowns != nil {
			if until, bad := cooldowns[ep]; bad && now.Before(until) {
				cooled = append(cooled, ep)
				continue
			}
		}
		healthy = append(healthy, ep)
	}
	s.mu.RUnlock()

	// If every candidate is currently cooled down, fall back to the full list so we don't deadlock.
	if len(healthy) == 0 {
		return cooled
	}
	if len(healthy) > defaultRuntimeBatch {
		return healthy[:defaultRuntimeBatch]
	}
	return healthy
}

// SelectMASQUEEndpoint chooses the fastest reachable MASQUE endpoint for scopeKey,
// using the per-scope cache when valid and otherwise probing candidates concurrently.
func (s *EndpointSelector) SelectMASQUEEndpoint(ctx context.Context, scopeKey string, dialer Dialer, acc *Account, opts MASQUEOptions) (EndpointCandidateResult, error) {
	if scopeKey == "" {
		scopeKey = "direct"
	}
	if dialer == nil {
		dialer = &defaultDialer{}
	}
	key := EndpointCacheKey{
		ScopeKey: scopeKey,
		Mode:     ModeMASQUE,
		TCPOnly:  opts.TCPOnly || opts.ForceH2,
	}
	if entry, ok := s.getCachedEntry(key); ok {
		return EndpointCandidateResult{
			Endpoint: entry.endpoint,
			Protocol: entry.protocol,
			RTT:      entry.rtt,
		}, nil
	}

	baseCandidates := s.masqueCandidates
	if (opts.TCPOnly || opts.ForceH2 || opts.PreferH2) && slices.Equal(s.masqueCandidates, DefaultMASQUERuntimeCandidates) {
		baseCandidates = DefaultMASQUEH2RuntimeCandidates
	}
	candidates := s.activeCandidates(key, baseCandidates)
	if scopeKey != "direct" && !opts.TCPOnly && !opts.ForceH2 {
		// Chained remote nodes can resolve Cloudflare's Anycast hostname remotely if IPs fail.
		const domainCandidate = "engage.cloudflareclient.com:443"
		hasDomain := false
		for _, c := range candidates {
			if strings.HasPrefix(c, "engage.cloudflareclient.com:") {
				hasDomain = true
				break
			}
		}
		if !hasDomain && len(candidates) < defaultRuntimeBatch && !s.isOnCooldown(key, domainCandidate) {
			candidates = append(candidates, domainCandidate)
		}
	}

	probeFn := s.masqueProbeFn
	if probeFn == nil {
		probeFn = probeMASQUEEndpoint
	}
	best, err := s.raceCandidates(ctx, candidates, func(pCtx context.Context, ep string) (EndpointCandidateResult, error) {
		proto, rtt, pErr := probeFn(pCtx, dialer, ep, acc, opts)
		if pErr != nil {
			return EndpointCandidateResult{}, pErr
		}
		return EndpointCandidateResult{
			Endpoint: ep,
			Protocol: proto,
			RTT:      rtt,
		}, nil
	})
	if err != nil {
		return EndpointCandidateResult{}, err
	}
	s.SetCached(key, best.Endpoint, best.Protocol, best.RTT)
	return best, nil
}

// SelectMASQUEAndConnect selects the best MASQUE endpoint for scopeKey and establishes a MASQUETunnel.
// If a cached endpoint fails to connect, it marks that endpoint failed and re-selects a healthy one.
func (s *EndpointSelector) SelectMASQUEAndConnect(ctx context.Context, scopeKey string, dialer Dialer, acc *Account, opts MASQUEOptions) (*MASQUETunnel, string, error) {
	if scopeKey == "" {
		scopeKey = "direct"
	}
	if dialer == nil {
		dialer = &defaultDialer{}
	}
	key := EndpointCacheKey{
		ScopeKey: scopeKey,
		Mode:     ModeMASQUE,
		TCPOnly:  opts.TCPOnly || opts.ForceH2,
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	// Fast path: if a cached endpoint exists, attempt direct tunnel connection without extra probe overhead.
	if cached, ok := s.GetCached(key); ok {
		tun, err := ConnectMASQUEWithOptions(ctx, dialer, cached, acc, opts)
		if err == nil {
			return tun, cached, nil
		}
		if !errors.Is(ctx.Err(), context.Canceled) && !errors.Is(err, context.Canceled) {
			s.MarkFailed(key, cached)
		}
		if ctx.Err() != nil {
			return nil, "", err
		}
	}

	// Concurrent selection via lightweight protocol probe.
	best, err := s.SelectMASQUEEndpoint(ctx, scopeKey, dialer, acc, opts)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", err
		}
		// Last-resort fallback to default endpoint.
		tun, fbErr := ConnectMASQUEWithOptions(ctx, dialer, DefaultMASQUEEndpoint, acc, opts)
		if fbErr != nil {
			return nil, "", fmt.Errorf("endpoint selection failed (%v) and default %s failed: %w", err, DefaultMASQUEEndpoint, fbErr)
		}
		s.SetCached(key, DefaultMASQUEEndpoint, tun.Protocol(), 0)
		return tun, DefaultMASQUEEndpoint, nil
	}

	tun, err := ConnectMASQUEWithOptions(ctx, dialer, best.Endpoint, acc, opts)
	if err != nil {
		if !errors.Is(ctx.Err(), context.Canceled) && !errors.Is(err, context.Canceled) {
			s.MarkFailed(key, best.Endpoint)
		}
		// Retry once with another candidate if context still has time.
		if ctx.Err() == nil {
			if second, sErr := s.SelectMASQUEEndpoint(ctx, scopeKey, dialer, acc, opts); sErr == nil && second.Endpoint != best.Endpoint {
				if tun2, err2 := ConnectMASQUEWithOptions(ctx, dialer, second.Endpoint, acc, opts); err2 == nil {
					return tun2, second.Endpoint, nil
				} else {
					if !errors.Is(ctx.Err(), context.Canceled) && !errors.Is(err2, context.Canceled) {
						s.MarkFailed(key, second.Endpoint)
					}
					if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err2, context.Canceled) {
						return nil, "", err2
					}
					return nil, "", errors.Join(err, err2)
				}
			}
		}
		return nil, "", err
	}
	return tun, best.Endpoint, nil
}

// SelectWireGuardEndpoint chooses the fastest reachable WireGuard endpoint for scopeKey.
func (s *EndpointSelector) SelectWireGuardEndpoint(ctx context.Context, scopeKey string, dialer Dialer, acc *Account) (EndpointCandidateResult, error) {
	if scopeKey == "" {
		scopeKey = "direct"
	}
	if dialer == nil {
		dialer = &defaultDialer{}
	}
	key := EndpointCacheKey{
		ScopeKey: scopeKey,
		Mode:     ModeWireGuard,
	}
	if entry, ok := s.getCachedEntry(key); ok {
		return EndpointCandidateResult{
			Endpoint: entry.endpoint,
			Protocol: "wireguard",
			RTT:      entry.rtt,
		}, nil
	}

	candidates := s.activeCandidates(key, s.wgCandidates)
	probeFn := s.wgProbeFn
	if probeFn == nil {
		probeFn = probeWireGuardEndpoint
	}
	best, err := s.raceCandidates(ctx, candidates, func(pCtx context.Context, ep string) (EndpointCandidateResult, error) {
		rtt, pErr := probeFn(pCtx, dialer, ep, acc)
		if pErr != nil {
			return EndpointCandidateResult{}, pErr
		}
		return EndpointCandidateResult{
			Endpoint: ep,
			Protocol: "wireguard",
			RTT:      rtt,
		}, nil
	})
	if err != nil {
		return EndpointCandidateResult{}, err
	}
	s.SetCached(key, best.Endpoint, "wireguard", best.RTT)
	return best, nil
}

func (s *EndpointSelector) raceCandidates(
	ctx context.Context,
	candidates []string,
	probe func(ctx context.Context, ep string) (EndpointCandidateResult, error),
) (EndpointCandidateResult, error) {
	if len(candidates) == 0 {
		return EndpointCandidateResult{}, errors.New("no candidate endpoints available")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	timeout := s.probeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	raceWindow := s.raceWindow
	if raceWindow <= 0 {
		raceWindow = defaultRaceWindow
	}

	resCh := make(chan EndpointCandidateResult, len(candidates))
	errCh := make(chan error, len(candidates))

	var wg sync.WaitGroup
	for _, ep := range candidates {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			pCtx, pCancel := context.WithTimeout(raceCtx, timeout)
			defer pCancel()
			res, err := probe(pCtx, endpoint)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			select {
			case resCh <- res:
			default:
			}
		}(ep)
	}

	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()
	defer func() {
		cancelRace()
		<-allDone
	}()

	var results []EndpointCandidateResult
	var windowTimer *time.Timer
	var windowCh <-chan time.Time
	var lastErr error

	for {
		select {
		case res := <-resCh:
			results = append(results, res)
			if windowTimer == nil {
				windowTimer = time.NewTimer(raceWindow)
				windowCh = windowTimer.C
			}
			if len(results) == len(candidates) {
				if windowTimer != nil {
					windowTimer.Stop()
				}
				return pickLowestRTT(results), nil
			}
		case err := <-errCh:
			lastErr = err
		case <-windowCh:
			return pickLowestRTT(results), nil
		case <-allDone:
			// Drain any queued successes that arrived simultaneously with allDone.
			for len(resCh) > 0 {
				results = append(results, <-resCh)
			}
			if windowTimer != nil {
				windowTimer.Stop()
			}
			if len(results) > 0 {
				return pickLowestRTT(results), nil
			}
			if lastErr != nil {
				return EndpointCandidateResult{}, fmt.Errorf("all %d endpoint probes failed (last error: %w)", len(candidates), lastErr)
			}
			return EndpointCandidateResult{}, fmt.Errorf("all %d endpoint probes failed", len(candidates))
		case <-ctx.Done():
			if windowTimer != nil {
				windowTimer.Stop()
			}
			if len(results) > 0 {
				return pickLowestRTT(results), nil
			}
			return EndpointCandidateResult{}, ctx.Err()
		}
	}
}

func pickLowestRTT(results []EndpointCandidateResult) EndpointCandidateResult {
	best := results[0]
	for _, r := range results[1:] {
		if r.RTT < best.RTT {
			best = r
		}
	}
	return best
}

// ScanBestEndpoints concurrently probes sampled Cloudflare Anycast endpoints and returns top results sorted by RTT.
func ScanBestEndpoints(ctx context.Context, opts ScanOptions) ([]EndpointCandidateResult, error) {
	return scanBestEndpointsWithProbers(ctx, opts, probeMASQUEEndpoint, probeWireGuardEndpoint)
}

type scanInitialHit struct {
	endpoint string
	protocol string
	rtt      time.Duration
}

func scanBestEndpointsWithProbers(
	ctx context.Context,
	opts ScanOptions,
	masqueProbe func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, mOpts MASQUEOptions) (string, time.Duration, error),
	wgProbe func(ctx context.Context, dialer Dialer, endpoint string, acc *Account) (time.Duration, error),
) ([]EndpointCandidateResult, error) {
	if opts.Dialer == nil {
		opts.Dialer = &defaultDialer{}
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultScanConcurrency
	}
	if opts.PerProbeTimout <= 0 {
		opts.PerProbeTimout = defaultScanProbeTimeout
	}
	if opts.SampleCount <= 0 {
		opts.SampleCount = defaultScanSamples
	}
	rounds := opts.ProbeRounds
	if rounds <= 0 {
		rounds = defaultScanProbeRounds
	}
	mode := opts.Mode
	if mode == "" || mode == ModeAuto {
		mode = ModeMASQUE
	}
	if opts.TCPOnly && mode == ModeWireGuard {
		mode = ModeMASQUE
	}

	includeIPv6 := false
	if opts.IncludeIPv6 != nil {
		includeIPv6 = *opts.IncludeIPv6
	} else if len(opts.Candidates) == 0 {
		includeIPv6 = hasGlobalIPv6()
	}

	var hits []scanInitialHit
	var lastErr error
	stage2ForceH2 := false

	if len(opts.Candidates) > 0 {
		hits, lastErr = sweepInitialCandidates(ctx, opts.Candidates, mode, MASQUEOptions{
			TCPOnly:  opts.TCPOnly,
			PreferH2: opts.PreferH2,
		}, opts, masqueProbe, wgProbe)
	} else if mode == ModeWireGuard {
		candidates := sampleWireGuardCandidatesWithIPv6(opts.SampleCount, includeIPv6)
		if len(candidates) == 0 {
			return nil, errors.New("no scan candidates generated")
		}
		hits, lastErr = sweepInitialCandidates(ctx, candidates, mode, MASQUEOptions{}, opts, masqueProbe, wgProbe)
	} else if opts.TCPOnly || opts.PreferH2 {
		candidates := sampleMASQUEH2Candidates(opts.SampleCount, includeIPv6)
		if len(candidates) == 0 {
			return nil, errors.New("no scan candidates generated")
		}
		hits, lastErr = sweepInitialCandidates(ctx, candidates, mode, MASQUEOptions{
			TCPOnly:  opts.TCPOnly,
			PreferH2: opts.PreferH2,
		}, opts, masqueProbe, wgProbe)
	} else {
		// QUIC-first MASQUE mode: Tier 1 tests dedicated ::1/::2 QUIC Anycast endpoints across all official ports.
		quicCandidates := sampleMASQUEQUICCandidates(opts.SampleCount, includeIPv6)
		if len(quicCandidates) == 0 {
			return nil, errors.New("no scan candidates generated")
		}
		hits, lastErr = sweepInitialCandidates(ctx, quicCandidates, mode, MASQUEOptions{}, opts, masqueProbe, wgProbe)

		hasH3 := slices.ContainsFunc(hits, func(h scanInitialHit) bool {
			return h.protocol == "h3"
		})
		if !hasH3 && ctx.Err() == nil {
			// UDP/QUIC produced no H3 hits; expand to Tier 2 full HTTP/2 subnets directly.
			stage2ForceH2 = true
			seen := make(map[string]bool, len(quicCandidates))
			for _, ep := range quicCandidates {
				seen[ep] = true
			}
			var h2Candidates []string
			for _, ep := range sampleMASQUEH2Candidates(opts.SampleCount, includeIPv6) {
				if !seen[ep] {
					h2Candidates = append(h2Candidates, ep)
				}
			}
			if len(h2Candidates) > 0 {
				h2Hits, h2Err := sweepInitialCandidates(ctx, h2Candidates, mode, MASQUEOptions{ForceH2: true}, opts, masqueProbe, wgProbe)
				hits = append(hits, h2Hits...)
				if h2Err != nil {
					lastErr = h2Err
				}
			}
		}
	}

	if len(hits) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("no reachable WARP endpoints found (%w)", lastErr)
		}
		return nil, errors.New("no reachable WARP endpoints found")
	}

	// Stage 2: Follow-up rounds on reachable endpoints (up to top 24 by initial RTT) to measure packet loss & average RTT.
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].rtt < hits[j].rtt
	})
	verifyLimit := 24
	if len(hits) < verifyLimit {
		verifyLimit = len(hits)
	}
	verifyHits := hits[:verifyLimit]

	var (
		mu      sync.Mutex
		results []EndpointCandidateResult
		sem     = make(chan struct{}, opts.Concurrency)
		wg2     sync.WaitGroup
	)
	for _, h := range verifyHits {
		wg2.Add(1)
		go func(hit scanInitialHit) {
			defer wg2.Done()
			sent := 1
			received := 1
			totalRTT := hit.rtt
			proto := hit.protocol

			cancelled := false
			for r := 1; r < rounds && !cancelled; r++ {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					cancelled = true
				}
				if cancelled {
					break
				}
				sent++
				pCtx, pCancel := context.WithTimeout(ctx, opts.PerProbeTimout)
				if mode == ModeWireGuard {
					rtt, err := wgProbe(pCtx, opts.Dialer, hit.endpoint, opts.Account)
					if err == nil {
						received++
						totalRTT += rtt
					}
				} else {
					p, rtt, err := masqueProbe(pCtx, opts.Dialer, hit.endpoint, opts.Account, MASQUEOptions{
						TCPOnly:  opts.TCPOnly,
						ForceH2:  stage2ForceH2,
						PreferH2: opts.PreferH2,
					})
					if err == nil {
						received++
						totalRTT += rtt
						if p != "" {
							proto = p
						}
					}
				}
				pCancel()
				<-sem
			}

			avgRTT := totalRTT / time.Duration(received)
			lossRate := float64(sent-received) / float64(sent)
			mu.Lock()
			results = append(results, EndpointCandidateResult{
				Endpoint: hit.endpoint,
				Protocol: proto,
				RTT:      avgRTT,
				LossRate: lossRate,
				Sent:     sent,
				Received: received,
			})
			mu.Unlock()
		}(h)
	}
	wg2.Wait()

	sort.Slice(results, func(i, j int) bool {
		si, sj := results[i].Score(), results[j].Score()
		if si == sj {
			if results[i].RTT == results[j].RTT {
				return results[i].Endpoint < results[j].Endpoint
			}
			return results[i].RTT < results[j].RTT
		}
		return si < sj
	})

	if opts.TopN > 0 && len(results) > opts.TopN {
		results = results[:opts.TopN]
	}
	return results, nil
}

func sweepInitialCandidates(
	ctx context.Context,
	candidates []string,
	mode Mode,
	mOpts MASQUEOptions,
	opts ScanOptions,
	masqueProbe func(ctx context.Context, dialer Dialer, endpoint string, acc *Account, mOpts MASQUEOptions) (string, time.Duration, error),
	wgProbe func(ctx context.Context, dialer Dialer, endpoint string, acc *Account) (time.Duration, error),
) ([]scanInitialHit, error) {
	var (
		mu      sync.Mutex
		hits    []scanInitialHit
		lastErr error
	)
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for _, ep := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			pCtx, pCancel := context.WithTimeout(ctx, opts.PerProbeTimout)
			defer pCancel()

			if mode == ModeWireGuard {
				rtt, err := wgProbe(pCtx, opts.Dialer, endpoint, opts.Account)
				mu.Lock()
				if err != nil {
					lastErr = err
				} else {
					hits = append(hits, scanInitialHit{endpoint: endpoint, protocol: "wireguard", rtt: rtt})
				}
				mu.Unlock()
				return
			}

			proto, rtt, err := masqueProbe(pCtx, opts.Dialer, endpoint, opts.Account, mOpts)
			mu.Lock()
			if err != nil {
				lastErr = err
			} else {
				hits = append(hits, scanInitialHit{endpoint: endpoint, protocol: proto, rtt: rtt})
			}
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
	return hits, lastErr
}

func sampleMASQUECandidates(count int) []string {
	return sampleCIDRPorts(MASQUEAnycastCIDRs, MASQUEPorts, count)
}

func sampleMASQUEQUICCandidates(count int, includeIPv6 bool) []string {
	if count <= 0 {
		return nil
	}
	v4 := enumerateHostPrefixesPorts(MASQUEQUICAnycastCIDRs, MASQUEPorts, count)
	if !includeIPv6 || len(v4) >= count {
		return v4
	}
	v6 := enumerateHostPrefixesPorts(MASQUEQUICAnycastCIDRsV6, MASQUEPorts, count-len(v4))
	return append(v4, v6...)
}

func sampleMASQUEH2Candidates(count int, includeIPv6 bool) []string {
	return sampleWithOptionalIPv6(MASQUEAnycastCIDRs, MASQUEAnycastCIDRsV6, MASQUEPorts, count, includeIPv6)
}

func sampleWireGuardCandidates(count int) []string {
	return sampleCIDRPorts(WireGuardAnycastCIDRs, WireGuardPorts, count)
}

func sampleWireGuardCandidatesWithIPv6(count int, includeIPv6 bool) []string {
	return sampleWithOptionalIPv6(WireGuardAnycastCIDRs, WireGuardAnycastCIDRsV6, WireGuardPorts, count, includeIPv6)
}

func sampleWithOptionalIPv6(v4CIDRs, v6CIDRs []string, ports []int, count int, includeIPv6 bool) []string {
	if count <= 0 {
		return nil
	}
	if !includeIPv6 || len(v6CIDRs) == 0 || count < 4 {
		return sampleCIDRPorts(v4CIDRs, ports, count)
	}
	v6Quota := min(count/4, 16)
	v4 := sampleCIDRPorts(v4CIDRs, ports, count-v6Quota)
	v6 := sampleCIDRPorts(v6CIDRs, ports, count-len(v4))
	return append(v4, v6...)
}

func enumerateHostPrefixesPorts(cidrs []string, ports []int, maxCount int) []string {
	if len(cidrs) == 0 || len(ports) == 0 || maxCount <= 0 {
		return nil
	}
	var addrs []netip.Addr
	for _, raw := range cidrs {
		if p, err := netip.ParsePrefix(raw); err == nil {
			addrs = append(addrs, p.Addr())
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(addrs)*len(ports), maxCount))
	// Iterate ports outer, addresses inner so primary ports across all Anycast IPs appear first.
	for _, port := range ports {
		portStr := strconv.Itoa(port)
		for _, addr := range addrs {
			out = append(out, net.JoinHostPort(addr.String(), portStr))
			if len(out) >= maxCount {
				return out
			}
		}
	}
	return out
}

func sampleCIDRPorts(cidrs []string, ports []int, count int) []string {
	if len(cidrs) == 0 || len(ports) == 0 || count <= 0 {
		return nil
	}
	var prefixes []netip.Prefix
	for _, raw := range cidrs {
		if p, err := netip.ParsePrefix(raw); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	if len(prefixes) == 0 {
		return nil
	}

	seen := make(map[string]bool, count)
	out := make([]string, 0, count)

	// Seed with .1 and .2 (or ::1 and ::2 for IPv6) on primary port for each subnet so well-known Anycast IPs are always covered.
	for _, p := range prefixes {
		for _, hostOctet := range []byte{1, 2} {
			if ip, ok := seedPrefixHost(p, hostOctet); ok {
				ep := net.JoinHostPort(ip.String(), strconv.Itoa(ports[0]))
				if !seen[ep] {
					seen[ep] = true
					out = append(out, ep)
					if len(out) >= count {
						return out
					}
				}
			}
		}
	}

	attempts := count * 6
	for i := 0; i < attempts && len(out) < count; i++ {
		p := prefixes[i%len(prefixes)]
		ip := randomIPInPrefix(p)
		port := ports[cryptoRandInt(len(ports))]
		ep := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		if !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out
}

func seedPrefixHost(p netip.Prefix, hostOctet byte) (netip.Addr, bool) {
	if p.Addr().Is4() {
		addr4 := p.Addr().As4()
		ip := netip.AddrFrom4([4]byte{addr4[0], addr4[1], addr4[2], hostOctet})
		return ip, p.Contains(ip)
	}
	if p.Addr().Is6() {
		addr16 := p.Masked().Addr().As16()
		addr16[15] = hostOctet
		ip := netip.AddrFrom16(addr16)
		return ip, p.Contains(ip)
	}
	return netip.Addr{}, false
}

func randomIPInPrefix(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		return randomIPv4InPrefix(p)
	}
	return randomIPv6InPrefix(p)
}

func randomIPv4InPrefix(p netip.Prefix) netip.Addr {
	base := p.Addr().As4()
	bits := p.Bits()
	if bits >= 31 {
		return p.Addr()
	}
	hostBits := 32 - bits
	maxHost := uint32(1) << hostBits
	// Avoid network (.0) and broadcast (.255) when hostBits >= 2.
	offset := uint32(1)
	if maxHost > 3 {
		offset += uint32(cryptoRandInt(int(maxHost - 2)))
	}
	baseVal := binary.BigEndian.Uint32(base[:])
	mask := ^uint32(0) << hostBits
	ipVal := (baseVal & mask) | offset
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], ipVal)
	return netip.AddrFrom4(out)
}

func randomIPv6InPrefix(p netip.Prefix) netip.Addr {
	masked := p.Masked()
	bits := masked.Bits()
	if bits >= 127 {
		return masked.Addr()
	}
	addr16 := masked.Addr().As16()
	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return masked.Addr()
	}
	// Preserve prefix bits and randomize host bits.
	for bit := bits; bit < 128; bit++ {
		byteIdx := bit / 8
		bitMask := byte(1 << (7 - (bit % 8)))
		if randBytes[byteIdx]&bitMask != 0 {
			addr16[byteIdx] |= bitMask
		} else {
			addr16[byteIdx] &^= bitMask
		}
	}
	ip := netip.AddrFrom16(addr16)
	if ip == masked.Addr() {
		addr16[15] |= 1
		ip = netip.AddrFrom16(addr16)
	}
	return ip
}

func cryptoRandInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

func subProbeContext(ctx context.Context, primaryFraction float64) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	remaining := time.Until(deadline)
	if remaining <= 200*time.Millisecond {
		return ctx, func() {}
	}
	budget := time.Duration(float64(remaining) * primaryFraction)
	if budget < 200*time.Millisecond {
		budget = 200 * time.Millisecond
	}
	return context.WithTimeout(ctx, budget)
}

// probeMASQUEEndpoint measures protocol-level MASQUE handshake RTT (TLS H2 or QUIC H3) to endpoint.
func probeMASQUEEndpoint(ctx context.Context, dialer Dialer, endpoint string, acc *Account, opts MASQUEOptions) (string, time.Duration, error) {
	if dialer == nil {
		dialer = &defaultDialer{}
	}
	baseTLS := &tls.Config{
		ServerName:         DefaultMASQUESNI,
		InsecureSkipVerify: true,
	}
	if acc != nil && acc.MASQUECertPEM != "" && acc.MASQUEPrivateKey != "" {
		if cert, err := ParseMASQUETLSCertificate(acc.MASQUECertPEM, acc.MASQUEPrivateKey); err == nil {
			baseTLS.Certificates = []tls.Certificate{cert}
		}
	}

	probeH2 := func(pCtx context.Context) (time.Duration, error) {
		start := time.Now()
		rawConn, err := dialer.DialContext(pCtx, "tcp", endpoint)
		if err != nil {
			return 0, err
		}
		var closeOnce sync.Once
		closeRaw := func() {
			closeOnce.Do(func() {
				_ = rawConn.Close()
			})
		}
		defer closeRaw()
		stopWatch := context.AfterFunc(pCtx, closeRaw)
		defer stopWatch()
		tlsCfg := baseTLS.Clone()
		tlsCfg.NextProtos = []string{"h2"}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(pCtx); err != nil {
			return 0, err
		}
		if len(baseTLS.Certificates) == 0 {
			return time.Since(start), nil
		}

		// Account credentials are enrolled: verify full HTTP/2 CONNECT-IP (cf-connect-ip)
		// instead of stopping at TLS handshake so DPI/blackhole endpoints are rejected.
		tmpl, err := uritemplate.New(DefaultMASQUEConnectURI)
		if err != nil {
			return 0, err
		}
		var usedFirstConn atomic.Bool
		h2Tr := &http2.Transport{
			DisableCompression: true,
			DialTLSContext: func(_ context.Context, _ string, _ string, _ *tls.Config) (net.Conn, error) {
				if usedFirstConn.CompareAndSwap(false, true) {
					return tlsConn, nil
				}
				rc, dErr := dialer.DialContext(pCtx, "tcp", endpoint)
				if dErr != nil {
					return nil, dErr
				}
				tc := tls.Client(rc, tlsCfg)
				if hErr := tc.HandshakeContext(pCtx); hErr != nil {
					_ = rc.Close()
					return nil, hErr
				}
				return tc, nil
			},
		}
		defer h2Tr.CloseIdleConnections()

		h2Headers := http.Header{
			"User-Agent":       []string{""},
			"cf-connect-proto": []string{"cf-connect-ip"},
			"pq-enabled":       []string{"false"},
		}
		ipConn, rsp, err := connectip.DialH2(pCtx, &http.Client{Transport: h2Tr}, tmpl, h2Headers)
		if err != nil {
			return 0, err
		}
		_ = ipConn.Close()
		if rsp == nil || rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
			status := "nil"
			if rsp != nil {
				status = rsp.Status
			}
			return 0, fmt.Errorf("HTTP/2 CONNECT rejected: %s", status)
		}
		return time.Since(start), nil
	}

	probeH3 := func(pCtx context.Context) (time.Duration, error) {
		pConn, err := dialer.ListenPacket(pCtx, "udp", endpoint)
		if err != nil {
			return 0, err
		}
		var closeOnce sync.Once
		closePConn := func() {
			closeOnce.Do(func() {
				_ = pConn.Close()
			})
		}
		defer closePConn()
		stopWatch := context.AfterFunc(pCtx, closePConn)
		defer stopWatch()

		rAddr, err := resolveMASQUEUDPAddr(pCtx, dialer, pConn, endpoint)
		if err != nil {
			return 0, err
		}

		qTr := &quic.Transport{
			Conn:               pConn,
			ConnectionIDLength: 20,
		}
		defer qTr.Close()

		tlsCfg := baseTLS.Clone()
		tlsCfg.NextProtos = []string{http3.NextProtoH3}
		start := time.Now()
		qConn, err := qTr.Dial(pCtx, rAddr, tlsCfg, &quic.Config{
			EnableDatagrams: true,
		})
		if err != nil {
			return 0, err
		}
		if len(baseTLS.Certificates) > 0 {
			h3Tr := &http3.Transport{
				EnableDatagrams:    true,
				DisableCompression: true,
				AdditionalSettings: map[uint64]uint64{
					0x276: 1, // SETTINGS_H3_DATAGRAM_00 required by Cloudflare
				},
			}
			clientConn := h3Tr.NewClientConn(qConn)
			tmpl, tErr := uritemplate.New(DefaultMASQUEConnectURI)
			if tErr != nil {
				_ = h3Tr.Close()
				_ = qConn.CloseWithError(0, "")
				return 0, tErr
			}
			ipConn, rsp, cErr := connectip.Dial(pCtx, clientConn, tmpl, "cf-connect-ip", http.Header{
				"User-Agent": []string{""},
			}, true)
			if cErr != nil {
				_ = h3Tr.Close()
				_ = qConn.CloseWithError(0, "")
				return 0, cErr
			}
			_ = ipConn.Close()
			_ = h3Tr.Close()
			if rsp == nil || rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
				status := "nil"
				if rsp != nil {
					status = rsp.Status
				}
				_ = qConn.CloseWithError(0, "")
				return 0, fmt.Errorf("HTTP/3 CONNECT rejected: %s", status)
			}
		}
		rtt := time.Since(start)
		_ = qConn.CloseWithError(0, "")
		return rtt, nil
	}

	if opts.TCPOnly || opts.ForceH2 || isKnownMASQUEH2OnlyEndpoint(endpoint) {
		rtt, err := probeH2(ctx)
		return "h2", rtt, err
	}
	if opts.PreferH2 {
		h2Ctx, h2Cancel := subProbeContext(ctx, 0.65)
		rtt, h2Err := probeH2(h2Ctx)
		h2Cancel()
		if h2Err == nil {
			return "h2", rtt, nil
		}
		if ctx.Err() != nil {
			return "", 0, ctx.Err()
		}
		rtt, err := probeH3(ctx)
		return "h3", rtt, err
	}

	h3Ctx, h3Cancel := subProbeContext(ctx, 0.6)
	rtt, h3Err := probeH3(h3Ctx)
	h3Cancel()
	if h3Err == nil {
		return "h3", rtt, nil
	}
	if ctx.Err() != nil {
		return "", 0, ctx.Err()
	}
	rtt, err := probeH2(ctx)
	return "h2", rtt, err
}

// probeWireGuardEndpoint sends a real WireGuard Handshake Initiation packet (with 3-byte Reserved)
// and awaits the 92-byte Handshake Response (Type=2) to measure true WireGuard RTT.
func probeWireGuardEndpoint(ctx context.Context, dialer Dialer, endpoint string, acc *Account) (time.Duration, error) {
	if dialer == nil {
		dialer = &defaultDialer{}
	}
	rAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return 0, err
	}

	var privKeyB64, peerPubB64 string
	var reserved [3]uint8
	if acc != nil {
		privKeyB64 = acc.WGPrivateKey
		peerPubB64 = acc.WGPeerPublicKey
		if len(acc.Reserved) == 3 {
			copy(reserved[:], acc.Reserved)
		}
	}
	if peerPubB64 == "" {
		peerPubB64 = DefaultWireGuardPubKey
	}

	var privKey [32]byte
	if privKeyB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(privKeyB64)
		if err == nil && len(raw) == 32 {
			copy(privKey[:], raw)
		}
	}
	if isAllZero32(privKey[:]) {
		if _, err := rand.Read(privKey[:]); err != nil {
			return 0, err
		}
		privKey[0] &= 248
		privKey[31] = (privKey[31] & 127) | 64
	}

	peerPubRaw, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil || len(peerPubRaw) != 32 {
		return 0, errors.New("invalid wireguard peer public key")
	}
	var peerPub [32]byte
	copy(peerPub[:], peerPubRaw)

	pkt, senderIdx, err := buildWGHandshakeInitiation(privKey, peerPub, reserved)
	if err != nil {
		return 0, err
	}

	pConn, err := dialer.ListenPacket(ctx, "udp", endpoint)
	if err != nil {
		return 0, err
	}
	defer pConn.Close()

	stopWatch := context.AfterFunc(ctx, func() {
		_ = pConn.Close()
	})
	defer stopWatch()

	if dl, ok := ctx.Deadline(); ok {
		_ = pConn.SetDeadline(dl)
	}

	start := time.Now()
	if _, err := pConn.WriteTo(pkt, rAddr); err != nil {
		return 0, err
	}

	buf := make([]byte, 256)
	for {
		n, _, err := pConn.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		if n == 92 && buf[0] == 2 {
			recvIdx := binary.LittleEndian.Uint32(buf[8:12])
			if recvIdx == senderIdx {
				return time.Since(start), nil
			}
		}
		// Type 3 (Cookie Reply, 64 bytes) also proves the remote WireGuard daemon processed MAC1.
		if n == 64 && buf[0] == 3 {
			recvIdx := binary.LittleEndian.Uint32(buf[4:8])
			if recvIdx == senderIdx {
				return time.Since(start), nil
			}
		}
	}
}

func isAllZero32(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

const (
	wgNoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier        = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	wgLabelMAC1         = "mac1----"
)

// buildWGHandshakeInitiation builds a 148-byte WireGuard Handshake Initiation packet
// with Cloudflare's 3-byte Reserved header injected in bytes [1:4].
func buildWGHandshakeInitiation(staticPriv, peerPub [32]byte, reserved [3]uint8) ([]byte, uint32, error) {
	var staticPub [32]byte
	curve25519.ScalarBaseMult(&staticPub, &staticPriv)

	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return nil, 0, err
	}
	ephPriv[0] &= 248
	ephPriv[31] = (ephPriv[31] & 127) | 64
	var ephPub [32]byte
	curve25519.ScalarBaseMult(&ephPub, &ephPriv)

	chainKey := blake2s.Sum256([]byte(wgNoiseConstruction))
	var hash [32]byte
	wgMixHash(&hash, &chainKey, []byte(wgIdentifier))
	wgMixHash(&hash, &hash, peerPub[:])

	// Message initiation fields
	pkt := make([]byte, 148)
	var idxBytes [4]byte
	if _, err := rand.Read(idxBytes[:]); err != nil {
		return nil, 0, err
	}
	senderIdx := binary.LittleEndian.Uint32(idxBytes[:])
	binary.LittleEndian.PutUint32(pkt[0:4], 1)
	binary.LittleEndian.PutUint32(pkt[4:8], senderIdx)
	copy(pkt[8:40], ephPub[:])

	wgMixKey(&chainKey, &chainKey, ephPub[:])
	wgMixHash(&hash, &hash, ephPub[:])

	ssEph, err := curve25519.X25519(ephPriv[:], peerPub[:])
	if err != nil {
		return nil, 0, err
	}
	var key [chacha20poly1305.KeySize]byte
	wgKDF2(&chainKey, &key, chainKey[:], ssEph)
	aead, _ := chacha20poly1305.New(key[:])
	var zeroNonce [chacha20poly1305.NonceSize]byte
	aead.Seal(pkt[40:40], zeroNonce[:], staticPub[:], hash[:])
	wgMixHash(&hash, &hash, pkt[40:88])

	ssStatic, err := curve25519.X25519(staticPriv[:], peerPub[:])
	if err != nil {
		return nil, 0, err
	}
	wgKDF2(&chainKey, &key, chainKey[:], ssStatic)
	ts := tai64n.Now()
	aead2, _ := chacha20poly1305.New(key[:])
	aead2.Seal(pkt[88:88], zeroNonce[:], ts[:], hash[:])

	// MAC1 computed over bytes [0:116] before injecting Reserved in [1:4] (or with zeroed [1:4]).
	mac1Hasher, _ := blake2s.New256(nil)
	mac1Hasher.Write([]byte(wgLabelMAC1))
	mac1Hasher.Write(peerPub[:])
	var mac1Key [32]byte
	mac1Hasher.Sum(mac1Key[:0])

	mac, _ := blake2s.New128(mac1Key[:])
	mac.Write(pkt[:116])
	mac.Sum(pkt[116:116])

	// Inject Cloudflare WARP 3-byte Reserved into header bytes [1:4]
	copy(pkt[1:4], reserved[:])

	return pkt, senderIdx, nil
}

func wgMixHash(dst, h *[32]byte, data []byte) {
	hasher, _ := blake2s.New256(nil)
	hasher.Write(h[:])
	hasher.Write(data)
	hasher.Sum(dst[:0])
}

func wgMixKey(dst, c *[32]byte, data []byte) {
	wgHMAC1(dst, c[:], data)
	wgHMAC1(dst, dst[:], []byte{0x1})
}

func wgKDF2(t0, t1 *[32]byte, key, input []byte) {
	var prk [32]byte
	wgHMAC1(&prk, key, input)
	wgHMAC1(t0, prk[:], []byte{0x1})
	wgHMAC2(t1, prk[:], t0[:], []byte{0x2})
}

func wgHMAC1(sum *[32]byte, key, in0 []byte) {
	// Standard 2-step HMAC-BLAKE2s matching wireguard-go/device/noise-helpers.go
	var ipad, opad [64]byte
	var k [32]byte
	if len(key) > 64 {
		k = blake2s.Sum256(key)
		copy(ipad[:], k[:])
		copy(opad[:], k[:])
	} else {
		copy(ipad[:], key)
		copy(opad[:], key)
	}
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	inner, _ := blake2s.New256(nil)
	inner.Write(ipad[:])
	inner.Write(in0)
	var innerSum [32]byte
	inner.Sum(innerSum[:0])

	outer, _ := blake2s.New256(nil)
	outer.Write(opad[:])
	outer.Write(innerSum[:])
	outer.Sum(sum[:0])
}

func wgHMAC2(sum *[32]byte, key, in0, in1 []byte) {
	var ipad, opad [64]byte
	var k [32]byte
	if len(key) > 64 {
		k = blake2s.Sum256(key)
		copy(ipad[:], k[:])
		copy(opad[:], k[:])
	} else {
		copy(ipad[:], key)
		copy(opad[:], key)
	}
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	inner, _ := blake2s.New256(nil)
	inner.Write(ipad[:])
	inner.Write(in0)
	inner.Write(in1)
	var innerSum [32]byte
	inner.Sum(innerSum[:0])

	outer, _ := blake2s.New256(nil)
	outer.Write(opad[:])
	outer.Write(innerSum[:])
	outer.Sum(sum[:0])
}
