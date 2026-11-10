package telemetry

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	ewmaAlpha                    = 0.2
	circuitFailureThreshold      = 3
	circuitRecoverySuccessTarget = 3
	circuitCooldownDuration      = 60 * time.Second
	hysteresisRTTDelta           = 30 * time.Millisecond
	hysteresisRatioDelta         = 0.20
	defaultInitialRTT            = 150 * time.Millisecond
	maxTrackerDomains            = 2000

	recentWindowSize             = 50
	severePacketLossRTT          = 3000 * time.Millisecond
	highLossMinSamples           = 5
	highLossSuccessRate          = 0.60
	multiDomainCorrelationWindow = 5 * time.Second
	multiDomainVetoThreshold     = 2
	probeHistorySize             = 5

	defaultProbeInterval  = 5 * time.Minute
	defaultIdleThreshold  = 60 * time.Second
	healthyProbeMaxRTT    = 300 * time.Millisecond
	idleWashFailuresCount = 2
)

type slowDomainRecord struct {
	root string
	at   time.Time
}

type NodeStats struct {
	EWMA                 time.Duration
	PassiveEWMA          time.Duration
	ProbeRTT             time.Duration
	MaxProbeRTT          time.Duration
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	TotalDials           int
	SuccessfulDials      int
	LastFailure          time.Time
	LastPassiveDial      time.Time
	circuitTrippedAt     time.Time
	samplesSinceRecovery int
	recentSlow           []slowDomainRecord
	probeHistory         [probeHistorySize]time.Duration
	probeCursor          int
	probeCount           int

	window    [recentWindowSize]bool
	winCursor int
	winCount  int
}

// recordProbeSample tracks probe latency in a 5-sample ring buffer and updates MaxProbeRTT jitter.
func (st *NodeStats) recordProbeSample(rtt time.Duration) {
	st.ProbeRTT = rtt
	st.probeHistory[st.probeCursor] = rtt
	st.probeCursor = (st.probeCursor + 1) % probeHistorySize
	if st.probeCount < probeHistorySize {
		st.probeCount++
	}
	var maxRTT time.Duration
	for i := 0; i < st.probeCount; i++ {
		if st.probeHistory[i] > maxRTT {
			maxRTT = st.probeHistory[i]
		}
	}
	st.MaxProbeRTT = maxRTT
}

// recordSlowDomain tracks stalled root domains in a 5s window and returns the count of unique stalled roots.
func (st *NodeStats) recordSlowDomain(root string, now time.Time) int {
	if root == "" {
		return 1
	}
	cutoff := now.Add(-multiDomainCorrelationWindow)
	n := 0
	for _, rec := range st.recentSlow {
		if rec.at.After(cutoff) {
			st.recentSlow[n] = rec
			n++
		}
	}
	st.recentSlow = append(st.recentSlow[:n], slowDomainRecord{root: root, at: now})

	unique := make(map[string]struct{}, len(st.recentSlow))
	for _, rec := range st.recentSlow {
		unique[rec.root] = struct{}{}
	}
	return len(unique)
}

// updateEffectiveEWMA synthesizes effective RTT from passive telemetry and active probe baseline.
// It implements pure Asymmetric Certainty without magic numbers:
// 1. Passive traffic naturally reflects the true distance to the current target cluster.
// 2. Active probe acts as a physical floor and executes an instant one-vote veto when degraded.
func (st *NodeStats) updateEffectiveEWMA() {
	if st.ProbeRTT == 0 {
		st.EWMA = st.PassiveEWMA
		return
	}
	if st.PassiveEWMA == 0 {
		st.EWMA = st.ProbeRTT
		return
	}
	st.EWMA = max(st.PassiveEWMA, st.ProbeRTT)
}

// decayStalePassiveLocked pulls stale PassiveEWMA towards current healthy probe RTT when the node has been idle.
// It applies exponential decay proportional to the elapsed idle time relative to the probe interval.
func (st *NodeStats) decayStalePassiveLocked(rtt time.Duration, probeInterval time.Duration, elapsed time.Duration) {
	if st.PassiveEWMA == 0 || st.PassiveEWMA <= rtt {
		return
	}
	if probeInterval <= 0 {
		probeInterval = defaultProbeInterval
	}
	decayRatio := 0.5
	if elapsed > probeInterval {
		intervals := float64(elapsed) / float64(probeInterval)
		decayRatio = 1.0 - math.Pow(0.5, intervals)
		if decayRatio < 0.5 {
			decayRatio = 0.5
		} else if decayRatio > 0.95 {
			decayRatio = 0.95
		}
	}
	delta := st.PassiveEWMA - rtt
	decayed := st.PassiveEWMA - time.Duration(float64(delta)*decayRatio)
	if decayed < rtt {
		decayed = rtt
	}
	st.PassiveEWMA = decayed
}

// washHistoricalFailures heals up to count oldest failures (false) in the sliding window to true,
// representing gradual recovery of past transient faults during healthy idle probes.
func (st *NodeStats) washHistoricalFailures(count int) int {
	if count <= 0 || st.SuccessfulDials >= st.TotalDials || st.winCount == 0 {
		return 0
	}
	fixed := 0
	start := 0
	if st.winCount == recentWindowSize {
		start = st.winCursor
	}
	for i := 0; i < st.winCount && fixed < count; i++ {
		idx := (start + i) % recentWindowSize
		if !st.window[idx] {
			st.window[idx] = true
			st.SuccessfulDials++
			fixed++
		}
	}
	return fixed
}

func (st *NodeStats) recordWindowSample(success bool) {
	st.samplesSinceRecovery++
	if st.winCount < recentWindowSize {
		st.window[st.winCursor] = success
		st.winCursor = (st.winCursor + 1) % recentWindowSize
		st.winCount++
		st.TotalDials = st.winCount
		if success {
			st.SuccessfulDials++
		}
		return
	}
	oldest := st.window[st.winCursor]
	if oldest {
		st.SuccessfulDials--
	}
	st.window[st.winCursor] = success
	st.winCursor = (st.winCursor + 1) % recentWindowSize
	if success {
		st.SuccessfulDials++
	}
	st.TotalDials = recentWindowSize
}

func (st *NodeStats) checkAndTripCircuit() {
	now := time.Now()
	st.LastFailure = now
	if st.ConsecutiveFailures >= circuitFailureThreshold {
		st.circuitTrippedAt = now
		return
	}
	if st.TotalDials >= highLossMinSamples && st.samplesSinceRecovery >= highLossMinSamples {
		sr := float64(st.SuccessfulDials) / float64(st.TotalDials)
		if sr < highLossSuccessRate {
			st.circuitTrippedAt = now
		}
	}
}

func (st *NodeStats) clearCircuit() {
	if !st.circuitTrippedAt.IsZero() {
		st.circuitTrippedAt = time.Time{}
		st.samplesSinceRecovery = 0
	}
}

type QualityScore struct {
	EWMA                time.Duration
	PassiveEWMA         time.Duration
	ProbeRTT            time.Duration
	MaxProbeRTT         time.Duration
	SuccessRate         float64
	Score               float64
	IsBroken            bool
	TotalDials          int
	SuccessfulDials     int
	ConsecutiveFailures int
	CircuitPenalty      float64
	LastPassiveDial     time.Time
}

// SiteFault represents an error caused by the remote target website rather than the proxy node.
type SiteFault interface {
	IsSiteFault() bool
}

type siteFaultWrapper struct {
	error
}

func (w *siteFaultWrapper) Unwrap() error { return w.error }
func (w *siteFaultWrapper) IsSiteFault() bool { return true }

// MarkSiteFault wraps an error indicating it was caused by the destination site rather than proxy failure.
func MarkSiteFault(err error) error {
	if err == nil {
		return nil
	}
	return &siteFaultWrapper{error: err}
}

// IsClientCanceled reports whether an error was caused by client cancellation (e.g. browser refresh or closed tab).
func IsClientCanceled(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "context canceled") || strings.Contains(errStr, "operation was canceled")
}

// IsSiteFault reports whether an error is attributable to the destination server rather than the proxy.
func IsSiteFault(err error) bool {
	if err == nil {
		return false
	}
	var sf SiteFault
	if errors.As(err, &sf) && sf.IsSiteFault() {
		return true
	}
	errStr := strings.ToLower(err.Error())
	// Target site certificate issues (e.g. expired, self-signed, host mismatch)
	if strings.Contains(errStr, "x509:") ||
		strings.Contains(errStr, "certificate is not trusted") ||
		strings.Contains(errStr, "bad certificate") ||
		strings.Contains(errStr, "tls: unknown authority") ||
		strings.Contains(errStr, "remote connection refused") ||
		strings.Contains(errStr, "site closed connection") {
		return true
	}
	return false
}

type Tracker struct {
	mu            sync.RWMutex
	nodes         map[string]*NodeStats
	affinity      map[string]string         // rootDomain -> nodeID
	domainErrors  map[string]map[string]int // rootDomain -> nodeID -> count
	probeInterval time.Duration             // configurable active probe interval, default 5m
	idleThreshold time.Duration             // passive idle threshold, default 60s
}

func NewTracker() *Tracker {
	return &Tracker{
		nodes:         make(map[string]*NodeStats),
		affinity:      make(map[string]string),
		domainErrors:  make(map[string]map[string]int),
		probeInterval: defaultProbeInterval,
		idleThreshold: defaultIdleThreshold,
	}
}

// SetProbeInterval updates the configured active probe interval (e.g. from app settings).
func (t *Tracker) SetProbeInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.probeInterval = d
}

// ProbeInterval returns the currently configured probe interval (or default 5m).
func (t *Tracker) ProbeInterval() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.probeInterval <= 0 {
		return defaultProbeInterval
	}
	return t.probeInterval
}

// SetIdleThreshold updates the idle duration threshold for passive traffic (default 60s).
func (t *Tracker) SetIdleThreshold(d time.Duration) {
	if d <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.idleThreshold = d
}

// IdleThreshold returns the currently configured idle threshold.
func (t *Tracker) IdleThreshold() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.idleThreshold <= 0 {
		return defaultIdleThreshold
	}
	return t.idleThreshold
}

// ExtractRootDomain extracts the effective root domain (eTLD+1 heuristic) from a host/domain.
func ExtractRootDomain(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" || net.ParseIP(host) != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	// Heuristic for common two-part TLDs like .com.cn, .co.uk, .org.cn
	if len(parts) >= 3 {
		lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if lastTwo == "com.cn" || lastTwo == "co.uk" || lastTwo == "org.cn" || lastTwo == "gov.cn" || lastTwo == "net.cn" {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (t *Tracker) RecordDial(nodeID string, targetHost string, rtt time.Duration, err error) {
	if IsClientCanceled(err) {
		// Client canceled connection (browser refresh, tab closed). Ignore completely to prevent F5 false-tripping.
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	root := ExtractRootDomain(targetHost)
	st, exists := t.nodes[nodeID]
	if !exists {
		st = &NodeStats{}
		t.nodes[nodeID] = st
	}
	st.LastPassiveDial = time.Now()

	if err != nil {
		// Site-level errors do not penalize node's global success rate or trip circuit breaker
		if IsSiteFault(err) {
			t.recordDomainFailureLocked(root, nodeID)
			return
		}

		st.recordSlowDomain(root, time.Now())
		st.recordWindowSample(false)
		st.ConsecutiveFailures++
		st.ConsecutiveSuccesses = 0
		st.checkAndTripCircuit()
		t.recordDomainFailureLocked(root, nodeID)
		return
	}

	if rtt > 0 {
		if st.PassiveEWMA == 0 {
			st.PassiveEWMA = rtt
		} else {
			st.PassiveEWMA = time.Duration((1.0-ewmaAlpha)*float64(st.PassiveEWMA) + ewmaAlpha*float64(rtt))
		}
		st.updateEffectiveEWMA()
	}

	// Connections that took >= severePacketLossRTT (3000ms) suffered multi-RTO packet loss stalls.
	if rtt >= severePacketLossRTT {
		uniqueSlowRoots := st.recordSlowDomain(root, time.Now())
		hasRecentProbeSpike := st.MaxProbeRTT >= 1000*time.Millisecond
		if uniqueSlowRoots >= multiDomainVetoThreshold || hasRecentProbeSpike {
			// Multi-domain correlation collapse OR recent probe jitter spike:
			// Strip single-domain immunity and hold the node accountable!
			st.recordWindowSample(false)
			st.ConsecutiveFailures++
			st.ConsecutiveSuccesses = 0
			st.checkAndTripCircuit()
			t.recordDomainFailureLocked(root, nodeID)
			return
		}

		// Single domain stall on a jitter-free line: isolate to domain level.
		// Evict affinity so the domain can test alternative nodes, but isolate from global node failure.
		t.recordDomainFailureLocked(root, nodeID)
		return
	}

	// Healthy success
	st.recordWindowSample(true)
	st.ConsecutiveFailures = 0
	st.ConsecutiveSuccesses++
	if st.ConsecutiveSuccesses >= circuitRecoverySuccessTarget ||
		st.TotalDials < highLossMinSamples ||
		float64(st.SuccessfulDials)/float64(st.TotalDials) >= highLossSuccessRate {
		st.clearCircuit()
	}

	if root != "" {
		if t.domainErrors[root] != nil {
			delete(t.domainErrors[root], nodeID)
		}
		if _, ok := t.affinity[root]; !ok {
			if len(t.affinity) >= maxTrackerDomains {
				for k := range t.affinity {
					delete(t.affinity, k)
					if len(t.affinity) < maxTrackerDomains/2 {
						break
					}
				}
			}
			t.affinity[root] = nodeID
		}
	}
}

func (t *Tracker) recordDomainFailureLocked(root string, nodeID string) {
	if root == "" {
		return
	}
	if len(t.domainErrors) >= maxTrackerDomains && t.domainErrors[root] == nil {
		for k := range t.domainErrors {
			delete(t.domainErrors, k)
			if len(t.domainErrors) < maxTrackerDomains/2 {
				break
			}
		}
	}
	if t.domainErrors[root] == nil {
		t.domainErrors[root] = make(map[string]int)
	}
	t.domainErrors[root][nodeID]++
	// Only evict affinity if we haven't exhausted alternative nodes for this domain.
	// If the domain has already stalled or failed across multiple distinct nodes (>= 2 nodes),
	// the origin server itself is inherently slow across the entire pool ("全池皆慢").
	// Stop evicting affinity to preserve session IP stickiness and prevent login dropouts!
	if t.affinity[root] == nodeID && len(t.domainErrors[root]) < 2 {
		delete(t.affinity, root)
	}
}

func (t *Tracker) clearNodeDomainErrorsLocked(nodeID string) {
	for root, m := range t.domainErrors {
		delete(m, nodeID)
		if len(m) == 0 {
			delete(t.domainErrors, root)
		}
	}
}

// RecordProbe records an active probe RTT measurement for nodeID into EWMA
// and counts the probe in the sliding window connectivity metrics.
// Probe measurements smaller than 1ms are ignored as local loopback artifacts.
func (t *Tracker) RecordProbe(nodeID string, rtt time.Duration) {
	if rtt < time.Millisecond {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	st, exists := t.nodes[nodeID]
	if !exists {
		st = &NodeStats{}
		t.nodes[nodeID] = st
	}
	st.recordProbeSample(rtt)

	now := time.Now()
	idleThresh := t.idleThreshold
	if idleThresh <= 0 {
		idleThresh = defaultIdleThreshold
	}
	isIdle := st.LastPassiveDial.IsZero() || now.Sub(st.LastPassiveDial) >= idleThresh

	probeInterval := t.probeInterval
	if probeInterval <= 0 {
		probeInterval = defaultProbeInterval
	}

	if rtt >= severePacketLossRTT {
		st.updateEffectiveEWMA()
		st.recordWindowSample(false)
		st.ConsecutiveFailures++
		st.ConsecutiveSuccesses = 0
		st.checkAndTripCircuit()
		return
	}

	// Healthy active probe:
	// 1. If the node is idle and was burdened by a stale high-latency passive EWMA,
	// decay PassiveEWMA towards current probe ground-truth RTT.
	if isIdle {
		var elapsed time.Duration
		if !st.LastPassiveDial.IsZero() {
			elapsed = now.Sub(st.LastPassiveDial)
		} else {
			elapsed = probeInterval
		}
		st.decayStalePassiveLocked(rtt, probeInterval, elapsed)
	}
	st.updateEffectiveEWMA()

	// 2. Push successful probe sample into sliding window.
	st.recordWindowSample(true)

	// 3. If the node is idle and probe result is genuinely healthy (rtt <= 300ms),
	// fast-wash up to 2 oldest historical failure records to accelerate recovery.
	if isIdle && rtt <= healthyProbeMaxRTT {
		st.washHistoricalFailures(idleWashFailuresCount)
	}

	st.ConsecutiveFailures = 0
	st.ConsecutiveSuccesses++
	st.clearCircuit()
	t.clearNodeDomainErrorsLocked(nodeID)
}

// ResetNode clears all telemetry stats, sticky domain affinities, and domain error records for nodeID.
func (t *Tracker) ResetNode(nodeID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.nodes, nodeID)
	t.clearNodeDomainErrorsLocked(nodeID)
	for root, affID := range t.affinity {
		if affID == nodeID {
			delete(t.affinity, root)
		}
	}
}

// RecordProbeFailure records an active probe failure (e.g. timeout or connection reset)
// into the node's success rate and consecutive failure circuit breaker metrics.
func (t *Tracker) RecordProbeFailure(nodeID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	st, exists := t.nodes[nodeID]
	if !exists {
		st = &NodeStats{}
		t.nodes[nodeID] = st
	}
	st.recordProbeSample(severePacketLossRTT)
	st.recordWindowSample(false)
	st.ConsecutiveFailures++
	st.ConsecutiveSuccesses = 0
	st.checkAndTripCircuit()
}

// RecordStall records an in-flight stall when a connection takes longer than severePacketLossRTT
// to receive its first response byte. It immediately evicts sticky domain affinity and penalizes
// the node so subsequent concurrent requests are not funneled into the blackhole.
func (t *Tracker) RecordStall(nodeID string, targetHost string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	root := ExtractRootDomain(targetHost)
	t.recordDomainFailureLocked(root, nodeID)

	st, exists := t.nodes[nodeID]
	if !exists {
		st = &NodeStats{}
		t.nodes[nodeID] = st
	}
	st.LastPassiveDial = time.Now()
	st.recordProbeSample(severePacketLossRTT)
	st.recordWindowSample(false)
	st.ConsecutiveFailures++
	st.ConsecutiveSuccesses = 0
	st.checkAndTripCircuit()
}

func isNodeBrokenLocked(st *NodeStats) bool {
	if st == nil || st.circuitTrippedAt.IsZero() {
		return false
	}
	return time.Since(st.circuitTrippedAt) < circuitCooldownDuration
}

func (t *Tracker) IsBroken(nodeID string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return false
	}
	return isNodeBrokenLocked(st)
}

func (t *Tracker) GetScore(nodeID string) QualityScore {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.getScoreLocked(nodeID)
}

func (t *Tracker) getScoreLocked(nodeID string) QualityScore {
	st, ok := t.nodes[nodeID]
	if !ok || (st.TotalDials == 0 && st.EWMA == 0) {
		return QualityScore{
			EWMA:                0,
			SuccessRate:         1.0,
			Score:               float64(defaultInitialRTT.Milliseconds()),
			IsBroken:            false,
			TotalDials:          0,
			SuccessfulDials:     0,
			ConsecutiveFailures: 0,
			CircuitPenalty:      0,
		}
	}

	sr := 1.0
	if st.TotalDials > 0 {
		sr = float64(st.SuccessfulDials) / float64(st.TotalDials)
		if sr < 0.1 {
			sr = 0.1
		}
	}

	isBroken := isNodeBrokenLocked(st)
	circuitPenalty := 0.0
	if isBroken {
		circuitPenalty = 10000.0 // 10s artificial penalty
	}

	rttMs := float64(st.EWMA.Milliseconds())
	if rttMs <= 0 {
		rttMs = float64(defaultInitialRTT.Milliseconds())
	}
	score := (rttMs / (sr * sr)) + circuitPenalty

	return QualityScore{
		EWMA:                st.EWMA,
		PassiveEWMA:         st.PassiveEWMA,
		ProbeRTT:            st.ProbeRTT,
		MaxProbeRTT:         st.MaxProbeRTT,
		SuccessRate:         sr,
		Score:               score,
		IsBroken:            isBroken,
		TotalDials:          st.TotalDials,
		SuccessfulDials:     st.SuccessfulDials,
		ConsecutiveFailures: st.ConsecutiveFailures,
		CircuitPenalty:      circuitPenalty,
		LastPassiveDial:     st.LastPassiveDial,
	}
}

// PeekBest predicts the best candidate node for targetHost without updating sticky affinity or taking a write lock.
func (t *Tracker) PeekBest(candidates []string, targetHost string) (string, QualityScore, bool) {
	if len(candidates) == 0 {
		return "", QualityScore{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.peekBestLocked(candidates, targetHost)
}

func (t *Tracker) peekBestLocked(candidates []string, targetHost string) (string, QualityScore, bool) {
	root := ExtractRootDomain(targetHost)

	// Filter out completely broken candidates if there is at least one non-broken candidate
	healthy := make([]string, 0, len(candidates))
	for _, id := range candidates {
		sc := t.getScoreLocked(id)
		if !sc.IsBroken {
			healthy = append(healthy, id)
		}
	}
	pool := healthy
	if len(pool) == 0 {
		pool = candidates
	}

	// Filter by domain errors if possible
	if root != "" && len(pool) > 1 && t.domainErrors[root] != nil {
		var domainClean []string
		for _, id := range pool {
			if t.domainErrors[root][id] == 0 {
				domainClean = append(domainClean, id)
			}
		}
		if len(domainClean) > 0 {
			pool = domainClean
		}
	}

	// Check if current affinity node is available in pool
	currentAffinity := ""
	if root != "" {
		if aff, ok := t.affinity[root]; ok {
			for _, id := range pool {
				if id == aff {
					currentAffinity = aff
					break
				}
			}
		}
	}

	// Find the candidate with minimum score
	var bestID string
	var minScore float64 = -1
	var bestScore QualityScore
	for _, id := range pool {
		sc := t.getScoreLocked(id)
		if minScore < 0 || sc.Score < minScore {
			minScore = sc.Score
			bestID = id
			bestScore = sc
		}
	}

	if bestID == "" {
		return "", QualityScore{}, false
	}

	// If we have an existing healthy affinity node, check sticky hysteresis
	if currentAffinity != "" {
		currScore := t.getScoreLocked(currentAffinity)
		delta := currScore.Score - minScore
		deltaDur := time.Duration(delta) * time.Millisecond

		// In survival "比烂" mode (when all candidates in pool are broken / degraded):
		// 1. Strip the identical artificial circuit penalty (10000ms) so ratio reflects real network margin.
		// 2. Raise the switching threshold from 20% to 40% (ratio > 0.40) to suppress pointless thrashing.
		currBaseline := currScore.Score
		reqRatio := hysteresisRatioDelta
		if len(healthy) == 0 {
			reqRatio = 0.40
			currBaseline = currScore.Score - currScore.CircuitPenalty
			if currBaseline <= 0 {
				currBaseline = 1.0
			}
		}
		ratio := delta / currBaseline

		// Only switch if faster by > 30ms and > reqRatio
		if deltaDur > hysteresisRTTDelta && ratio > reqRatio {
			return bestID, bestScore, true
		}
		return currentAffinity, currScore, true
	}

	return bestID, bestScore, true
}

func (t *Tracker) SelectBest(candidates []string, targetHost string) (string, bool) {
	if len(candidates) == 0 {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	chosenID, _, ok := t.peekBestLocked(candidates, targetHost)
	if !ok {
		return "", false
	}
	root := ExtractRootDomain(targetHost)
	if root != "" && chosenID != "" {
		t.affinity[root] = chosenID
	}
	return chosenID, true
}
