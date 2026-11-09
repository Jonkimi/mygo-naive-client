package telemetry

import (
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

	recentWindowSize    = 50
	severePacketLossRTT = 3000 * time.Millisecond
	highLossMinSamples  = 5
	highLossSuccessRate = 0.60
)

type NodeStats struct {
	EWMA                 time.Duration
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	TotalDials           int
	SuccessfulDials      int
	LastFailure          time.Time
	circuitTrippedAt     time.Time
	samplesSinceRecovery int

	window    [recentWindowSize]bool
	winCursor int
	winCount  int
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
	SuccessRate         float64
	Score               float64
	IsBroken            bool
	TotalDials          int
	SuccessfulDials     int
	ConsecutiveFailures int
	CircuitPenalty      float64
}

type Tracker struct {
	mu           sync.RWMutex
	nodes        map[string]*NodeStats
	affinity     map[string]string            // rootDomain -> nodeID
	domainErrors map[string]map[string]int     // rootDomain -> nodeID -> count
}

func NewTracker() *Tracker {
	return &Tracker{
		nodes:        make(map[string]*NodeStats),
		affinity:     make(map[string]string),
		domainErrors: make(map[string]map[string]int),
	}
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
	t.mu.Lock()
	defer t.mu.Unlock()

	root := ExtractRootDomain(targetHost)
	st, exists := t.nodes[nodeID]
	if !exists {
		st = &NodeStats{}
		t.nodes[nodeID] = st
	}

	if err != nil {
		st.recordWindowSample(false)
		st.ConsecutiveFailures++
		st.ConsecutiveSuccesses = 0
		st.checkAndTripCircuit()
		t.recordDomainFailureLocked(root, nodeID)
		return
	}

	if rtt > 0 {
		if st.EWMA == 0 {
			st.EWMA = rtt
		} else {
			st.EWMA = time.Duration((1.0-ewmaAlpha)*float64(st.EWMA) + ewmaAlpha*float64(rtt))
		}
	}

	// Connections that took >= severePacketLossRTT (3000ms) suffered multi-RTO packet loss stalls.
	// Treat them as degraded attempts: increment ConsecutiveFailures, evict sticky affinity, and check circuit breaker.
	if rtt >= severePacketLossRTT {
		st.recordWindowSample(false)
		st.ConsecutiveFailures++
		st.ConsecutiveSuccesses = 0
		st.checkAndTripCircuit()
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
	if t.affinity[root] == nodeID {
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
	if st.EWMA == 0 {
		st.EWMA = rtt
	} else {
		st.EWMA = time.Duration((1.0-ewmaAlpha)*float64(st.EWMA) + ewmaAlpha*float64(rtt))
	}
	if rtt >= severePacketLossRTT {
		st.recordWindowSample(false)
		st.ConsecutiveFailures++
		st.ConsecutiveSuccesses = 0
		st.checkAndTripCircuit()
		return
	}
	st.recordWindowSample(true)
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
		SuccessRate:         sr,
		Score:               score,
		IsBroken:            isBroken,
		TotalDials:          st.TotalDials,
		SuccessfulDials:     st.SuccessfulDials,
		ConsecutiveFailures: st.ConsecutiveFailures,
		CircuitPenalty:      circuitPenalty,
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
		ratio := delta / currScore.Score

		// Only switch if faster by > 30ms and > 20%
		if deltaDur > hysteresisRTTDelta && ratio > hysteresisRatioDelta {
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
