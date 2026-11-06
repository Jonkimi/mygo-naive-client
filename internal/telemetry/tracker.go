package telemetry

import (
	"net"
	"strings"
	"sync"
	"time"
)

const (
	ewmaAlpha             = 0.2
	circuitFailureThreshold = 3
	circuitCooldownDuration = 60 * time.Second
	hysteresisRTTDelta      = 30 * time.Millisecond
	hysteresisRatioDelta    = 0.20
	defaultInitialRTT       = 150 * time.Millisecond
	maxTrackerDomains       = 2000
)

type NodeStats struct {
	EWMA                time.Duration
	ConsecutiveFailures int
	TotalDials          int
	SuccessfulDials     int
	LastFailure         time.Time
}

type QualityScore struct {
	EWMA        time.Duration
	SuccessRate float64
	Score       float64
	IsBroken    bool
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

	st.TotalDials++
	if err != nil {
		st.ConsecutiveFailures++
		st.LastFailure = time.Now()
		if root != "" {
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
		return
	}

	// Success
	st.ConsecutiveFailures = 0
	st.SuccessfulDials++
	if st.EWMA == 0 {
		st.EWMA = rtt
	} else {
		st.EWMA = time.Duration((1.0-ewmaAlpha)*float64(st.EWMA) + ewmaAlpha*float64(rtt))
	}

	if root != "" {
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

func (t *Tracker) IsBroken(nodeID string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return false
	}
	if st.ConsecutiveFailures >= circuitFailureThreshold {
		if time.Since(st.LastFailure) < circuitCooldownDuration {
			return true
		}
	}
	return false
}

func (t *Tracker) GetScore(nodeID string) QualityScore {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.getScoreLocked(nodeID)
}

func (t *Tracker) getScoreLocked(nodeID string) QualityScore {
	st, ok := t.nodes[nodeID]
	if !ok || st.TotalDials == 0 {
		return QualityScore{
			EWMA:        defaultInitialRTT,
			SuccessRate: 1.0,
			Score:       float64(defaultInitialRTT.Milliseconds()),
			IsBroken:    false,
		}
	}

	sr := float64(st.SuccessfulDials) / float64(st.TotalDials)
	if sr < 0.1 {
		sr = 0.1
	}

	isBroken := false
	circuitPenalty := 0.0
	if st.ConsecutiveFailures >= circuitFailureThreshold {
		if time.Since(st.LastFailure) < circuitCooldownDuration {
			isBroken = true
			circuitPenalty = 10000.0 // 10s artificial penalty
		}
	}

	rttMs := float64(st.EWMA.Milliseconds())
	if rttMs <= 0 {
		rttMs = float64(defaultInitialRTT.Milliseconds())
	}
	score := (rttMs / (sr * sr)) + circuitPenalty

	return QualityScore{
		EWMA:        st.EWMA,
		SuccessRate: sr,
		Score:       score,
		IsBroken:    isBroken,
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
