package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Tests that EWMA RTT updates smoothly with alpha = 0.2 and penalizes consecutive failures.
func TestTracker_EWMAAndCircuitBreaker(t *testing.T) {
	tr := NewTracker()

	nodeA := "node-a"

	// Initial dial: 100ms
	tr.RecordDial(nodeA, "example.com", 100*time.Millisecond, nil)
	score1 := tr.GetScore(nodeA)
	if score1.EWMA != 100*time.Millisecond {
		t.Fatalf("expected initial EWMA = 100ms, got %v", score1.EWMA)
	}

	// Second dial: 50ms -> EWMA = 0.8 * 100ms + 0.2 * 50ms = 80ms + 10ms = 90ms
	tr.RecordDial(nodeA, "example.com", 50*time.Millisecond, nil)
	score2 := tr.GetScore(nodeA)
	if score2.EWMA != 90*time.Millisecond {
		t.Fatalf("expected EWMA = 90ms, got %v", score2.EWMA)
	}

	// 3 consecutive failures triggers circuit breaker
	testErr := errors.New("connection refused")
	tr.RecordDial(nodeA, "example.com", 0, testErr)
	tr.RecordDial(nodeA, "example.com", 0, testErr)
	if tr.IsBroken(nodeA) {
		t.Fatalf("expected nodeA not broken after 2 failures")
	}

	tr.RecordDial(nodeA, "example.com", 0, testErr)
	if !tr.IsBroken(nodeA) {
		t.Fatalf("expected nodeA broken after 3 consecutive failures")
	}
}

// Tests that candidate selection respects sticky hysteresis (>30ms and >20%) and domain affinity.
func TestTracker_AffinityAndStickySelection(t *testing.T) {
	tr := NewTracker()

	nodeA := "node-a"
	nodeB := "node-b"

	// nodeA has 100ms RTT, nodeB has 90ms RTT (diff is 10ms, < 30ms threshold)
	tr.RecordDial(nodeA, "api.openai.com", 100*time.Millisecond, nil)
	tr.RecordDial(nodeB, "api.openai.com", 90*time.Millisecond, nil)

	// Since nodeA is already affinity for openai.com, nodeB (90ms) is not >30ms faster, so keep nodeA
	best, ok := tr.SelectBest([]string{nodeA, nodeB}, "api.openai.com")
	if !ok || best != nodeA {
		t.Fatalf("expected sticky nodeA retained, got %v (ok=%v)", best, ok)
	}

	// If nodeB becomes significantly faster over consecutive requests (EWMA drops well below 70ms: diff > 30ms, ratio > 20%)
	tr.RecordDial(nodeB, "api.openai.com", 20*time.Millisecond, nil)
	tr.RecordDial(nodeB, "api.openai.com", 20*time.Millisecond, nil)
	tr.RecordDial(nodeB, "api.openai.com", 20*time.Millisecond, nil)
	best2, ok2 := tr.SelectBest([]string{nodeA, nodeB}, "api.openai.com")
	if !ok2 || best2 != nodeB {
		t.Fatalf("expected switch to nodeB, got %v", best2)
	}

	// If nodeB fails for openai.com, automatic escape failover back to nodeA
	tr.RecordDial(nodeB, "auth.openai.com", 0, errors.New("tls alert: blocked"))
	best3, ok3 := tr.SelectBest([]string{nodeA, nodeB}, "api.openai.com")
	if !ok3 || best3 != nodeA {
		t.Fatalf("expected failover to nodeA after nodeB domain failure, got %v", best3)
	}
}

// Tests that PeekBest predicts the best candidate without altering affinity state.
func TestTracker_PeekBestDoesNotMutateAffinity(t *testing.T) {
	tr := NewTracker()
	nodeA := "node-a"
	nodeB := "node-b"

	tr.RecordDial(nodeA, "github.com", 100*time.Millisecond, nil)
	tr.RecordDial(nodeB, "github.com", 30*time.Millisecond, nil)

	// PeekBest should recommend nodeB without establishing sticky affinity for nodeB
	best, sc, ok := tr.PeekBest([]string{nodeA, nodeB}, "github.com")
	if !ok || best != nodeB {
		t.Fatalf("expected PeekBest to return nodeB, got %v (ok=%v)", best, ok)
	}
	if sc.EWMA != 30*time.Millisecond {
		t.Fatalf("expected EWMA = 30ms, got %v", sc.EWMA)
	}

	// Internal affinity map should still be nodeA (from RecordDial), NOT overwritten by PeekBest
	tr.mu.RLock()
	aff := tr.affinity["github.com"]
	tr.mu.RUnlock()
	if aff != nodeA {
		t.Fatalf("expected affinity to remain node-a after PeekBest, got %v", aff)
	}

	// In contrast, SelectBest should commit the new affinity to nodeB
	bestSel, okSel := tr.SelectBest([]string{nodeA, nodeB}, "github.com")
	if !okSel || bestSel != nodeB {
		t.Fatalf("expected SelectBest to return nodeB, got %v", bestSel)
	}
	tr.mu.RLock()
	affAfterSelect := tr.affinity["github.com"]
	tr.mu.RUnlock()
	if affAfterSelect != nodeB {
		t.Fatalf("expected SelectBest to update affinity to node-b, got %v", affAfterSelect)
	}
}

// Regression test: sidecar loopback traffic passes rtt=0 to avoid displaying a misleading 1ms latency,
// and unsampled nodes return EWMA=0 instead of a fake 150ms while active probes populate EWMA.
func TestTracker_SidecarZeroRTTAndProbeRecording(t *testing.T) {
	tr := NewTracker()
	node := "sidecar-naive"

	// 1. Fresh unsampled node should report EWMA = 0 (so UI can show "awaiting sample")
	initScore := tr.GetScore(node)
	if initScore.EWMA != 0 {
		t.Fatalf("expected unsampled node EWMA = 0, got %v", initScore.EWMA)
	}

	// 2. Active probe records real internet latency (e.g. 80ms)
	tr.RecordProbe(node, 80*time.Millisecond)
	probeScore := tr.GetScore(node)
	if probeScore.EWMA != 80*time.Millisecond {
		t.Fatalf("expected EWMA after probe = 80ms, got %v", probeScore.EWMA)
	}

	// 3. Sidecar loopback dial passes rtt = 0; should increment TotalDials & affinity without polluting EWMA
	tr.RecordDial(node, "chatgpt.com", 0, nil)
	afterDialScore := tr.GetScore(node)
	if afterDialScore.EWMA != 80*time.Millisecond {
		t.Fatalf("expected EWMA to remain 80ms after rtt=0 dial, got %v", afterDialScore.EWMA)
	}
	tr.mu.RLock()
	aff := tr.affinity["chatgpt.com"]
	tr.mu.RUnlock()
	if aff != node {
		t.Fatalf("expected domain affinity recorded for chatgpt.com, got %v", aff)
	}
}

// Tests that QualityScore exports detailed telemetry metrics: SuccessRate, Dials, ConsecutiveFailures, and Penalty.
func TestTracker_QualityScoreDetailedMetrics(t *testing.T) {
	tr := NewTracker()
	node := "test-node-telemetry"

	// 1. Unsampled node
	sc0 := tr.GetScore(node)
	if sc0.TotalDials != 0 || sc0.SuccessfulDials != 0 || sc0.ConsecutiveFailures != 0 || sc0.CircuitPenalty != 0 {
		t.Fatalf("expected zeroed initial telemetry stats, got %+v", sc0)
	}

	// 2. 1 success + 1 failure
	tr.RecordDial(node, "site1.com", 50*time.Millisecond, nil)
	tr.RecordDial(node, "site2.com", 0, errors.New("timeout"))
	sc1 := tr.GetScore(node)
	if sc1.TotalDials != 2 || sc1.SuccessfulDials != 1 {
		t.Fatalf("expected 2 total dials and 1 success, got %d and %d", sc1.TotalDials, sc1.SuccessfulDials)
	}
	if sc1.SuccessRate != 0.5 {
		t.Fatalf("expected 0.5 success rate, got %v", sc1.SuccessRate)
	}
	if sc1.ConsecutiveFailures != 1 {
		t.Fatalf("expected 1 consecutive failure, got %d", sc1.ConsecutiveFailures)
	}

	// 3. 2 more failures to trip circuit breaker (threshold = 3)
	tr.RecordDial(node, "site3.com", 0, errors.New("timeout"))
	tr.RecordDial(node, "site4.com", 0, errors.New("timeout"))
	sc2 := tr.GetScore(node)
	if !sc2.IsBroken {
		t.Fatalf("expected node to be broken after 3 consecutive failures")
	}
	if sc2.CircuitPenalty != 10000.0 {
		t.Fatalf("expected 10000.0 penalty, got %v", sc2.CircuitPenalty)
	}
	if sc2.Score < 10000.0 {
		t.Fatalf("expected score > 10000 with circuit penalty, got %v", sc2.Score)
	}
}

// Regression test: active probe failures must reduce SuccessRate, increase routing Score via EWMA/SR^2
// without corrupting EWMA with fake timeout values, and trip the circuit breaker after 3 consecutive failures.
func TestTracker_ProbeFailureUpdatesSuccessRateAndCircuitBreaker(t *testing.T) {
	tr := NewTracker()
	node := "sidecar-naive"

	// 1. Initial successful probe at 100ms -> 1/1 (100% success rate), EWMA = 100ms, Score = 100
	tr.RecordProbe(node, 100*time.Millisecond)
	sc1 := tr.GetScore(node)
	if sc1.EWMA != 100*time.Millisecond || sc1.SuccessRate != 1.0 || sc1.TotalDials != 1 || sc1.SuccessfulDials != 1 {
		t.Fatalf("unexpected score after initial probe: %+v", sc1)
	}

	// 2. Active probe fails (e.g. context deadline exceeded) -> 1/2 (50% success rate), EWMA stays 100ms, Score = 100 / 0.25 = 400
	tr.RecordProbeFailure(node)
	sc2 := tr.GetScore(node)
	if sc2.EWMA != 100*time.Millisecond {
		t.Fatalf("expected EWMA to remain 100ms after probe failure, got %v", sc2.EWMA)
	}
	if sc2.SuccessRate != 0.5 || sc2.TotalDials != 2 || sc2.SuccessfulDials != 1 || sc2.ConsecutiveFailures != 1 {
		t.Fatalf("expected 50%% success rate (1/2) and 1 consecutive failure, got %+v", sc2)
	}
	if sc2.Score != 400.0 {
		t.Fatalf("expected Score = 400.0 (100 / 0.5^2), got %v", sc2.Score)
	}

	// 3. Two more consecutive probe failures trip the circuit breaker
	tr.RecordProbeFailure(node)
	tr.RecordProbeFailure(node)
	sc3 := tr.GetScore(node)
	if !sc3.IsBroken || sc3.ConsecutiveFailures != 3 || sc3.CircuitPenalty != 10000.0 {
		t.Fatalf("expected circuit breaker tripped after 3 probe failures, got %+v", sc3)
	}

	// 4. Subsequent successful probe recovers from circuit breaker
	tr.RecordProbe(node, 100*time.Millisecond)
	sc4 := tr.GetScore(node)
	if sc4.IsBroken || sc4.ConsecutiveFailures != 0 {
		t.Fatalf("expected probe success to clear consecutive failures and circuit breaker, got %+v", sc4)
	}
}

// Tests that the 50-sample sliding window evicts old history so sudden packet loss is not diluted by past successes.
func TestTracker_SlidingWindowEvictsHistoricalSamples(t *testing.T) {
	tr := NewTracker()
	node := "node-window"

	// 1. 100 historical successful dials
	for i := 0; i < 100; i++ {
		tr.RecordDial(node, "example.com", 80*time.Millisecond, nil)
	}
	scBefore := tr.GetScore(node)
	if scBefore.TotalDials != recentWindowSize || scBefore.SuccessfulDials != recentWindowSize || scBefore.SuccessRate != 1.0 {
		t.Fatalf("expected full window 50/50 (100%%), got %+v", scBefore)
	}

	// 2. Sudden 50% packet loss over the next 50 requests (alternating success and failure)
	for i := 0; i < recentWindowSize; i++ {
		if i%2 == 0 {
			tr.RecordDial(node, "example.com", 80*time.Millisecond, nil)
		} else {
			tr.RecordDial(node, "example.com", 0, errors.New("i/o timeout"))
		}
	}
	scAfter := tr.GetScore(node)
	if scAfter.TotalDials != recentWindowSize || scAfter.SuccessfulDials != 25 || scAfter.SuccessRate != 0.5 {
		t.Fatalf("expected sliding window to reflect 50%% recent success rate (25/50), got %+v", scAfter)
	}
	if !scAfter.IsBroken {
		t.Fatalf("expected high packet loss (50%% < 60%% threshold) to trip circuit breaker, got %+v", scAfter)
	}
}

// Tests that severe RTO retransmission stalls (RTT >= 3000ms) count as packet-loss degradation, do not reset
// ConsecutiveFailures, and trip the circuit breaker under intermittent high packet loss even when lucky packets slip through.
func TestTracker_HighPacketLossAndSevereRTOStallCircuitBreaker(t *testing.T) {
	tr := NewTracker()
	node := "node-lossy"

	// 1. 1 timeout failure -> ConsecutiveFailures = 1
	tr.RecordDial(node, "site1.com", 0, errors.New("timeout"))
	// 2. 1 severe RTO stall (4200ms >= 3000ms) -> updates EWMA, counts as degraded (0/2), increments ConsecutiveFailures to 2
	tr.RecordDial(node, "site2.com", 4200*time.Millisecond, nil)
	sc1 := tr.GetScore(node)
	if sc1.EWMA != 4200*time.Millisecond {
		t.Fatalf("expected EWMA = 4200ms from stalled packet, got %v", sc1.EWMA)
	}
	if sc1.SuccessfulDials != 0 || sc1.TotalDials != 2 || sc1.ConsecutiveFailures != 2 {
		t.Fatalf("expected stalled packet not to increment SuccessfulDials and to increment ConsecutiveFailures=2, got %+v", sc1)
	}

	// 3. One lucky fast packet (120ms) slips through -> resets ConsecutiveFailures to 0, window is now 1/3
	tr.RecordDial(node, "site3.com", 120*time.Millisecond, nil)
	// 4. Another timeout and another RTO stall -> window has 5 samples: only 1 healthy out of 5 (20% < 60%)
	tr.RecordDial(node, "site4.com", 0, errors.New("timeout"))
	tr.RecordDial(node, "site5.com", 3500*time.Millisecond, nil)

	sc2 := tr.GetScore(node)
	if sc2.TotalDials != 5 || sc2.SuccessfulDials != 1 || sc2.SuccessRate != 0.2 {
		t.Fatalf("expected 1/5 (20%%) healthy rate, got %+v", sc2)
	}
	if !sc2.IsBroken || sc2.CircuitPenalty != 10000.0 {
		t.Fatalf("expected high packet-loss circuit breaker tripped at 20%% success rate even with ConsecutiveFailures=%d, got %+v", sc2.ConsecutiveFailures, sc2)
	}

	// 5. A single lucky passive packet while SR is still < 60% (2/6 = 33.3%) must NOT prematurely clear the high-loss breaker
	tr.RecordDial(node, "site6.com", 100*time.Millisecond, nil)
	if !tr.IsBroken(node) {
		t.Fatalf("expected single lucky packet not to clear high-loss circuit breaker while SR=33.3%%")
	}

	// 6. Three consecutive healthy packets (ConsecutiveSuccesses >= 3) prove the link has recovered and clear the breaker
	tr.RecordDial(node, "site7.com", 100*time.Millisecond, nil)
	tr.RecordDial(node, "site8.com", 100*time.Millisecond, nil)
	if tr.IsBroken(node) {
		t.Fatalf("expected 3 consecutive healthy responses to recover from high-loss circuit breaker")
	}

	// 7. After recovery, a single isolated failure must NOT immediately re-trip the high-loss breaker from old window debt
	tr.RecordDial(node, "site9.com", 0, errors.New("single transient blip"))
	if tr.IsBroken(node) {
		t.Fatalf("expected single isolated failure after recovery not to re-trip breaker on old window debt")
	}

	// 8. ResetNode clears all node stats, domain errors, and sticky affinity on service restart
	tr.ResetNode(node)
	scReset := tr.GetScore(node)
	if scReset.TotalDials != 0 || scReset.EWMA != 0 || scReset.IsBroken {
		t.Fatalf("expected clean state after ResetNode, got %+v", scReset)
	}
}

// Tests that active probe RTT sets the physical floor and executes an instant one-vote veto,
// while letting genuine trans-oceanic business latency dictate selection without artificial truncation.
func TestTracker_ActiveProbeBaselineAnchoring(t *testing.T) {
	tr := NewTracker()
	node := "node-anchor"

	// 1. Hong Kong node: local Anycast Google 204 probe is 35ms
	tr.RecordProbe(node, 35*time.Millisecond)
	sc1 := tr.GetScore(node)
	if sc1.EWMA != 35*time.Millisecond || sc1.ProbeRTT != 35*time.Millisecond {
		t.Fatalf("expected initial probe baseline 35ms, got EWMA=%v", sc1.EWMA)
	}

	// 2. Real user visits South America or US West origin: physical trans-oceanic latency is 180ms
	// max(180ms, 35ms) = 180ms. The genuine distance is respected without being crushed by magic numbers.
	tr.RecordDial(node, "south-america.org", 180*time.Millisecond, nil)
	sc2 := tr.GetScore(node)
	if sc2.PassiveEWMA != 180*time.Millisecond {
		t.Fatalf("expected PassiveEWMA = 180ms, got %v", sc2.PassiveEWMA)
	}
	if sc2.EWMA != 180*time.Millisecond {
		t.Fatalf("expected pure max EWMA = 180ms, got %v", sc2.EWMA)
	}

	// 3. Probe degradation (e.g. 1199ms in screenshot):
	// Instantly executes one-vote veto: max(180ms, 1199ms) = 1199ms!
	tr.RecordProbe(node, 1199*time.Millisecond)
	sc3 := tr.GetScore(node)
	if sc3.EWMA != 1199*time.Millisecond {
		t.Fatalf("expected one-vote veto to take probe 1199ms, got %v", sc3.EWMA)
	}
}

// Tests that client-side cancellation (e.g. user refreshed or closed tab)
// is completely ignored: no penalty, no dials counted, no domain error pollution.
func TestTracker_ClientCancellationIgnored(t *testing.T) {
	tr := NewTracker()
	node := "node-client-cancel"

	// Initial healthy dial: 100ms
	tr.RecordDial(node, "example.com", 100*time.Millisecond, nil)
	scInitial := tr.GetScore(node)
	if scInitial.TotalDials != 1 || scInitial.SuccessfulDials != 1 {
		t.Fatalf("expected 1/1 dials initially, got %+v", scInitial)
	}

	// User mashes F5 (refresh) or rapidly switches tabs, producing 10 context.Canceled errors
	for i := 0; i < 10; i++ {
		tr.RecordDial(node, "example.com", 0, context.Canceled)
	}

	scAfter := tr.GetScore(node)
	// Stats must be completely untouched:
	if scAfter.TotalDials != 1 || scAfter.SuccessfulDials != 1 {
		t.Fatalf("expected total dials untouched after client cancellations, got %d/%d", scAfter.SuccessfulDials, scAfter.TotalDials)
	}
	if scAfter.ConsecutiveFailures != 0 {
		t.Fatalf("expected 0 consecutive failures after client cancellations, got %d", scAfter.ConsecutiveFailures)
	}
	if scAfter.IsBroken {
		t.Fatalf("expected node not broken by client cancellations")
	}

	// Must NOT record in domain errors
	tr.mu.RLock()
	domainErrs := tr.domainErrors["example.com"][node]
	tr.mu.RUnlock()
	if domainErrs != 0 {
		t.Fatalf("expected 0 domain errors for client cancellations, got %d", domainErrs)
	}
}

// Tests that destination site faults (e.g. expired TLS certificate or site refusal)
// do not penalize node's global success rate or trigger circuit breaker.
func TestTracker_SiteFaultIsolationDoesNotTripCircuit(t *testing.T) {
	tr := NewTracker()
	node := "node-sitefault"

	// Initial healthy dial: 100ms
	tr.RecordDial(node, "good.com", 100*time.Millisecond, nil)
	scInitial := tr.GetScore(node)
	if scInitial.TotalDials != 1 || scInitial.SuccessfulDials != 1 {
		t.Fatalf("expected 1/1 dials initially, got %+v", scInitial)
	}

	// 3 consecutive failures caused by a broken target website's TLS certificate
	certErr := errors.New("remote error: tls: bad certificate (x509: certificate signed by unknown authority)")
	for i := 0; i < 3; i++ {
		tr.RecordDial(node, "broken-cert.com", 0, certErr)
	}

	scAfter := tr.GetScore(node)
	// Global stats must NOT be penalized:
	if scAfter.ConsecutiveFailures != 0 {
		t.Fatalf("expected 0 consecutive failures for site faults, got %d", scAfter.ConsecutiveFailures)
	}
	if scAfter.IsBroken {
		t.Fatalf("expected node NOT broken by remote site faults")
	}
	if scAfter.TotalDials != 1 || scAfter.SuccessfulDials != 1 {
		t.Fatalf("expected total dials unchanged by isolated site faults, got %d/%d", scAfter.SuccessfulDials, scAfter.TotalDials)
	}

	// But broken-cert.com must still be recorded in domain errors to evict affinity
	tr.mu.RLock()
	errCount := tr.domainErrors["broken-cert.com"][node]
	tr.mu.RUnlock()
	if errCount != 3 {
		t.Fatalf("expected 3 domain errors recorded for broken-cert.com, got %d", errCount)
	}
}

// Tests that single slow cold-site (e.g. 3500ms stall on same root domain)
// isolates penalty to domain level and does NOT penalize node's global consecutive failures or trip circuit breaker.
func TestTracker_SingleSlowDomainIsolationDoesNotTripNode(t *testing.T) {
	tr := NewTracker()
	node := "node-stable"

	// Initial healthy dial: 100ms
	tr.RecordDial(node, "healthy.com", 100*time.Millisecond, nil)

	// User opens a very slow cold forum: 5 concurrent requests all take 3500ms
	for i := 0; i < 5; i++ {
		tr.RecordDial(node, "slow-cold-site.org", 3500*time.Millisecond, nil)
	}

	sc := tr.GetScore(node)
	if sc.ConsecutiveFailures != 0 {
		t.Fatalf("expected 0 consecutive failures for isolated single slow root domain, got %d", sc.ConsecutiveFailures)
	}
	if sc.IsBroken {
		t.Fatalf("expected node NOT broken by single slow cold site")
	}
}

// Tests that when multiple distinct root domains stall within correlation window (5s),
// the system breaks through probe time-lag blindness and trips circuit breaker.
func TestTracker_MultiDomainCorrelationBreaksProbeLagBlindness(t *testing.T) {
	tr := NewTracker()
	node := "node-qos-stall"

	// Initial healthy probe: 100ms
	tr.RecordProbe(node, 100*time.Millisecond)

	// Suddenly node gets throttled/QoS blocked: 2 different domains stall in rapid succession
	tr.RecordDial(node, "site-a.com", 3500*time.Millisecond, nil)
	tr.RecordDial(node, "site-b.com", 3500*time.Millisecond, nil)

	sc := tr.GetScore(node)
	if sc.ConsecutiveFailures < 1 {
		t.Fatalf("expected multi-domain stall to increment consecutive failures, got %d", sc.ConsecutiveFailures)
	}
}

// Tests that when all candidate nodes stall on the same slow forum ("全池皆慢"),
// affinity eviction stops to preserve session IP stickiness and prevent login dropouts.
func TestTracker_AllNodesSlowStopsAffinityEviction(t *testing.T) {
	tr := NewTracker()
	nodeA := "node-a"
	nodeB := "node-b"
	root := "slow-forum.com"

	// 1. Initially assign affinity to nodeA
	_, _ = tr.SelectBest([]string{nodeA, nodeB}, root)
	tr.mu.RLock()
	aff1 := tr.affinity[root]
	tr.mu.RUnlock()
	if aff1 != nodeA {
		t.Fatalf("expected initial affinity to node-a, got %v", aff1)
	}

	// 2. First failure on nodeA: evicts affinity so domain can try nodeB
	tr.RecordDial(nodeA, root, 3500*time.Millisecond, nil)
	tr.mu.RLock()
	_, ok := tr.affinity[root]
	tr.mu.RUnlock()
	if ok {
		t.Fatalf("expected affinity evicted on first failure to test alternative node")
	}

	// 3. User switches to nodeB and establishes affinity to nodeB
	_, _ = tr.SelectBest([]string{nodeB}, root)

	// 4. Second failure on nodeB ("全池皆慢"): domain now has failed on both nodeA and nodeB
	// Must NOT evict affinity anymore to preserve session IP stickiness!
	tr.RecordDial(nodeB, root, 3500*time.Millisecond, nil)
	tr.mu.RLock()
	aff2, ok2 := tr.affinity[root]
	tr.mu.RUnlock()
	if !ok2 || aff2 != nodeB {
		t.Fatalf("expected affinity to stay sticky on node-b after all nodes slow, got %v (ok=%v)", aff2, ok2)
	}
}

// Tests that probe jitter spikes (e.g. 1600ms packet loss spike among 180ms samples)
// strip the single-domain isolation immunity and penalize the node.
func TestTracker_ProbeJitterSpikeStripsSingleDomainImmunity(t *testing.T) {
	tr := NewTracker()
	node := "node-jitter"

	// 5 probes: 180ms, 190ms, 1600ms (spike), 185ms, 190ms
	tr.RecordProbe(node, 180*time.Millisecond)
	tr.RecordProbe(node, 190*time.Millisecond)
	tr.RecordProbe(node, 1600*time.Millisecond)
	tr.RecordProbe(node, 185*time.Millisecond)
	tr.RecordProbe(node, 190*time.Millisecond)

	sc := tr.GetScore(node)
	if sc.ProbeRTT != 190*time.Millisecond {
		t.Fatalf("expected latest probe to report 190ms, got %v", sc.ProbeRTT)
	}
	if sc.MaxProbeRTT != 1600*time.Millisecond {
		t.Fatalf("expected MaxProbeRTT = 1600ms, got %v", sc.MaxProbeRTT)
	}

	// Now a single domain stalls at 3500ms
	// Because of the recent 1600ms jitter spike, single-domain immunity is stripped!
	tr.RecordDial(node, "single-site.com", 3500*time.Millisecond, nil)

	scAfter := tr.GetScore(node)
	if scAfter.ConsecutiveFailures != 1 {
		t.Fatalf("expected jitter spike to strip immunity and increment consecutive failures=1, got %d", scAfter.ConsecutiveFailures)
	}
}

// Tests that in survival mode (all candidates broken/degraded),
// switching hysteresis threshold is raised to 40% to suppress pointless thrashing.
func TestTracker_AllNodesDegradedSurvivalHysteresis(t *testing.T) {
	tr := NewTracker()
	nodeA := "node-a"
	nodeB := "node-b"
	root := "work-app.com"

	// Trip both nodes into circuit breaker (both broken)
	for i := 0; i < 3; i++ {
		tr.RecordDial(nodeA, "dummy.com", 0, errors.New("timeout"))
		tr.RecordDial(nodeB, "dummy.com", 0, errors.New("timeout"))
	}
	if !tr.IsBroken(nodeA) || !tr.IsBroken(nodeB) {
		t.Fatalf("expected both nodes broken")
	}

	// Establish affinity to nodeA
	tr.mu.Lock()
	tr.affinity[root] = nodeA
	// Set nodeA EWMA = 400ms, nodeB EWMA = 310ms (nodeB is ~22.5% faster, < 40% survival threshold)
	tr.nodes[nodeA].EWMA = 400 * time.Millisecond
	tr.nodes[nodeB].EWMA = 310 * time.Millisecond
	tr.mu.Unlock()

	// In survival mode, 22.5% advantage should NOT switch
	best1, _ := tr.SelectBest([]string{nodeA, nodeB}, root)
	if best1 != nodeA {
		t.Fatalf("expected survival mode to suppress switch for 22.5%% margin, retained %v", best1)
	}

	// If nodeB becomes 50% faster (e.g. 200ms vs 400ms > 40%), it should switch
	tr.mu.Lock()
	tr.nodes[nodeB].EWMA = 200 * time.Millisecond
	tr.mu.Unlock()

	best2, _ := tr.SelectBest([]string{nodeA, nodeB}, root)
	if best2 != nodeB {
		t.Fatalf("expected survival mode to switch when margin exceeds 40%%, got %v", best2)
	}
}

// Tests that idle nodes with stale high-latency passive EWMA decay towards healthy probe RTT.
func TestTracker_IdleNodePassiveEWMADecay(t *testing.T) {
	tr := NewTracker()
	node := "node-decay"

	// 1. Node previously served trans-oceanic requests, building up a 600ms passive EWMA
	tr.RecordDial(node, "south-america.org", 600*time.Millisecond, nil)
	sc1 := tr.GetScore(node)
	if sc1.PassiveEWMA != 600*time.Millisecond || sc1.EWMA != 600*time.Millisecond {
		t.Fatalf("expected initial passive EWMA = 600ms, got %v", sc1.EWMA)
	}

	// 2. Active business traffic (< 60s ago): probe must NOT decay passive EWMA
	tr.RecordProbe(node, 30*time.Millisecond)
	scActive := tr.GetScore(node)
	if scActive.PassiveEWMA != 600*time.Millisecond {
		t.Fatalf("expected active business traffic to preserve 600ms passive EWMA, got %v", scActive.PassiveEWMA)
	}

	// 3. Node enters idle standby (e.g. 5 minutes without passive traffic)
	tr.mu.Lock()
	tr.nodes[node].LastPassiveDial = time.Now().Add(-5 * time.Minute)
	tr.mu.Unlock()

	// 4. Healthy probe arrives (30ms): passive EWMA decays towards probe baseline
	tr.RecordProbe(node, 30*time.Millisecond)
	scDecayed1 := tr.GetScore(node)
	if scDecayed1.PassiveEWMA >= 600*time.Millisecond {
		t.Fatalf("expected idle probe to decay passive EWMA, still %v", scDecayed1.PassiveEWMA)
	}
	if scDecayed1.PassiveEWMA > 350*time.Millisecond {
		t.Fatalf("expected passive EWMA to decay by ~50%%, got %v", scDecayed1.PassiveEWMA)
	}
	if scDecayed1.EWMA != scDecayed1.PassiveEWMA {
		t.Fatalf("expected effective EWMA to reflect decayed passive EWMA, got %v", scDecayed1.EWMA)
	}

	// 5. Subsequent probe after further idle time (15 mins total) converges close to probe RTT
	tr.mu.Lock()
	tr.nodes[node].LastPassiveDial = time.Now().Add(-15 * time.Minute)
	tr.mu.Unlock()

	tr.RecordProbe(node, 30*time.Millisecond)
	scDecayed2 := tr.GetScore(node)
	if scDecayed2.PassiveEWMA > 100*time.Millisecond {
		t.Fatalf("expected passive EWMA after extended idle to converge towards 30ms, got %v", scDecayed2.PassiveEWMA)
	}
}

// Tests that healthy active probes on idle nodes fast-wash historical failures in the sliding window.
func TestTracker_IdleNodeFastWashHistoricalFailures(t *testing.T) {
	tr := NewTracker()
	node := "node-wash"

	// 1. Produce 5 consecutive failures
	for i := 0; i < 5; i++ {
		tr.RecordDial(node, "flaky.com", 0, errors.New("timeout"))
	}
	scInitial := tr.GetScore(node)
	if scInitial.TotalDials != 5 || scInitial.SuccessfulDials != 0 {
		t.Fatalf("expected 0/5 successful dials initially, got %+v", scInitial)
	}

	// 2. Active business traffic (< 60s ago): healthy probe only pushes 1 sample, no fast-wash
	tr.RecordProbe(node, 50*time.Millisecond)
	scActive := tr.GetScore(node)
	// 5 failures + 1 probe success = 6 dials, 1 success
	if scActive.TotalDials != 6 || scActive.SuccessfulDials != 1 {
		t.Fatalf("expected active probe to only record 1 success without fast-wash, got %d/%d",
			scActive.SuccessfulDials, scActive.TotalDials)
	}

	// 3. Mark node as idle (5 minutes ago)
	tr.mu.Lock()
	tr.nodes[node].LastPassiveDial = time.Now().Add(-5 * time.Minute)
	tr.mu.Unlock()

	// 4. An UNHEALTHY probe (e.g. 500ms > 300ms) should NOT trigger fast-wash
	tr.RecordProbe(node, 500*time.Millisecond)
	scUnhealthy := tr.GetScore(node)
	// Pushes 1 probe success (now 7 dials, 2 successes), 0 washed
	if scUnhealthy.SuccessfulDials != 2 {
		t.Fatalf("expected unhealthy probe to not fast-wash, got %d successes", scUnhealthy.SuccessfulDials)
	}

	// 5. A genuinely HEALTHY probe (50ms <= 300ms) on idle node triggers fast-wash of up to 2 historical failures
	tr.RecordProbe(node, 50*time.Millisecond)
	scHealthy := tr.GetScore(node)
	// 1 success from probe sample + 2 failures washed to success = 3 additional successes (total 2 + 3 = 5 successes out of 8)
	if scHealthy.SuccessfulDials != 5 {
		t.Fatalf("expected healthy idle probe to wash 2 failures + 1 sample, got %d successes out of %d",
			scHealthy.SuccessfulDials, scHealthy.TotalDials)
	}

	// 6. Another healthy idle probe washes 2 more failures (total 4 washed, 1 remaining)
	tr.RecordProbe(node, 50*time.Millisecond)
	scWash2 := tr.GetScore(node)
	if scWash2.SuccessfulDials != 8 || scWash2.TotalDials != 9 {
		t.Fatalf("expected second healthy idle probe to reach 8/9, got %d/%d",
			scWash2.SuccessfulDials, scWash2.TotalDials)
	}

	// 7. Third healthy idle probe washes the last failure -> 100% full recovery
	tr.RecordProbe(node, 50*time.Millisecond)
	scRecovered := tr.GetScore(node)
	if scRecovered.SuccessfulDials != scRecovered.TotalDials || scRecovered.TotalDials != 10 {
		t.Fatalf("expected full recovery after third healthy idle probe, got %d/%d",
			scRecovered.SuccessfulDials, scRecovered.TotalDials)
	}
}

// Tests that the configurable active probe interval proportionally scales the idle passive decay rate.
func TestTracker_ConfigurableProbeIntervalAffectsDecay(t *testing.T) {
	tr1 := NewTracker()
	tr1.SetProbeInterval(1 * time.Minute)
	if tr1.ProbeInterval() != 1*time.Minute {
		t.Fatalf("expected ProbeInterval = 1m, got %v", tr1.ProbeInterval())
	}

	tr5 := NewTracker()
	tr5.SetProbeInterval(10 * time.Minute)

	node := "node-interval-test"
	tr1.RecordDial(node, "target.com", 500*time.Millisecond, nil)
	tr5.RecordDial(node, "target.com", 500*time.Millisecond, nil)

	// Simulate both nodes being idle for 2 minutes
	idleTime := time.Now().Add(-2 * time.Minute)
	tr1.mu.Lock()
	tr1.nodes[node].LastPassiveDial = idleTime
	tr1.mu.Unlock()

	tr5.mu.Lock()
	tr5.nodes[node].LastPassiveDial = idleTime
	tr5.mu.Unlock()

	// Probe both with 50ms
	tr1.RecordProbe(node, 50*time.Millisecond)
	tr5.RecordProbe(node, 50*time.Millisecond)

	sc1 := tr1.GetScore(node)
	sc5 := tr5.GetScore(node)

	// For tr1 (1m interval), 2 minutes is 2 probe intervals -> decayRatio = 75%
	// For tr5 (10m interval), 2 minutes is 0.2 probe intervals -> decayRatio = 50%
	if sc1.PassiveEWMA >= sc5.PassiveEWMA {
		t.Fatalf("expected 1m probe interval to decay faster than 10m interval, got tr1=%v, tr5=%v",
			sc1.PassiveEWMA, sc5.PassiveEWMA)
	}
}

