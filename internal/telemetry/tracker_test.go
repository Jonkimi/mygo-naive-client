package telemetry

import (
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

