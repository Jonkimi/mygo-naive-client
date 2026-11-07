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

