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
