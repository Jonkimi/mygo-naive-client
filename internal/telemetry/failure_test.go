package telemetry

import (
	"errors"
	"fmt"
	"testing"
)

// Tests that FailureMonitor aggregates failures by target and action, maintains ring buffer capacity, and tracks resolution.
func TestFailureMonitor_AggregationAndRingBuffer(t *testing.T) {
	fm := NewFailureMonitor(5) // Small capacity for testing ring buffer overflow

	// 1. Record direct failure on api.openai.com
	fm.Record(FailureEvent{
		Category:       FailureDirect,
		Target:         "api.openai.com",
		Port:           443,
		OriginalAction: "DIRECT",
		OriginalRule:   "rule-direct",
		Error:          errors.New("dial tcp: i/o timeout"),
	})

	// 2. Record second failure on same host and action
	fm.Record(FailureEvent{
		Category:       FailureDirect,
		Target:         "api.openai.com:443",
		Port:           443,
		OriginalAction: "DIRECT",
		OriginalRule:   "rule-direct",
		Error:          errors.New("read: connection reset by peer"),
	})

	list := fm.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 aggregated item, got %d", len(list))
	}
	item := list[0]
	if item.Target != "api.openai.com" {
		t.Errorf("expected target api.openai.com, got %s", item.Target)
	}
	if item.RootDomain != "openai.com" {
		t.Errorf("expected root domain openai.com, got %s", item.RootDomain)
	}
	if item.FailCount != 2 {
		t.Errorf("expected FailCount 2, got %d", item.FailCount)
	}
	if item.Category != FailureDirect {
		t.Errorf("expected Category FailureDirect, got %v", item.Category)
	}
	if item.RecommendedAction != "PROXY_POOL" {
		t.Errorf("expected RecommendedAction PROXY_POOL, got %s", item.RecommendedAction)
	}
	if item.LastError != "read: connection reset by peer" {
		t.Errorf("expected latest error, got %s", item.LastError)
	}
	if fm.UnresolvedCount() != 1 {
		t.Errorf("expected 1 unresolved count, got %d", fm.UnresolvedCount())
	}

	// 3. Resolve target
	fm.Resolve("api.openai.com")
	if fm.UnresolvedCount() != 0 {
		t.Errorf("expected 0 unresolved count after resolve, got %d", fm.UnresolvedCount())
	}
	list = fm.List()
	if !list[0].Resolved {
		t.Errorf("expected item to be marked resolved")
	}

	// 4. Test ring buffer overflow (capacity = 5)
	for i := 1; i <= 10; i++ {
		fm.Record(FailureEvent{
			Category:       FailureProxy,
			Target:         fmt.Sprintf("host%d.example.org", i),
			Port:           80,
			OriginalAction: "PROXY_POOL",
			OriginalRule:   "rule-proxy",
			Error:          errors.New("all candidates failed"),
		})
	}

	list = fm.List()
	if len(list) != 5 {
		t.Fatalf("expected ring buffer capped at 5, got %d", len(list))
	}
	// The oldest item (api.openai.com) should have been evicted
	for _, it := range list {
		if it.Target == "api.openai.com" {
			t.Errorf("api.openai.com should have been evicted by ring buffer")
		}
	}
}

// Tests recommended action logic for different failure categories.
func TestFailureMonitor_Recommendations(t *testing.T) {
	fm := NewFailureMonitor(10)

	// Direct failure should recommend PROXY_POOL
	fm.Record(FailureEvent{
		Category:       FailureDirect,
		Target:         "unblocked.example.com",
		OriginalAction: "DIRECT",
		Error:          errors.New("timeout"),
	})

	// Proxy failure should recommend DIRECT
	fm.Record(FailureEvent{
		Category:       FailureProxy,
		Target:         "blocked.example.com",
		OriginalAction: "PROXY_TAG:AI",
		Error:          errors.New("refused"),
	})

	list := fm.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 items, got %d", len(list))
	}
	for _, it := range list {
		if it.Target == "unblocked.example.com" && it.RecommendedAction != "PROXY_POOL" {
			t.Errorf("expected PROXY_POOL, got %s", it.RecommendedAction)
		}
		if it.Target == "blocked.example.com" && it.RecommendedAction != "DIRECT" {
			t.Errorf("expected DIRECT, got %s", it.RecommendedAction)
		}
	}
}
