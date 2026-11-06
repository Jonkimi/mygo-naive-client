package blocker

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Tests that QueryLogger retains exactly at most 2000 entries in its ring buffer,
// correctly aggregates hourly metrics across the 24-hour window, and tracks Top domains.
func TestQueryLogger_RingBufferAndMetrics(t *testing.T) {
	ql := NewQueryLogger(2000)

	now := time.Now().Truncate(time.Hour)

	// Record 2500 entries across 3 hours
	for i := 0; i < 2500; i++ {
		verdict := VerdictAllowed
		rule := ""
		if i%5 == 0 {
			verdict = VerdictBlocked
			rule = "test-block"
		}
		domain := fmt.Sprintf("domain-%d.com", i%20)
		tOffset := now.Add(-time.Duration(i%3) * time.Hour)
		ql.RecordAt(domain, SourceDNS, verdict, rule, tOffset)
	}

	// 1. Ring buffer capacity: exactly 2000 entries
	entries := ql.GetEntries(0) // 0 means all
	if len(entries) != 2000 {
		t.Fatalf("expected ring buffer to have 2000 entries, got %d", len(entries))
	}
	// Entries should be returned newest first
	if entries[0].ID <= entries[len(entries)-1].ID {
		t.Fatalf("expected entries to be sorted newest first")
	}

	// 2. 24 Hourly Buckets
	buckets := ql.Get24HourlyBuckets(now)
	if len(buckets) != 24 {
		t.Fatalf("expected 24 hourly buckets, got %d", len(buckets))
	}
	var totalQueries, totalBlocked int64
	for _, b := range buckets {
		totalQueries += b.Total
		totalBlocked += b.Blocked
	}
	if totalQueries != 2500 {
		t.Fatalf("expected total queries 2500, got %d", totalQueries)
	}
	if totalBlocked != 500 {
		t.Fatalf("expected total blocked 500 (2500/5), got %d", totalBlocked)
	}

	// 3. Top blocked and allowed domains
	topBlocked := ql.GetTopBlocked(5)
	if len(topBlocked) == 0 {
		t.Fatalf("expected non-empty top blocked")
	}
	for i := 1; i < len(topBlocked); i++ {
		if topBlocked[i-1].Count < topBlocked[i].Count {
			t.Fatalf("top blocked not sorted descending")
		}
	}

	topAllowed := ql.GetTopAllowed(5)
	if len(topAllowed) == 0 {
		t.Fatalf("expected non-empty top allowed")
	}
	for i := 1; i < len(topAllowed); i++ {
		if topAllowed[i-1].Count < topAllowed[i].Count {
			t.Fatalf("top allowed not sorted descending")
		}
	}
}

// Tests that QueryLogger is thread-safe under concurrent logging.
func TestQueryLogger_Concurrency(t *testing.T) {
	ql := NewQueryLogger(2000)
	var wg sync.WaitGroup

	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				d := fmt.Sprintf("worker-%d-dom.com", gid)
				ql.Record(d, SourceGateway, VerdictAllowed, "")
			}
		}(g)
	}
	wg.Wait()

	entries := ql.GetEntries(100)
	if len(entries) != 100 {
		t.Fatalf("expected 100 entries, got %d", len(entries))
	}
}
