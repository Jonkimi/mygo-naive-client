package blocker

import (
	"testing"
	"time"
)

// Consecutive identical blocked entries fold into one row with a count; anything
// that differs (verdict, rule) or interrupts the run must stay separate.
func TestFoldConsecutive(t *testing.T) {
	now := time.Now()
	mk := func(id int64, dom string, v Verdict, rule string) QueryLogEntry {
		return QueryLogEntry{ID: id, Timestamp: now.Add(time.Duration(id) * time.Second), Domain: dom, Source: SourceGateway, Verdict: v, Rule: rule}
	}
	// newest-first
	in := []QueryLogEntry{
		mk(6, "ads.com", VerdictBlocked, "r1"),
		mk(5, "ads.com", VerdictBlocked, "r1"),
		mk(4, "ads.com", VerdictBlocked, "r2"),
		mk(3, "ok.com", VerdictAllowed, ""),
		mk(2, "ok.com", VerdictAllowed, ""),
		mk(1, "ads.com", VerdictBlocked, "r2"),
	}
	got := FoldConsecutive(in)
	wantCounts := []int{2, 1, 1, 1, 1}
	if len(got) != len(wantCounts) {
		t.Fatalf("rows = %d, want %d: %+v", len(got), len(wantCounts), got)
	}
	for i, c := range wantCounts {
		if got[i].Count != c {
			t.Fatalf("row %d count = %d, want %d", i, got[i].Count, c)
		}
	}
	if got[0].ID != 6 || !got[0].First.Equal(in[1].Timestamp) {
		t.Fatalf("folded row should show newest entry and oldest timestamp: %+v", got[0])
	}
}

func TestGetFoldedEntries_LimitCountsRows(t *testing.T) {
	l := NewQueryLogger(100)
	for i := 0; i < 20; i++ {
		l.RecordWithChain("ads.com", SourceGateway, VerdictBlocked, "r", "r -> block")
	}
	l.RecordWithChain("a.com", SourceGateway, VerdictAllowed, "", "final")
	rows, _ := l.GetFoldedEntries("", "", 2)
	if len(rows) != 2 || rows[1].Count != 20 {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}
