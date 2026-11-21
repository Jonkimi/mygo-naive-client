package runner

import "testing"

func TestLogBuffer_MonotonicSequencesAndRingEviction(t *testing.T) {
	lb := NewLogBuffer(3, nil)

	_, _ = lb.Write([]byte("part1"))
	partEntries := lb.Entries()
	if len(partEntries) != 1 || partEntries[0].Text != "part1" {
		t.Fatalf("expected partial entry 'part1', got %+v", partEntries)
	}
	partSeq := partEntries[0].Seq

	_, _ = lb.Write([]byte(" part2\nline2\nline3\nline4\n"))
	entries := lb.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected ring capacity 3, got %d (%+v)", len(entries), entries)
	}
	if entries[0].Text != "line2" || entries[1].Text != "line3" || entries[2].Text != "line4" {
		t.Fatalf("unexpected surviving ring entries: %+v", entries)
	}
	if !(partSeq < entries[0].Seq && entries[0].Seq < entries[1].Seq && entries[1].Seq < entries[2].Seq) {
		t.Fatalf("expected strictly monotonic sequences across ring eviction, part=%d entries=%+v", partSeq, entries)
	}

	lb.Clear()
	if got := lb.Entries(); len(got) != 0 {
		t.Fatalf("expected empty entries after Clear, got %+v", got)
	}
	lb.AppendLine("after-clear")
	after := lb.Entries()
	if len(after) != 1 || after[0].Seq <= entries[2].Seq {
		t.Fatalf("expected Clear to keep monotonic sequences above %d, got %+v", entries[2].Seq, after)
	}
}
