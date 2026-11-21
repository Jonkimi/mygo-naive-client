package runner

import (
	"bytes"
	"strings"
	"sync"
)

const defaultMaxLines = 500

// LogEntry holds a single buffered log line with a monotonic sequence number
// so UI views keep stable element identities even as older lines roll off.
type LogEntry struct {
	Seq  uint64
	Text string
}

// LogBuffer is a thread-safe ring buffer of log lines.
type LogBuffer struct {
	mu         sync.Mutex
	entries    []LogEntry
	max        int
	nextSeq    uint64
	partial    string
	partialSeq uint64
	onNew      func()
}

// NewLogBuffer creates a ring buffer keeping up to maxLines lines.
func NewLogBuffer(maxLines int, onNew func()) *LogBuffer {
	if maxLines <= 0 {
		maxLines = defaultMaxLines
	}
	return &LogBuffer{
		entries: make([]LogEntry, 0, maxLines),
		max:     maxLines,
		nextSeq: 1,
		onNew:   onNew,
	}
}

func (b *LogBuffer) allocSeqLocked() uint64 {
	if b.nextSeq == 0 {
		b.nextSeq = 1
	}
	seq := b.nextSeq
	b.nextSeq++
	return seq
}

// Write implements io.Writer, splitting incoming bytes into lines.
func (b *LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	chunk := b.partial + string(bytes.ReplaceAll(p, []byte("\r\n"), []byte("\n")))
	parts := strings.Split(chunk, "\n")
	b.partial = parts[len(parts)-1]
	added := false
	for i, line := range parts[:len(parts)-1] {
		seq := uint64(0)
		if i == 0 && b.partialSeq != 0 {
			seq = b.partialSeq
			b.partialSeq = 0
		}
		b.appendLocked(line, seq)
		added = true
	}
	if b.partial == "" {
		b.partialSeq = 0
	} else if b.partialSeq == 0 {
		b.partialSeq = b.allocSeqLocked()
	}
	cb := b.onNew
	b.mu.Unlock()

	if added && cb != nil {
		cb()
	}
	return len(p), nil
}

// AppendLine adds a single line to the log buffer.
func (b *LogBuffer) AppendLine(line string) {
	b.mu.Lock()
	b.appendLocked(line, 0)
	cb := b.onNew
	b.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (b *LogBuffer) appendLocked(line string, seq uint64) {
	if seq == 0 {
		seq = b.allocSeqLocked()
	}
	entry := LogEntry{Seq: seq, Text: line}
	if len(b.entries) >= b.max {
		copy(b.entries, b.entries[1:])
		b.entries[len(b.entries)-1] = entry
	} else {
		b.entries = append(b.entries, entry)
	}
}

// Entries returns a snapshot copy of the buffered log lines with stable sequences.
func (b *LogBuffer) Entries() []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]LogEntry, len(b.entries))
	copy(out, b.entries)
	if b.partial != "" {
		seq := b.partialSeq
		if seq == 0 {
			seq = b.allocSeqLocked()
			b.partialSeq = seq
		}
		out = append(out, LogEntry{Seq: seq, Text: b.partial})
	}
	return out
}

// Lines returns a snapshot copy of the buffered log lines.
func (b *LogBuffer) Lines() []string {
	entries := b.Entries()
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Text
	}
	return out
}

// Text returns all lines joined by newline.
func (b *LogBuffer) Text() string {
	return strings.Join(b.Lines(), "\n")
}

// Clear empties the log buffer while continuing monotonic sequence allocation.
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	b.entries = b.entries[:0]
	b.partial = ""
	b.partialSeq = 0
	b.mu.Unlock()
}
