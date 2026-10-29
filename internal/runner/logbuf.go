package runner

import (
	"bytes"
	"strings"
	"sync"
)

const defaultMaxLines = 500

// LogBuffer is a thread-safe ring buffer of log lines.
type LogBuffer struct {
	mu      sync.Mutex
	lines   []string
	max     int
	partial string
	onNew   func()
}

// NewLogBuffer creates a ring buffer keeping up to maxLines lines.
func NewLogBuffer(maxLines int, onNew func()) *LogBuffer {
	if maxLines <= 0 {
		maxLines = defaultMaxLines
	}
	return &LogBuffer{
		lines: make([]string, 0, maxLines),
		max:   maxLines,
		onNew: onNew,
	}
}

// Write implements io.Writer, splitting incoming bytes into lines.
func (b *LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	chunk := b.partial + string(bytes.ReplaceAll(p, []byte("\r\n"), []byte("\n")))
	parts := strings.Split(chunk, "\n")
	b.partial = parts[len(parts)-1]
	added := false
	for _, line := range parts[:len(parts)-1] {
		b.appendLocked(line)
		added = true
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
	b.appendLocked(line)
	cb := b.onNew
	b.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (b *LogBuffer) appendLocked(line string) {
	if len(b.lines) >= b.max {
		copy(b.lines, b.lines[1:])
		b.lines[len(b.lines)-1] = line
	} else {
		b.lines = append(b.lines, line)
	}
}

// Lines returns a snapshot copy of the buffered log lines.
func (b *LogBuffer) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	if b.partial != "" {
		out = append(out, b.partial)
	}
	return out
}

// Text returns all lines joined by newline.
func (b *LogBuffer) Text() string {
	return strings.Join(b.Lines(), "\n")
}

// Clear empties the log buffer.
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	b.lines = b.lines[:0]
	b.partial = ""
	b.mu.Unlock()
}
