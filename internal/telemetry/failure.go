package telemetry

import (
	"net"
	"strings"
	"sync"
	"time"
)

// FailureCategory classifies the failure layer according to ADR-0005.
type FailureCategory string

const (
	FailureDirect FailureCategory = "FailureDirect"
	FailureProxy  FailureCategory = "FailureProxy"
	FailureDNS    FailureCategory = "FailureDNS"
)

// FailureEvent is an observation of a failed network operation.
type FailureEvent struct {
	Category       FailureCategory
	Target         string
	Port           uint16
	OriginalAction string
	OriginalRule   string
	Error          error
}

// AggregatedFailure represents aggregated statistics for a failing target and action.
type AggregatedFailure struct {
	Target            string          `json:"target"`
	RootDomain        string          `json:"root_domain"`
	Port              uint16          `json:"port"`
	OriginalAction    string          `json:"original_action"`
	Category          FailureCategory `json:"category"`
	FirstSeen         time.Time       `json:"first_seen"`
	LastSeen          time.Time       `json:"last_seen"`
	FailCount         int             `json:"fail_count"`
	LastError         string          `json:"last_error"`
	OriginalRule      string          `json:"original_rule"`
	RecommendedAction string          `json:"recommended_action"`
	Resolved          bool            `json:"resolved"`
}

// FailureMonitor manages a bounded memory ring buffer of aggregated failures with one-click conversion support.
type FailureMonitor struct {
	mu          sync.RWMutex
	capacity    int
	order       []string // keys in insertion order (FIFO ring buffer)
	items       map[string]*AggregatedFailure
	unresolved  int
}

// NewFailureMonitor creates a monitor with the specified maximum capacity.
func NewFailureMonitor(capacity int) *FailureMonitor {
	if capacity <= 0 {
		capacity = 500
	}
	return &FailureMonitor{
		capacity: capacity,
		order:    make([]string, 0, capacity),
		items:    make(map[string]*AggregatedFailure, capacity),
	}
}

func cleanTarget(target string) string {
	t := strings.TrimSpace(target)
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return strings.ToLower(t)
}

// Record ingests a failure event, aggregating by cleaned target + original action.
func (fm *FailureMonitor) Record(event FailureEvent) {
	if fm == nil {
		return
	}
	fm.mu.Lock()
	defer fm.mu.Unlock()

	target := cleanTarget(event.Target)
	if target == "" {
		return
	}

	action := strings.TrimSpace(event.OriginalAction)
	key := target + "|" + action
	errMsg := ""
	if event.Error != nil {
		errMsg = event.Error.Error()
	}

	now := time.Now()
	existing, found := fm.items[key]
	if found {
		existing.LastSeen = now
		existing.FailCount++
		existing.LastError = errMsg
		if event.Port > 0 {
			existing.Port = event.Port
		}
		if existing.Resolved {
			existing.Resolved = false
			fm.unresolved++
		}
		return
	}

	// Evict oldest item if capacity is reached
	for len(fm.items) >= fm.capacity && len(fm.order) > 0 {
		oldestKey := fm.order[0]
		fm.order = fm.order[1:]
		if oldItem, ok := fm.items[oldestKey]; ok {
			if !oldItem.Resolved {
				fm.unresolved--
			}
			delete(fm.items, oldestKey)
		}
	}

	rootDomain := ExtractRootDomain(target)
	recAction := "PROXY_POOL"
	if event.Category == FailureProxy || strings.HasPrefix(action, "PROXY") {
		recAction = "DIRECT"
	}

	item := &AggregatedFailure{
		Target:            target,
		RootDomain:        rootDomain,
		Port:              event.Port,
		OriginalAction:    action,
		Category:          event.Category,
		FirstSeen:         now,
		LastSeen:          now,
		FailCount:         1,
		LastError:         errMsg,
		OriginalRule:      event.OriginalRule,
		RecommendedAction: recAction,
		Resolved:          false,
	}

	fm.items[key] = item
	fm.order = append(fm.order, key)
	fm.unresolved++
}

// List returns a snapshot of all failures, sorted from newest to oldest.
func (fm *FailureMonitor) List() []AggregatedFailure {
	if fm == nil {
		return nil
	}
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	result := make([]AggregatedFailure, 0, len(fm.order))
	for i := len(fm.order) - 1; i >= 0; i-- {
		k := fm.order[i]
		if it, ok := fm.items[k]; ok {
			result = append(result, *it)
		}
	}
	return result
}

// Resolve marks all failure entries matching target as resolved.
func (fm *FailureMonitor) Resolve(target string) {
	if fm == nil {
		return
	}
	fm.mu.Lock()
	defer fm.mu.Unlock()

	clean := cleanTarget(target)
	root := ExtractRootDomain(clean)

	for _, item := range fm.items {
		if !item.Resolved {
			if item.Target == clean || (root != "" && item.RootDomain == root) {
				item.Resolved = true
				fm.unresolved--
			}
		}
	}
}

// UnresolvedCount returns the count of unresolved unique failures.
func (fm *FailureMonitor) UnresolvedCount() int {
	if fm == nil {
		return 0
	}
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	if fm.unresolved < 0 {
		return 0
	}
	return fm.unresolved
}

// Clear resets the failure monitor.
func (fm *FailureMonitor) Clear() {
	if fm == nil {
		return
	}
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.order = fm.order[:0]
	fm.items = make(map[string]*AggregatedFailure, fm.capacity)
	fm.unresolved = 0
}
