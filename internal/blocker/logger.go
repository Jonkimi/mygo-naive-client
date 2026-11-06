package blocker

import (
	"sort"
	"sync"
	"time"
)

// TopDomainItem represents domain frequency ranking entry.
type TopDomainItem struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// QueryLogger maintains zero-disk-wear in-memory query ring buffer,
// 24-hour sliding hourly metrics, and top blocked/allowed counters.
type QueryLogger struct {
	mu            sync.RWMutex
	capacity      int
	entries       []QueryLogEntry
	start         int
	count         int
	nextID        int64
	hourlyMap     map[int64]*HourlyBucket // hour unix -> bucket
	blockedCounts map[string]int64
	allowedCounts map[string]int64
}

// NewQueryLogger creates an in-memory query logger with the given ring buffer capacity.
func NewQueryLogger(capacity int) *QueryLogger {
	if capacity <= 0 {
		capacity = 2000
	}
	return &QueryLogger{
		capacity:      capacity,
		entries:       make([]QueryLogEntry, capacity),
		hourlyMap:     make(map[int64]*HourlyBucket),
		blockedCounts: make(map[string]int64),
		allowedCounts: make(map[string]int64),
	}
}

// Record records a query event at current timestamp.
func (l *QueryLogger) Record(domain string, source QuerySource, verdict Verdict, rule string) {
	l.RecordAt(domain, source, verdict, rule, time.Now())
}

// RecordAt records a query event at a specific timestamp.
func (l *QueryLogger) RecordAt(domain string, source QuerySource, verdict Verdict, rule string, ts time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.nextID++
	entry := QueryLogEntry{
		ID:        l.nextID,
		Timestamp: ts,
		Domain:    domain,
		Source:    source,
		Verdict:   verdict,
		Rule:      rule,
	}

	// Ring buffer insert
	idx := (l.start + l.count) % l.capacity
	l.entries[idx] = entry
	if l.count < l.capacity {
		l.count++
	} else {
		l.start = (l.start + 1) % l.capacity
	}

	// 24-hour sliding hourly aggregation
	hourKey := ts.Truncate(time.Hour).Unix()
	bucket, ok := l.hourlyMap[hourKey]
	if !ok {
		bucket = &HourlyBucket{
			Hour: ts.Truncate(time.Hour),
		}
		l.hourlyMap[hourKey] = bucket
	}
	bucket.Total++
	if verdict == VerdictBlocked {
		bucket.Blocked++
		l.blockedCounts[domain]++
	} else {
		l.allowedCounts[domain]++
	}

	// Clean up hourly buckets older than 48 hours
	if len(l.hourlyMap) > 48 {
		cutoff := ts.Add(-48 * time.Hour).Unix()
		for k := range l.hourlyMap {
			if k < cutoff {
				delete(l.hourlyMap, k)
			}
		}
	}
}

// GetEntries returns recent query log entries, sorted newest first.
// If limit <= 0 or limit > count, returns all recorded entries.
func (l *QueryLogger) GetEntries(limit int) []QueryLogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	n := l.count
	if limit > 0 && limit < n {
		n = limit
	}

	res := make([]QueryLogEntry, n)
	for i := 0; i < n; i++ {
		// Newest entry is at (start + count - 1 - i) % capacity
		idx := (l.start + l.count - 1 - i) % l.capacity
		res[i] = l.entries[idx]
	}
	return res
}

// Get24HourlyBuckets returns an array of 24 hourly buckets ending at now.
func (l *QueryLogger) Get24HourlyBuckets(now time.Time) [24]HourlyBucket {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result [24]HourlyBucket
	currentHour := now.Truncate(time.Hour)

	// Result from currentHour-23h to currentHour
	for i := 0; i < 24; i++ {
		h := currentHour.Add(time.Duration(i-23) * time.Hour)
		key := h.Unix()
		if b, ok := l.hourlyMap[key]; ok {
			result[i] = *b
		} else {
			result[i] = HourlyBucket{
				Hour:    h,
				Total:   0,
				Blocked: 0,
			}
		}
	}
	return result
}

// GetTopBlocked returns top N blocked domains sorted descending.
func (l *QueryLogger) GetTopBlocked(limit int) []TopDomainItem {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return sortTopItems(l.blockedCounts, limit)
}

// GetTopAllowed returns top N allowed domains sorted descending.
func (l *QueryLogger) GetTopAllowed(limit int) []TopDomainItem {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return sortTopItems(l.allowedCounts, limit)
}

// GetStatsSummary returns total queries and total blocked queries.
func (l *QueryLogger) GetStatsSummary() (total int64, blocked int64) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, b := range l.hourlyMap {
		total += b.Total
		blocked += b.Blocked
	}
	return total, blocked
}

func sortTopItems(counts map[string]int64, limit int) []TopDomainItem {
	items := make([]TopDomainItem, 0, len(counts))
	for domain, count := range counts {
		items = append(items, TopDomainItem{Domain: domain, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Domain < items[j].Domain
		}
		return items[i].Count > items[j].Count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}
