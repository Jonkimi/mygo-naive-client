package blocker

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const maxTrackedDomains = 5000

// DefaultDedupWindow is the default time window for suppressing duplicate query logs.
const DefaultDedupWindow = 800 * time.Millisecond

type recentKey struct {
	domain  string
	source  QuerySource
	verdict Verdict
}

func pruneCounts(m map[string]int64, max int) {
	if len(m) <= max {
		return
	}
	items := sortTopItems(m, max/2)
	for k := range m {
		delete(m, k)
	}
	for _, it := range items {
		m[it.Domain] = it.Count
	}
}

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
	totalQueries  int64
	totalBlocked  int64

	dedupWindow   time.Duration
	recentQueries map[recentKey]time.Time

	dirtyTop        bool
	topBlockedCache []TopDomainItem
	topAllowedCache []TopDomainItem
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
		dedupWindow:   DefaultDedupWindow,
		recentQueries: make(map[recentKey]time.Time),
	}
}

// SetDedupWindow updates the deduplication time window.
// Setting it to 0 disables query deduplication.
func (l *QueryLogger) SetDedupWindow(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dedupWindow = d
	if d <= 0 {
		l.recentQueries = make(map[recentKey]time.Time)
	}
}

// Record records a query event at current timestamp.
func (l *QueryLogger) Record(domain string, source QuerySource, verdict Verdict, rule string) {
	l.RecordAtWithChain(domain, source, verdict, rule, "", time.Now())
}

// RecordWithChain records a query event with routing chain information at current timestamp.
func (l *QueryLogger) RecordWithChain(domain string, source QuerySource, verdict Verdict, rule string, chain string) {
	l.RecordAtWithChain(domain, source, verdict, rule, chain, time.Now())
}

// RecordAt records a query event at a specific timestamp.
func (l *QueryLogger) RecordAt(domain string, source QuerySource, verdict Verdict, rule string, ts time.Time) {
	l.RecordAtWithChain(domain, source, verdict, rule, "", ts)
}

// RecordAtWithChain records a query event with routing chain information at a specific timestamp.
func (l *QueryLogger) RecordAtWithChain(domain string, source QuerySource, verdict Verdict, rule string, chain string, ts time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.dedupWindow > 0 {
		k := recentKey{domain: domain, source: source, verdict: verdict}
		if lastTs, exists := l.recentQueries[k]; exists {
			diff := ts.Sub(lastTs)
			if diff >= 0 && diff < l.dedupWindow {
				return
			}
		}
		l.recentQueries[k] = ts
		if len(l.recentQueries) > 256 {
			cutoff := ts.Add(-2 * l.dedupWindow)
			for rk, rt := range l.recentQueries {
				if rt.Before(cutoff) {
					delete(l.recentQueries, rk)
				}
			}
		}
	}

	if chain == "" && rule != "" {
		chain = rule
	}

	l.nextID++
	entry := QueryLogEntry{
		ID:        l.nextID,
		Timestamp: ts,
		Domain:    domain,
		Source:    source,
		Verdict:   verdict,
		Rule:      rule,
		Chain:     chain,
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
	l.totalQueries++
	bucket.Total++
	l.dirtyTop = true
	if verdict == VerdictBlocked {
		l.totalBlocked++
		bucket.Blocked++
		l.blockedCounts[domain]++
		if len(l.blockedCounts) > maxTrackedDomains {
			pruneCounts(l.blockedCounts, maxTrackedDomains)
		}
	} else {
		l.allowedCounts[domain]++
		if len(l.allowedCounts) > maxTrackedDomains {
			pruneCounts(l.allowedCounts, maxTrackedDomains)
		}
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
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dirtyTop || l.topBlockedCache == nil {
		l.topBlockedCache = sortTopItems(l.blockedCounts, 0)
		l.topAllowedCache = sortTopItems(l.allowedCounts, 0)
		l.dirtyTop = false
	}
	return sliceTopItems(l.topBlockedCache, limit)
}

// GetTopAllowed returns top N allowed domains sorted descending.
func (l *QueryLogger) GetTopAllowed(limit int) []TopDomainItem {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dirtyTop || l.topAllowedCache == nil {
		l.topBlockedCache = sortTopItems(l.blockedCounts, 0)
		l.topAllowedCache = sortTopItems(l.allowedCounts, 0)
		l.dirtyTop = false
	}
	return sliceTopItems(l.topAllowedCache, limit)
}

func sliceTopItems(src []TopDomainItem, limit int) []TopDomainItem {
	n := len(src)
	if limit > 0 && limit < n {
		n = limit
	}
	res := make([]TopDomainItem, n)
	copy(res, src[:n])
	return res
}

// GetFilteredEntries scans newest-first and returns up to limit matching entries along with total recorded count.
func (l *QueryLogger) GetFilteredEntries(verdictFilter string, domainQuery string, limit int) (entries []QueryLogEntry, totalRecorded int) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	totalRecorded = l.count
	if limit <= 0 {
		limit = 50
	}

	q := strings.ToLower(strings.TrimSpace(domainQuery))
	res := make([]QueryLogEntry, 0, min(limit, l.count))

	for i := 0; i < l.count; i++ {
		idx := (l.start + l.count - 1 - i) % l.capacity
		e := l.entries[idx]

		if verdictFilter == "blocked" && e.Verdict != VerdictBlocked {
			continue
		}
		if verdictFilter == "allowed" && e.Verdict != VerdictAllowed && e.Verdict != VerdictWhitelisted {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Domain), q) {
			continue
		}

		res = append(res, e)
		if len(res) >= limit {
			break
		}
	}
	return res, totalRecorded
}

// GetStatsSummary returns total queries and total blocked queries in O(1) time.
func (l *QueryLogger) GetStatsSummary() (total int64, blocked int64) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.totalQueries, l.totalBlocked
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
