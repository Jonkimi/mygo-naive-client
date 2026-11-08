package blocker

import "time"

// Blocker defines the interface for matching domains against blocking rules.
type Blocker interface {
	Match(domain string) (blocked bool, rule string)
}

// Verdict indicates the blocking decision for a query.
type Verdict string

const (
	VerdictAllowed     Verdict = "ALLOWED"
	VerdictBlocked     Verdict = "BLOCKED"
	VerdictWhitelisted Verdict = "WHITELISTED"
)

// QuerySource indicates where the query was initiated.
type QuerySource string

const (
	SourceDNS     QuerySource = "DNS"
	SourceGateway QuerySource = "Gateway"
)

// QueryLogEntry represents an in-memory recorded domain query event.
type QueryLogEntry struct {
	ID        int64       `json:"id"`
	Timestamp time.Time   `json:"timestamp"`
	Domain    string      `json:"domain"`
	Source    QuerySource `json:"source"`
	Verdict   Verdict     `json:"verdict"`
	Rule      string        `json:"rule"`
	Chain     string        `json:"chain,omitempty"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration,omitempty"`
}

// HourlyBucket records aggregate queries in a one-hour window.
type HourlyBucket struct {
	Hour    time.Time `json:"hour"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
}
