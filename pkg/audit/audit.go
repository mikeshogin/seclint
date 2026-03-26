// Package audit provides a JSONL-based security audit log for seclint scan events.
package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultAuditPath returns the default path for the audit log file.
func DefaultAuditPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".seclint-audit.jsonl"
	}
	return filepath.Join(home, ".seclint-audit.jsonl")
}

// AuditEntry is a single scan event written to the audit log.
type AuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	TextHash    string    `json:"text_hash"`   // SHA-256 hex of the scanned text
	Rating      string    `json:"rating"`      // classifier rating: 6+, 12+, 16+, 18+, BLOCKED
	SecurityScore int     `json:"security_score"` // 0-100
	Flags       []string  `json:"flags,omitempty"`
	Blocked     bool      `json:"blocked"`
	ThreatType  string    `json:"threat_type,omitempty"`
}

// HashText returns the SHA-256 hex digest of text.
func HashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", sum)
}

// AuditSummary holds aggregate statistics derived from the audit log.
type AuditSummary struct {
	TotalScanned int            `json:"total_scanned"`
	TotalBlocked int            `json:"total_blocked"`
	BlockRate    float64        `json:"block_rate"` // 0.0-1.0
	ByType       map[string]int `json:"by_type"`
	Last24h      Last24hStats   `json:"last_24h"`
}

// Last24hStats is a subset of AuditSummary scoped to the last 24 hours.
type Last24hStats struct {
	Scanned int `json:"scanned"`
	Blocked int `json:"blocked"`
}

// AuditLog appends scan entries to a JSONL file.
type AuditLog struct {
	path string
	mu   sync.Mutex
}

// NewAuditLog creates an AuditLog that writes to path.
// Pass an empty string to use the default path (~/.seclint-audit.jsonl).
func NewAuditLog(path string) *AuditLog {
	if path == "" {
		path = DefaultAuditPath()
	}
	return &AuditLog{path: path}
}

// Record appends entry to the JSONL audit log.
// The file is created if it does not exist.
func (a *AuditLog) Record(entry AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", a.path, err)
	}
	defer f.Close()

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	line = append(line, '\n')

	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("audit: write entry: %w", err)
	}
	return nil
}

// readAll reads and parses all entries from the audit log.
// Returns an empty slice if the file does not exist.
func (a *AuditLog) readAll() ([]AuditEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	data, err := os.ReadFile(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read %s: %w", a.path, err)
	}

	var entries []AuditEntry
	for len(data) > 0 {
		idx := 0
		for idx < len(data) && data[idx] != '\n' {
			idx++
		}
		line := data[:idx]
		if idx < len(data) {
			data = data[idx+1:]
		} else {
			data = nil
		}
		if len(line) == 0 {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			// Skip malformed lines
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Summary computes aggregate statistics over the full audit log.
func (a *AuditLog) Summary() (AuditSummary, error) {
	entries, err := a.readAll()
	if err != nil {
		return AuditSummary{}, err
	}

	summary := AuditSummary{
		ByType: make(map[string]int),
	}

	cutoff := time.Now().Add(-24 * time.Hour)

	for _, e := range entries {
		summary.TotalScanned++
		if e.Blocked {
			summary.TotalBlocked++
		}
		if e.ThreatType != "" {
			summary.ByType[e.ThreatType]++
		}
		if e.Timestamp.After(cutoff) {
			summary.Last24h.Scanned++
			if e.Blocked {
				summary.Last24h.Blocked++
			}
		}
	}

	if summary.TotalScanned > 0 {
		summary.BlockRate = float64(summary.TotalBlocked) / float64(summary.TotalScanned)
	}

	return summary, nil
}

// Tail returns the last n entries from the audit log.
// If the log has fewer than n entries, all entries are returned.
func (a *AuditLog) Tail(n int) ([]AuditEntry, error) {
	entries, err := a.readAll()
	if err != nil {
		return nil, err
	}
	if n <= 0 || len(entries) <= n {
		return entries, nil
	}
	return entries[len(entries)-n:], nil
}
