// Package report generates daily security report cards from the audit log.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// auditEntry mirrors audit.AuditEntry for standalone JSONL parsing.
type auditEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	Rating        string    `json:"rating"`
	SecurityScore int       `json:"security_score"`
	Flags         []string  `json:"flags,omitempty"`
	Blocked       bool      `json:"blocked"`
	ThreatType    string    `json:"threat_type,omitempty"`
}

// ThreatCount holds the count of a specific threat type.
type ThreatCount struct {
	ThreatType string `json:"threat_type"`
	Count      int    `json:"count"`
}

// ReportCard is the daily security summary.
type ReportCard struct {
	Date                string        `json:"date"`
	TotalScanned        int           `json:"total_scanned"`
	TotalBlocked        int           `json:"total_blocked"`
	BlockRate           float64       `json:"block_rate"`
	TopThreats          []ThreatCount `json:"top_threats"`
	TrendVsYesterday    float64       `json:"trend_vs_yesterday"` // pct change in block rate
	SecurityHealthScore int           `json:"security_health_score"` // 0-100
}

// GenerateReportCard reads the JSONL audit log at auditPath and builds
// today's ReportCard. If auditPath is empty, the default path is used.
func GenerateReportCard(auditPath string) (ReportCard, error) {
	if auditPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			auditPath = ".seclint-audit.jsonl"
		} else {
			auditPath = home + "/.seclint-audit.jsonl"
		}
	}

	entries, err := readEntries(auditPath)
	if err != nil {
		return ReportCard{}, err
	}

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	yesterdayStart := todayStart.Add(-24 * time.Hour)

	var todayEntries, yesterdayEntries []auditEntry
	for _, e := range entries {
		if !e.Timestamp.Before(todayStart) {
			todayEntries = append(todayEntries, e)
		} else if !e.Timestamp.Before(yesterdayStart) {
			yesterdayEntries = append(yesterdayEntries, e)
		}
	}

	card := ReportCard{
		Date: todayStart.Format("2006-01-02"),
	}

	card.TotalScanned, card.TotalBlocked = countScanBlocked(todayEntries)
	if card.TotalScanned > 0 {
		card.BlockRate = float64(card.TotalBlocked) / float64(card.TotalScanned)
	}

	card.TopThreats = topThreats(todayEntries, 5)

	// Trend: compare block rate today vs yesterday
	yScanned, yBlocked := countScanBlocked(yesterdayEntries)
	var yBlockRate float64
	if yScanned > 0 {
		yBlockRate = float64(yBlocked) / float64(yScanned)
	}
	if yBlockRate > 0 {
		card.TrendVsYesterday = (card.BlockRate - yBlockRate) / yBlockRate * 100
	}

	card.SecurityHealthScore = computeHealthScore(card.BlockRate, card.TopThreats)

	return card, nil
}

// countScanBlocked returns total scanned and blocked counts.
func countScanBlocked(entries []auditEntry) (scanned, blocked int) {
	for _, e := range entries {
		scanned++
		if e.Blocked {
			blocked++
		}
	}
	return
}

// topThreats aggregates threat types and returns the top n by count.
func topThreats(entries []auditEntry, n int) []ThreatCount {
	counts := make(map[string]int)
	for _, e := range entries {
		if e.ThreatType != "" {
			counts[e.ThreatType]++
		}
	}
	result := make([]ThreatCount, 0, len(counts))
	for t, c := range counts {
		result = append(result, ThreatCount{ThreatType: t, Count: c})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].ThreatType < result[j].ThreatType
	})
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// severityWeight returns a multiplier (1.0-2.0) based on threat type name.
// Critical/injection threats are weighted higher.
func severityWeight(threatType string) float64 {
	t := strings.ToLower(threatType)
	switch {
	case strings.Contains(t, "injection") || strings.Contains(t, "jailbreak"):
		return 2.0
	case strings.Contains(t, "violence") || strings.Contains(t, "explicit"):
		return 1.75
	case strings.Contains(t, "hate") || strings.Contains(t, "harm"):
		return 1.5
	default:
		return 1.0
	}
}

// computeHealthScore returns a 0-100 score.
// 100 = perfect (no blocks), 0 = all requests blocked with severe threats.
func computeHealthScore(blockRate float64, threats []ThreatCount) int {
	if blockRate == 0 {
		return 100
	}

	// Base penalty from block rate (0-80 points)
	basePenalty := blockRate * 80

	// Severity adjustment from top threats (0-20 additional points)
	var severityPenalty float64
	totalThreats := 0
	for _, tc := range threats {
		totalThreats += tc.Count
	}
	if totalThreats > 0 {
		for _, tc := range threats {
			weight := severityWeight(tc.ThreatType)
			fraction := float64(tc.Count) / float64(totalThreats)
			severityPenalty += fraction * (weight - 1.0) * 20
		}
	}

	score := 100 - basePenalty - severityPenalty
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return int(score)
}

// FormatText returns a human-readable representation of the ReportCard.
func FormatText(r ReportCard) string {
	var sb strings.Builder

	sb.WriteString("=== Security Report Card ===\n")
	sb.WriteString(fmt.Sprintf("Date:                 %s\n", r.Date))
	sb.WriteString(fmt.Sprintf("Security Health Score: %d/100\n", r.SecurityHealthScore))
	sb.WriteString("\n--- Scan Summary ---\n")
	sb.WriteString(fmt.Sprintf("Total Scanned:        %d\n", r.TotalScanned))
	sb.WriteString(fmt.Sprintf("Total Blocked:        %d\n", r.TotalBlocked))
	sb.WriteString(fmt.Sprintf("Block Rate:           %.1f%%\n", r.BlockRate*100))

	trendSign := "+"
	if r.TrendVsYesterday < 0 {
		trendSign = ""
	}
	sb.WriteString(fmt.Sprintf("Trend vs Yesterday:   %s%.1f%%\n", trendSign, r.TrendVsYesterday))

	if len(r.TopThreats) > 0 {
		sb.WriteString("\n--- Top Threats Today ---\n")
		for i, tc := range r.TopThreats {
			sb.WriteString(fmt.Sprintf("  %d. %-30s %d\n", i+1, tc.ThreatType, tc.Count))
		}
	} else {
		sb.WriteString("\nNo threats detected today.\n")
	}

	sb.WriteString("\n")
	healthLabel := healthLabel(r.SecurityHealthScore)
	sb.WriteString(fmt.Sprintf("Status: %s\n", healthLabel))

	return sb.String()
}

// healthLabel converts numeric score to a status string.
func healthLabel(score int) string {
	switch {
	case score >= 90:
		return "HEALTHY"
	case score >= 70:
		return "MODERATE"
	case score >= 50:
		return "AT RISK"
	default:
		return "CRITICAL"
	}
}

// readEntries parses all JSONL entries from path.
// Returns empty slice if file does not exist.
func readEntries(path string) ([]auditEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("report: read %s: %w", path, err)
	}

	var entries []auditEntry
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
		var e auditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, e)
	}
	return entries, nil
}
