package report

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func writeAuditEntries(t *testing.T, entries []auditEntry) string {
	t.Helper()
	f, err := os.CreateTemp("", "audit-*.jsonl")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		f.Write(append(line, '\n'))
	}
	return f.Name()
}

func TestGenerateReportCard_Empty(t *testing.T) {
	path := writeAuditEntries(t, nil)
	defer os.Remove(path)

	card, err := GenerateReportCard(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if card.TotalScanned != 0 {
		t.Errorf("expected 0 scanned, got %d", card.TotalScanned)
	}
	if card.SecurityHealthScore != 100 {
		t.Errorf("expected health score 100 for empty log, got %d", card.SecurityHealthScore)
	}
}

func TestGenerateReportCard_TodayOnly(t *testing.T) {
	now := time.Now()
	entries := []auditEntry{
		{Timestamp: now, Blocked: false, ThreatType: ""},
		{Timestamp: now, Blocked: true, ThreatType: "injection"},
		{Timestamp: now, Blocked: true, ThreatType: "injection"},
		{Timestamp: now, Blocked: false, ThreatType: ""},
	}
	path := writeAuditEntries(t, entries)
	defer os.Remove(path)

	card, err := GenerateReportCard(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if card.TotalScanned != 4 {
		t.Errorf("expected 4 scanned, got %d", card.TotalScanned)
	}
	if card.TotalBlocked != 2 {
		t.Errorf("expected 2 blocked, got %d", card.TotalBlocked)
	}
	if card.BlockRate != 0.5 {
		t.Errorf("expected block rate 0.5, got %f", card.BlockRate)
	}
	if len(card.TopThreats) != 1 || card.TopThreats[0].ThreatType != "injection" {
		t.Errorf("expected top threat 'injection', got %+v", card.TopThreats)
	}
	if card.SecurityHealthScore < 0 || card.SecurityHealthScore > 100 {
		t.Errorf("health score out of range: %d", card.SecurityHealthScore)
	}
}

func TestGenerateReportCard_TrendPositive(t *testing.T) {
	now := time.Now()
	yesterday := now.Add(-25 * time.Hour)

	// Yesterday: 2/4 blocked (50%)
	// Today: 1/4 blocked (25%) -> trend should be negative (improvement)
	entries := []auditEntry{
		{Timestamp: yesterday, Blocked: true},
		{Timestamp: yesterday, Blocked: true},
		{Timestamp: yesterday, Blocked: false},
		{Timestamp: yesterday, Blocked: false},
		{Timestamp: now, Blocked: true},
		{Timestamp: now, Blocked: false},
		{Timestamp: now, Blocked: false},
		{Timestamp: now, Blocked: false},
	}
	path := writeAuditEntries(t, entries)
	defer os.Remove(path)

	card, err := GenerateReportCard(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Today block rate is lower than yesterday -> negative trend (good)
	if card.TrendVsYesterday >= 0 {
		t.Errorf("expected negative trend (improvement), got %f", card.TrendVsYesterday)
	}
}

func TestGenerateReportCard_MissingFile(t *testing.T) {
	card, err := GenerateReportCard("/tmp/does-not-exist-seclint-test.jsonl")
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	if card.TotalScanned != 0 {
		t.Errorf("expected 0 scanned for missing file, got %d", card.TotalScanned)
	}
}

func TestFormatText(t *testing.T) {
	card := ReportCard{
		Date:                "2026-03-26",
		TotalScanned:        100,
		TotalBlocked:        10,
		BlockRate:           0.1,
		TopThreats:          []ThreatCount{{ThreatType: "injection", Count: 8}},
		TrendVsYesterday:    -5.0,
		SecurityHealthScore: 85,
	}
	text := FormatText(card)
	if len(text) == 0 {
		t.Error("expected non-empty text output")
	}
	for _, want := range []string{"2026-03-26", "100", "10", "injection", "85"} {
		if !containsString(text, want) {
			t.Errorf("expected %q in text output:\n%s", want, text)
		}
	}
}

func TestComputeHealthScore(t *testing.T) {
	tests := []struct {
		blockRate float64
		threats   []ThreatCount
		wantMin   int
		wantMax   int
	}{
		{0, nil, 100, 100},
		{1.0, nil, 0, 20},
		{0.5, []ThreatCount{{ThreatType: "injection", Count: 1}}, 0, 60},
	}
	for _, tc := range tests {
		score := computeHealthScore(tc.blockRate, tc.threats)
		if score < tc.wantMin || score > tc.wantMax {
			t.Errorf("computeHealthScore(%f, %v) = %d, want [%d, %d]",
				tc.blockRate, tc.threats, score, tc.wantMin, tc.wantMax)
		}
	}
}

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
