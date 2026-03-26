package threat

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ThreatType represents the category of a detected threat.
type ThreatType string

const (
	ThreatTypeInjection     ThreatType = "injection"
	ThreatTypeSocialEng     ThreatType = "social_eng"
	ThreatTypeContent       ThreatType = "content"
	ThreatTypeSpam          ThreatType = "spam"
)

// ThreatEntry represents a single recorded threat in the feed.
type ThreatEntry struct {
	Timestamp   time.Time  `json:"timestamp"`
	PatternHash string     `json:"pattern_hash"`
	ThreatType  ThreatType `json:"threat_type"`
	TextSample  string     `json:"text_sample"`
	Score       int        `json:"score"`
}

// ThreatSummary holds aggregate statistics for the threat feed.
type ThreatSummary struct {
	Total    int            `json:"total"`
	ByType   map[string]int `json:"by_type"`
	Last24h  int            `json:"last_24h"`
}

// ThreatFeed manages reading and writing threat intelligence entries to a JSONL file.
type ThreatFeed struct {
	path string
}

// DefaultFeedPath returns the default path for the threat feed file.
func DefaultFeedPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".seclint-threats.jsonl"
	}
	return filepath.Join(home, ".seclint-threats.jsonl")
}

// NewThreatFeed creates a new ThreatFeed backed by the given file path.
// The file is created lazily on first write.
func NewThreatFeed(path string) *ThreatFeed {
	return &ThreatFeed{path: path}
}

// normalizeText lowercases and collapses whitespace for consistent hashing.
func normalizeText(text string) string {
	lower := strings.ToLower(text)
	fields := strings.Fields(lower)
	return strings.Join(fields, " ")
}

// hashText returns a SHA-256 hex digest of the normalized text.
func hashText(text string) string {
	normalized := normalizeText(text)
	sum := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("%x", sum)
}

// textSample returns the first 100 characters of text.
func textSample(text string) string {
	runes := []rune(text)
	if len(runes) > 100 {
		return string(runes[:100])
	}
	return text
}

// wordSet splits text into a set of lowercase words.
func wordSet(text string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, word := range strings.Fields(strings.ToLower(text)) {
		set[word] = struct{}{}
	}
	return set
}

// jaccardSimilarity computes the Jaccard index between two word sets.
func jaccardSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	intersection := 0
	for word := range a {
		if _, ok := b[word]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

// Record appends a new threat entry to the JSONL feed file.
func (f *ThreatFeed) Record(text string, threatType ThreatType, score int) error {
	entry := ThreatEntry{
		Timestamp:   time.Now().UTC(),
		PatternHash: hashText(text),
		ThreatType:  threatType,
		TextSample:  textSample(text),
		Score:       score,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("threat: marshal entry: %w", err)
	}

	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("threat: open feed: %w", err)
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "%s\n", data)
	if err != nil {
		return fmt.Errorf("threat: write entry: %w", err)
	}
	return nil
}

// IsKnownThreat checks whether the given text matches a previously recorded threat.
// It returns (true, matchedType) on an exact hash match or Jaccard similarity >= 0.7.
// Returns (false, "") if no match is found or the feed file does not exist.
func (f *ThreatFeed) IsKnownThreat(text string) (bool, string) {
	file, err := os.Open(f.path)
	if err != nil {
		// File may not exist yet - that's fine.
		return false, ""
	}
	defer file.Close()

	incomingHash := hashText(text)
	incomingWords := wordSet(text)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry ThreatEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		// Fast path: exact hash match.
		if entry.PatternHash == incomingHash {
			return true, string(entry.ThreatType)
		}
		// Slow path: Jaccard similarity on word sets.
		sampleWords := wordSet(entry.TextSample)
		if len(sampleWords) > 0 && jaccardSimilarity(incomingWords, sampleWords) >= 0.7 {
			return true, string(entry.ThreatType)
		}
	}
	return false, ""
}

// Summary returns aggregate statistics for all entries in the feed.
func (f *ThreatFeed) Summary() ThreatSummary {
	summary := ThreatSummary{
		ByType: make(map[string]int),
	}

	file, err := os.Open(f.path)
	if err != nil {
		return summary
	}
	defer file.Close()

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry ThreatEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		summary.Total++
		summary.ByType[string(entry.ThreatType)]++
		if entry.Timestamp.After(cutoff) {
			summary.Last24h++
		}
	}
	return summary
}

// List returns the most recent entries from the feed, up to limit.
func (f *ThreatFeed) List(limit int) ([]ThreatEntry, error) {
	file, err := os.Open(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("threat: open feed: %w", err)
	}
	defer file.Close()

	var all []ThreatEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry ThreatEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		all = append(all, entry)
	}

	if limit <= 0 || limit >= len(all) {
		return all, nil
	}
	// Return last `limit` entries (most recent).
	return all[len(all)-limit:], nil
}
