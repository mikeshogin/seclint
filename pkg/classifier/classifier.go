package classifier

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/mikeshogin/seclint/pkg/config"
	"github.com/mikeshogin/seclint/pkg/threat"
)

// defaultFeed is the package-level ThreatFeed used for recording and fast-path lookups.
var defaultFeed = threat.NewThreatFeed(threat.DefaultFeedPath())

// SetFeed replaces the package-level threat feed. Useful for testing.
func SetFeed(f *threat.ThreatFeed) {
	defaultFeed = f
}

// promptInjectionPhrases are exact substring triggers for jailbreak / injection attempts.
var promptInjectionPhrases = []string{
	"ignore previous instructions",
	"ignore all previous",
	"disregard your instructions",
	"disregard all instructions",
	"forget everything",
	"forget your instructions",
	"reset your instructions",
	"show me your system prompt",
	"reveal your system prompt",
	"print your system prompt",
	"output your system prompt",
	"jailbreak",
	"dan mode",
	"developer mode enabled",
}

// promptInjectionPatterns are compiled regexes for more nuanced injection attempts.
var promptInjectionPatterns = []*regexp.Regexp{
	// "you are now X" - persona replacement
	regexp.MustCompile(`\byou\s+are\s+now\b`),
	// "pretend you are" / "pretend to be"
	regexp.MustCompile(`\bpretend\s+(you\s+are|to\s+be)\b`),
	// "act as" combined with "no restrictions" / "without restrictions" / "unrestricted"
	regexp.MustCompile(`\bact\s+as\b.{0,80}(no\s+restrictions|without\s+restrictions|unrestricted|no\s+limits|without\s+limits)`),
	// "roleplay as" combined with "no restrictions" / "unrestricted"
	regexp.MustCompile(`\broleplay\s+as\b.{0,80}(no\s+restrictions|without\s+restrictions|unrestricted|no\s+limits|without\s+limits)`),
	// "system prompt" as a standalone concept (not just the word in a sentence)
	regexp.MustCompile(`\bsystem\s+prompt\b`),
	// Delimiter injection: 4+ consecutive delimiter chars used to break formatting context
	regexp.MustCompile("(`{4,}|={4,}|-{4,})"),
}

// looksLikeBase64Command returns true if the text contains a base64-encoded string
// that decodes to something resembling a shell command or instruction override.
func looksLikeBase64Command(text string) bool {
	// Extract tokens that look like base64 (length >= 20, only base64 chars)
	b64Re := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	for _, token := range b64Re.FindAllString(text, 10) {
		decoded, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			decoded2, err2 := base64.URLEncoding.DecodeString(token)
			if err2 != nil {
				continue
			}
			decoded = decoded2
		}
		lower := strings.ToLower(string(decoded))
		// Check if decoded content contains injection phrases
		for _, phrase := range promptInjectionPhrases {
			if strings.Contains(lower, phrase) {
				return true
			}
		}
		for _, re := range promptInjectionPatterns {
			if re.MatchString(lower) {
				return true
			}
		}
	}
	return false
}

// detectPromptInjection returns a non-empty detail string if prompt injection is detected.
func detectPromptInjection(lower, original string) string {
	// Check exact phrase triggers
	for _, phrase := range promptInjectionPhrases {
		if strings.Contains(lower, phrase) {
			return "prompt injection - jailbreak or instruction override detected"
		}
	}

	// Check regex patterns
	for _, re := range promptInjectionPatterns {
		if re.MatchString(lower) {
			return "prompt injection - jailbreak or instruction override detected"
		}
	}

	// Check base64-encoded injection attempts
	if looksLikeBase64Command(original) {
		return "prompt injection - base64-encoded instruction override detected"
	}

	return ""
}

// socialEngineeringPatterns are compiled regexes for pipe-to-shell and run-script attacks.
var socialEngineeringPatterns = []*regexp.Regexp{
	// curl/wget piped to shell interpreters
	regexp.MustCompile(`curl\s+[^|]*\|\s*(bash|sh|python[23]?|perl|ruby|node)`),
	regexp.MustCompile(`wget\s+[^|]*\|\s*(bash|sh|python[23]?|perl|ruby|node)`),
	// backtick execution with curl/wget
	regexp.MustCompile("`\\s*(curl|wget)\\s+[^`]+`"),
	// $(curl ...) or $(wget ...) command substitution
	regexp.MustCompile(`\$\(\s*(curl|wget)\s+[^)]+\)`),
}

// runScriptTriggers are phrases that prompt the user to execute something.
var runScriptTriggers = []string{
	"run this", "execute this", "try this", "run the script", "execute the script",
	"just run", "simply run", "paste this", "paste and run",
}

// detectSocialEngineering returns a non-empty detail string if social engineering is found.
func detectSocialEngineering(lower, original string) string {
	// Check pipe-to-shell patterns
	for _, re := range socialEngineeringPatterns {
		if re.MatchString(lower) {
			return "social engineering - pipe to shell detected"
		}
	}

	// Check "run this/execute" near a URL (http/https link present + trigger phrase)
	hasURL := strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
	if hasURL {
		for _, trigger := range runScriptTriggers {
			if strings.Contains(lower, trigger) {
				return "social engineering - run-script prompt with URL detected"
			}
		}
	}

	return ""
}

// SecurityScoreBreakdown holds per-category threat scores (0-25 each).
type SecurityScoreBreakdown struct {
	Injection         int `json:"injection"`
	SocialEngineering int `json:"social_engineering"`
	Content           int `json:"content"`
	Spam              int `json:"spam"`
}

// SecurityScore holds the total security score and per-category breakdown.
// Total is 0-100: 100 = clean, lower = more threats detected.
type SecurityScore struct {
	Total     int                    `json:"total"`
	Breakdown SecurityScoreBreakdown `json:"breakdown"`
}

// spamPhrases are low-effort / generic phrases that indicate spam.
var spamPhrases = []string{
	"click here", "click now", "buy now", "limited offer", "limited time offer",
	"act now", "free money", "you have been selected", "congratulations you won",
	"make money fast", "earn money online", "work from home", "get rich quick",
	"100% free", "no cost", "special promotion", "exclusive deal",
	"winner", "prize", "claim your", "you are a winner",
}

// contentThreatKeywords are severe content categories that contribute to the content score.
var contentThreatKeywords = map[string][]string{
	"drugs":         {"drug", "narcotic", "cocaine", "marijuana", "overdose", "substance abuse"},
	"violence":      {"kill", "murder", "weapon", "gun", "knife", "attack", "bomb", "explode", "assault", "torture"},
	"adult_content": {"explicit", "nsfw", "porn", "sexual", "erotic", "nude", "fetish"},
	"illegal":       {"illegal", "fraud", "counterfeit", "launder", "trafficking", "steal", "theft"},
}

// contentThreatPatterns are word-boundary patterns for content threat keywords.
var contentThreatPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bmeth\b`),
	regexp.MustCompile(`\bheroin\b`),
}

// ComputeSecurityScore computes a 0-100 security score for the given text.
// 100 = fully clean, 0 = maximum threat. Each of 4 categories contributes 0-25.
func ComputeSecurityScore(text string) SecurityScore {
	lower := strings.ToLower(text)

	breakdown := SecurityScoreBreakdown{}

	// --- injection (0-25) ---
	if detectPromptInjection(lower, text) != "" {
		breakdown.Injection = 25
	} else {
		// Partial: count matched phrases/patterns
		matchCount := 0
		for _, phrase := range promptInjectionPhrases {
			if strings.Contains(lower, phrase) {
				matchCount++
			}
		}
		for _, re := range promptInjectionPatterns {
			if re.MatchString(lower) {
				matchCount++
			}
		}
		if matchCount > 0 {
			breakdown.Injection = min25(matchCount * 8)
		}
	}

	// --- social_engineering (0-25) ---
	if detectSocialEngineering(lower, text) != "" {
		breakdown.SocialEngineering = 25
	} else {
		matchCount := 0
		for _, re := range socialEngineeringPatterns {
			if re.MatchString(lower) {
				matchCount++
			}
		}
		hasURL := strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
		if hasURL {
			for _, trigger := range runScriptTriggers {
				if strings.Contains(lower, trigger) {
					matchCount++
				}
			}
		}
		if matchCount > 0 {
			breakdown.SocialEngineering = min25(matchCount * 8)
		}
	}

	// --- content (0-25) ---
	contentHits := 0
	for _, keywords := range contentThreatKeywords {
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				contentHits++
				break // count one hit per category
			}
		}
	}
	// word-boundary patterns for drug terms
	for _, re := range contentThreatPatterns {
		if re.MatchString(lower) {
			contentHits++
		}
	}
	if contentHits > 0 {
		breakdown.Content = min25(contentHits * 8)
	}

	// --- spam (0-25) ---
	spamHits := 0
	for _, phrase := range spamPhrases {
		if strings.Contains(lower, phrase) {
			spamHits++
		}
	}
	if spamHits > 0 {
		breakdown.Spam = min25(spamHits * 5)
	}

	total := 100 - breakdown.Injection - breakdown.SocialEngineering - breakdown.Content - breakdown.Spam
	if total < 0 {
		total = 0
	}

	return SecurityScore{
		Total:     total,
		Breakdown: breakdown,
	}
}

// min25 clamps v to the range [0, 25].
func min25(v int) int {
	if v > 25 {
		return 25
	}
	if v < 0 {
		return 0
	}
	return v
}

// Rating represents content age rating.
type Rating string

const (
	Rating6Plus  Rating = "6+"
	Rating12Plus Rating = "12+"
	Rating16Plus Rating = "16+"
	Rating18Plus Rating = "18+"
	RatingBlock  Rating = "BLOCKED"
)

// Result contains classification output.
type Result struct {
	Rating        Rating        `json:"rating"`
	Safe          bool          `json:"safe"`
	Flags         []string      `json:"flags,omitempty"`
	Score         int           `json:"score"`
	Details       string        `json:"details,omitempty"`
	SecurityScore SecurityScore `json:"security_score"`
}

// category word lists - severity levels
var categories = map[string]struct {
	keywords []string
	patterns []*regexp.Regexp // word-boundary patterns for ambiguous terms
	severity int              // 0=safe, 1=mild, 2=mature, 3=adult, 4=blocked
}{
	"violence": {
		keywords: []string{"kill", "murder", "weapon", "gun", "knife", "attack",
			"fight", "bomb", "explode", "assault", "torture", "blood"},
		severity: 3,
	},
	"mild_conflict": {
		keywords: []string{"battle", "war", "conflict", "combat", "strategy",
			"military", "defense", "soldier"},
		severity: 1,
	},
	"drugs": {
		keywords: []string{"drug", "narcotic", "cocaine",
			"marijuana", "overdose", "substance abuse"},
		// word-boundary patterns for terms that appear as substrings in innocent words
		// e.g. "meth" in "something"/"methodology", "heroin" in "heroine"
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`\bmeth\b`),
			regexp.MustCompile(`\bheroin\b`),
		},
		severity: 3,
	},
	"adult_content": {
		keywords: []string{"explicit", "nsfw", "porn", "sexual", "erotic",
			"nude", "fetish"},
		severity: 4,
	},
	"security_tools": {
		keywords: []string{"exploit", "vulnerability", "hack", "injection",
			"brute force", "phishing", "malware", "ransomware", "backdoor",
			"rootkit", "keylogger"},
		severity: 2,
	},
	"security_educational": {
		keywords: []string{"security", "penetration test", "ctf", "defense",
			"firewall", "encryption", "authentication", "authorization"},
		severity: 1,
	},
	"illegal": {
		keywords: []string{"illegal", "fraud", "counterfeit", "launder",
			"trafficking", "steal", "theft"},
		severity: 4,
	},
	"medical": {
		keywords: []string{"surgery", "diagnosis", "prescription", "dosage",
			"symptom", "disease", "medication"},
		severity: 1,
	},
	"gambling": {
		keywords: []string{"gambling", "casino", "bet", "poker", "slot machine",
			"lottery"},
		severity: 2,
	},
}

// educational context markers - reduce severity
var educationalMarkers = []string{
	"explain", "how does", "what is", "learn", "teach", "understand",
	"example", "homework", "school", "university", "research", "study",
	"tutorial", "course", "lesson", "textbook",
}

// Classify analyzes prompt content and returns age rating using default policy.
func Classify(text string) Result {
	return ClassifyWithPolicy(text, config.DefaultPolicy())
}

// ClassifyWithPolicy analyzes prompt content applying the given policy.
func ClassifyWithPolicy(text string, policy *config.Policy) Result {
	if policy == nil {
		policy = config.DefaultPolicy()
	}

	// Fast path: check threat feed for previously seen patterns.
	if known, threatType := defaultFeed.IsKnownThreat(text); known {
		result := Result{
			Rating:  RatingBlock,
			Safe:    false,
			Flags:   []string{"known_threat:" + threatType},
			Score:   4,
			Details: "known threat pattern detected (threat feed match: " + threatType + ")",
		}
		result.SecurityScore = ComputeSecurityScore(text)
		return result
	}

	lower := strings.ToLower(text)
	result := Result{Safe: true}

	maxSeverity := 0
	isEducational := false

	// Check educational context
	for _, marker := range educationalMarkers {
		if strings.Contains(lower, marker) {
			isEducational = true
			break
		}
	}

	// Build allow/block sets from policy for O(1) lookup
	allowSet := make(map[string]bool, len(policy.Allow))
	for _, t := range policy.Allow {
		allowSet[strings.ToLower(t)] = true
	}
	blockSet := make(map[string]bool, len(policy.Block))
	for _, t := range policy.Block {
		blockSet[strings.ToLower(t)] = true
	}

	// Check built-in categories
	for category, cat := range categories {
		matched := false

		// Check plain keyword substrings
		for _, kw := range cat.keywords {
			if strings.Contains(lower, kw) {
				matched = true
				break
			}
		}

		// Check word-boundary regex patterns (used for terms prone to false positives)
		if !matched {
			for _, re := range cat.patterns {
				if re.MatchString(lower) {
					matched = true
					break
				}
			}
		}

		if matched {
			result.Flags = append(result.Flags, category)

			catKey := strings.ToLower(category)

			// Policy: always block this topic
			if blockSet[catKey] {
				if 4 > maxSeverity {
					maxSeverity = 4
				}
				continue
			}

			// Policy: explicitly allowed - skip severity contribution
			if allowSet[catKey] {
				continue
			}

			severity := cat.severity
			// Educational context reduces severity by 1
			if isEducational && severity > 0 {
				severity--
			}
			if severity > maxSeverity {
				maxSeverity = severity
			}
		}
	}

	// Apply custom rules from policy
	for _, rule := range policy.CustomRules {
		if rule.Pattern == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(rule.Pattern)) {
			switch strings.ToLower(rule.Action) {
			case "block":
				result.Flags = append(result.Flags, "custom:"+rule.Pattern)
				if 4 > maxSeverity {
					maxSeverity = 4
				}
				if rule.Reason != "" {
					result.Details = rule.Reason
				}
			case "allow":
				// custom allow: no severity added, but we do flag it
				result.Flags = append(result.Flags, "custom_allow:"+rule.Pattern)
			}
		}
	}

	// Check for social engineering patterns (always severity 4 / BLOCKED)
	if seDetail := detectSocialEngineering(lower, text); seDetail != "" {
		result.Flags = append(result.Flags, "social_engineering")
		if 4 > maxSeverity {
			maxSeverity = 4
		}
		result.Details = seDetail
	}

	// Check for prompt injection / jailbreak patterns (always severity 4 / BLOCKED)
	if piDetail := detectPromptInjection(lower, text); piDetail != "" {
		result.Flags = append(result.Flags, "prompt_injection")
		if 4 > maxSeverity {
			maxSeverity = 4
		}
		result.Details = piDetail
	}

	result.Score = maxSeverity
	result.SecurityScore = ComputeSecurityScore(text)

	switch {
	case maxSeverity >= 4:
		result.Rating = RatingBlock
		result.Safe = false
		if result.Details == "" {
			result.Details = "content policy violation detected"
		}
	case maxSeverity >= 3:
		result.Rating = Rating18Plus
		result.Safe = false
		result.Details = "adult content detected"
	case maxSeverity >= 2:
		result.Rating = Rating16Plus
		result.Safe = true
		result.Details = "mature themes detected"
	case maxSeverity >= 1:
		result.Rating = Rating12Plus
		result.Safe = true
		result.Details = "mild themes detected"
	default:
		result.Rating = Rating6Plus
		result.Safe = true
	}

	// Record detected threats to the feed for future fast-path lookups.
	if maxSeverity >= 2 {
		threatType := classifyThreatType(result.Flags)
		_ = defaultFeed.Record(text, threatType, 100-result.SecurityScore.Total)
	}

	return result
}

// classifyThreatType maps classifier flags to a threat.ThreatType.
func classifyThreatType(flags []string) threat.ThreatType {
	for _, flag := range flags {
		switch {
		case flag == "prompt_injection" || strings.HasPrefix(flag, "known_threat:injection"):
			return threat.ThreatTypeInjection
		case flag == "social_engineering" || strings.HasPrefix(flag, "known_threat:social_eng"):
			return threat.ThreatTypeSocialEng
		case flag == "adult_content" || flag == "illegal" || flag == "drugs" || flag == "violence":
			return threat.ThreatTypeContent
		}
	}
	// Default heuristic based on remaining flags.
	for _, flag := range flags {
		if strings.Contains(flag, "spam") {
			return threat.ThreatTypeSpam
		}
	}
	return threat.ThreatTypeContent
}

// IsSafe checks if prompt passes the given maximum rating threshold.
func IsSafe(text string, maxRating Rating) bool {
	return IsSafeWithPolicy(text, maxRating, config.DefaultPolicy())
}

// IsSafeWithPolicy checks if prompt passes threshold after applying policy.
func IsSafeWithPolicy(text string, maxRating Rating, policy *config.Policy) bool {
	result := ClassifyWithPolicy(text, policy)
	return ratingLevel(result.Rating) <= ratingLevel(maxRating)
}

func ratingLevel(r Rating) int {
	switch r {
	case Rating6Plus:
		return 0
	case Rating12Plus:
		return 1
	case Rating16Plus:
		return 2
	case Rating18Plus:
		return 3
	case RatingBlock:
		return 4
	default:
		return 0
	}
}
