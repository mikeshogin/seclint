package classifier

import (
	"regexp"
	"strings"

	"github.com/mikeshogin/seclint/pkg/config"
)

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
	Rating  Rating   `json:"rating"`
	Safe    bool     `json:"safe"`
	Flags   []string `json:"flags,omitempty"`
	Score   int      `json:"score"`
	Details string   `json:"details,omitempty"`
}

// category word lists - severity levels
var categories = map[string]struct {
	keywords []string
	severity int // 0=safe, 1=mild, 2=mature, 3=adult, 4=blocked
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
		keywords: []string{"drug", "narcotic", "cocaine", "heroin", "meth",
			"marijuana", "overdose", "substance abuse"},
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
		for _, kw := range cat.keywords {
			if strings.Contains(lower, kw) {
				result.Flags = append(result.Flags, category)

				catKey := strings.ToLower(category)

				// Policy: always block this topic
				if blockSet[catKey] {
					if 4 > maxSeverity {
						maxSeverity = 4
					}
					break
				}

				// Policy: explicitly allowed - skip severity contribution
				if allowSet[catKey] {
					break
				}

				severity := cat.severity
				// Educational context reduces severity by 1
				if isEducational && severity > 0 {
					severity--
				}
				if severity > maxSeverity {
					maxSeverity = severity
				}
				break // one match per category is enough
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

	result.Score = maxSeverity

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

	return result
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
