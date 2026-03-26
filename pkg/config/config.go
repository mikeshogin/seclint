// Package config provides parsing for .seclint.yaml policy files.
// Uses stdlib only - parses a minimal YAML subset by hand.
package config

import (
	"bufio"
	"os"
	"strings"
)

// CustomRule defines a keyword pattern with an action.
type CustomRule struct {
	Pattern string // regex-free substring/prefix pattern
	Action  string // "block" or "allow"
	Reason  string
}

// Policy holds the parsed content of a .seclint.yaml file.
type Policy struct {
	// Rating is the default threshold: "6+", "12+", "16+", "18+"
	Rating string

	// Block lists topic names that are always blocked regardless of rating.
	Block []string

	// Allow lists topic names that are allowed despite their normal rating.
	Allow []string

	// CustomRules are additional keyword rules.
	CustomRules []CustomRule
}

// DefaultPolicy returns a policy with sensible defaults (no overrides).
func DefaultPolicy() *Policy {
	return &Policy{Rating: "16+"}
}

// Load reads a .seclint.yaml file and returns a Policy.
// Returns DefaultPolicy if the file does not exist.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return nil, err
	}
	defer f.Close()

	return parse(f)
}

// LoadFromDir looks for .seclint.yaml in the given directory.
// Returns DefaultPolicy if the file does not exist.
func LoadFromDir(dir string) (*Policy, error) {
	path := dir + "/.seclint.yaml"
	return Load(path)
}

// parse reads a minimal YAML file with the expected structure.
// Supported constructs:
//
//	rating: "12+"
//	block:
//	  - financial_advice
//	allow:
//	  - medical_terms
//	custom_rules:
//	  - pattern: "invest.*money"
//	    action: block
//	    reason: "financial advice"
func parse(f *os.File) (*Policy, error) {
	p := DefaultPolicy()

	type parseState int
	const (
		stateRoot parseState = iota
		stateBlock
		stateAllow
		stateCustomRules
		stateCustomRuleItem
	)

	state := stateRoot
	var currentRule *CustomRule

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimRight(raw, " \t\r")

		// skip comments and empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := leadingSpaces(line)

		// top-level key detected (no indent)
		if indent == 0 {
			// flush pending custom rule
			if currentRule != nil {
				p.CustomRules = append(p.CustomRules, *currentRule)
				currentRule = nil
			}

			key, val := splitKeyValue(trimmed)
			switch key {
			case "rating":
				p.Rating = unquote(val)
				state = stateRoot
			case "block":
				state = stateBlock
			case "allow":
				state = stateAllow
			case "custom_rules":
				state = stateCustomRules
			default:
				state = stateRoot
			}
			continue
		}

		// list item at indent 2 (- value)
		if indent >= 2 && strings.HasPrefix(trimmed, "- ") {
			itemVal := strings.TrimPrefix(trimmed, "- ")

			switch state {
			case stateBlock:
				p.Block = append(p.Block, unquote(itemVal))

			case stateAllow:
				p.Allow = append(p.Allow, unquote(itemVal))

			case stateCustomRules:
				// flush previous rule
				if currentRule != nil {
					p.CustomRules = append(p.CustomRules, *currentRule)
				}
				// start a new rule; the "- " may be followed by "key: val"
				currentRule = &CustomRule{}
				state = stateCustomRuleItem
				key, val := splitKeyValue(itemVal)
				applyRuleField(currentRule, key, val)

			case stateCustomRuleItem:
				// another list item -> new rule
				if currentRule != nil {
					p.CustomRules = append(p.CustomRules, *currentRule)
				}
				currentRule = &CustomRule{}
				key, val := splitKeyValue(itemVal)
				applyRuleField(currentRule, key, val)
			}
			continue
		}

		// continuation key: val inside a custom_rule item (indent >= 4)
		if indent >= 4 && state == stateCustomRuleItem && currentRule != nil {
			key, val := splitKeyValue(trimmed)
			applyRuleField(currentRule, key, val)
		}
	}

	// flush last custom rule
	if currentRule != nil {
		p.CustomRules = append(p.CustomRules, *currentRule)
	}

	return p, scanner.Err()
}

func applyRuleField(r *CustomRule, key, val string) {
	switch key {
	case "pattern":
		r.Pattern = unquote(val)
	case "action":
		r.Action = unquote(val)
	case "reason":
		r.Reason = unquote(val)
	}
}

// splitKeyValue splits "key: value" -> ("key", "value").
// Returns ("", "") if the line has no colon.
func splitKeyValue(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return s, ""
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:])
}

// unquote strips surrounding double or single quotes from a YAML scalar.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// leadingSpaces counts leading space/tab characters (tabs count as 1).
func leadingSpaces(s string) int {
	count := 0
	for _, ch := range s {
		if ch == ' ' || ch == '\t' {
			count++
		} else {
			break
		}
	}
	return count
}
