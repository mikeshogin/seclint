// Package config provides parsing for .seclint.yaml policy files.
// Uses stdlib only - parses a minimal YAML subset by hand.
package config

import (
	"bufio"
	"os"
	"path/filepath"
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

	// Extends is an optional path to a parent policy file.
	// Supports "~/" prefix for home directory expansion.
	// Special value "global" resolves to ~/.seclint.yaml.
	Extends string
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

// globalPolicyPath returns the path to the user-wide policy file (~/.seclint.yaml).
func globalPolicyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".seclint.yaml")
}

// LoadGlobal loads the user-wide policy from ~/.seclint.yaml.
// Returns DefaultPolicy if the file does not exist.
func LoadGlobal() (*Policy, error) {
	path := globalPolicyPath()
	if path == "" {
		return DefaultPolicy(), nil
	}
	return Load(path)
}

// MergeInto merges parent into child using inheritance rules:
//   - Child Rating takes precedence; if empty, parent Rating is used.
//   - Block lists are combined (union).
//   - Allow lists are combined (union).
//   - CustomRules are combined (child rules appended after parent rules).
func MergeInto(child, parent *Policy) *Policy {
	if parent == nil {
		return child
	}
	if child == nil {
		return parent
	}

	merged := &Policy{
		Rating:  child.Rating,
		Extends: child.Extends,
	}

	// Rating: child wins; fall back to parent if child didn't set one.
	if merged.Rating == "" {
		merged.Rating = parent.Rating
	}
	if merged.Rating == "" {
		merged.Rating = "16+"
	}

	// Block: union of parent + child (deduplicated).
	merged.Block = mergeStringSlice(parent.Block, child.Block)

	// Allow: union of parent + child (deduplicated).
	merged.Allow = mergeStringSlice(parent.Allow, child.Allow)

	// CustomRules: parent rules first, then child rules (child can override by pattern).
	merged.CustomRules = mergeCustomRules(parent.CustomRules, child.CustomRules)

	return merged
}

// mergeStringSlice returns a deduplicated union of a and b, preserving order.
func mergeStringSlice(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	result := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		k := strings.ToLower(v)
		if !seen[k] {
			seen[k] = true
			result = append(result, v)
		}
	}
	for _, v := range b {
		k := strings.ToLower(v)
		if !seen[k] {
			seen[k] = true
			result = append(result, v)
		}
	}
	return result
}

// mergeCustomRules merges parent and child custom rule lists.
// Child rules with the same pattern as a parent rule override the parent rule.
// Other parent rules are kept first; new child rules are appended.
func mergeCustomRules(parent, child []CustomRule) []CustomRule {
	// Index child rules by pattern for quick lookup.
	childByPattern := make(map[string]CustomRule, len(child))
	for _, r := range child {
		if r.Pattern != "" {
			childByPattern[strings.ToLower(r.Pattern)] = r
		}
	}

	result := make([]CustomRule, 0, len(parent)+len(child))

	// Add parent rules, replaced by child if same pattern.
	parentPatterns := make(map[string]bool, len(parent))
	for _, r := range parent {
		k := strings.ToLower(r.Pattern)
		parentPatterns[k] = true
		if override, ok := childByPattern[k]; ok {
			result = append(result, override)
		} else {
			result = append(result, r)
		}
	}

	// Append child rules that don't exist in parent.
	for _, r := range child {
		k := strings.ToLower(r.Pattern)
		if !parentPatterns[k] {
			result = append(result, r)
		}
	}

	return result
}

// resolveExtendsPath resolves the value of an `extends:` field to an absolute file path.
// Supports:
//   - "global"            -> ~/.seclint.yaml
//   - "~/path/to/file"   -> expanded home path
//   - "/absolute/path"   -> used as-is
//   - "relative/path"    -> resolved relative to baseDir
func resolveExtendsPath(extends, baseDir string) string {
	if extends == "global" {
		return globalPolicyPath()
	}
	if strings.HasPrefix(extends, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, extends[2:])
	}
	if filepath.IsAbs(extends) {
		return extends
	}
	return filepath.Join(baseDir, extends)
}

// LoadWithInheritance loads a policy from dir and resolves inheritance.
//
// Inheritance order (lowest to highest priority):
//  1. ~/.seclint.yaml  (global defaults, always applied unless suppressed)
//  2. explicit `extends:` file referenced in the project policy
//  3. project-local .seclint.yaml (highest priority)
//
// If no project-local policy exists the global policy is returned as-is.
// If the project policy has `extends:` set, that file is loaded and merged
// before the global policy is applied (i.e. extends > global, project > extends).
//
// To disable global policy inheritance entirely, set `extends: none` in the
// project policy.
func LoadWithInheritance(dir string) (*Policy, error) {
	localPath := filepath.Join(dir, ".seclint.yaml")

	// Check whether a local policy file exists.
	_, statErr := os.Stat(localPath)
	localExists := statErr == nil

	// If no local policy, return global policy directly.
	if !localExists {
		return LoadGlobal()
	}

	// Load the project-local policy.
	local, err := Load(localPath)
	if err != nil {
		return nil, err
	}

	// `extends: none` disables all inheritance.
	if strings.ToLower(local.Extends) == "none" {
		local.Extends = ""
		return local, nil
	}

	// Resolve the parent policy.
	var parent *Policy

	if local.Extends != "" {
		// Explicit extends: load that file.
		parentPath := resolveExtendsPath(local.Extends, dir)
		if parentPath == "" {
			// Can't resolve path; fall back to global.
			parent, err = LoadGlobal()
		} else {
			parent, err = Load(parentPath)
		}
		if err != nil {
			return nil, err
		}
	} else {
		// No explicit extends: use global as parent.
		parent, err = LoadGlobal()
		if err != nil {
			return nil, err
		}
	}

	// Merge: parent provides defaults, local overrides.
	return MergeInto(local, parent), nil
}

// parse reads a minimal YAML file with the expected structure.
// Supported constructs:
//
//	rating: "12+"
//	extends: global
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
	p.Rating = "" // reset so we can detect whether it was explicitly set

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
			case "extends":
				p.Extends = unquote(val)
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

	// If rating was not explicitly set in the file, use default.
	if p.Rating == "" {
		p.Rating = "16+"
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
