package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempPolicy writes content to a temp dir as .seclint.yaml and returns the dir path.
func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".seclint.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}
	return dir
}

// writePolicyFile writes content to a named file in dir and returns the full path.
func writePolicyFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy file %s: %v", name, err)
	}
	return path
}

// --------------------------------------------------------------------------
// Parse tests
// --------------------------------------------------------------------------

func TestParse_RatingExplicit(t *testing.T) {
	dir := writeTempPolicy(t, `rating: "12+"`)
	p, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Rating != "12+" {
		t.Errorf("expected rating 12+, got %s", p.Rating)
	}
}

func TestParse_ExtendsField(t *testing.T) {
	dir := writeTempPolicy(t, `
rating: "18+"
extends: global
`)
	p, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Extends != "global" {
		t.Errorf("expected extends=global, got %q", p.Extends)
	}
	if p.Rating != "18+" {
		t.Errorf("expected rating 18+, got %s", p.Rating)
	}
}

func TestParse_NoFile_DefaultPolicy(t *testing.T) {
	p, err := LoadFromDir(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Rating != "16+" {
		t.Errorf("expected default rating 16+, got %s", p.Rating)
	}
	if len(p.Block) != 0 || len(p.Allow) != 0 || len(p.CustomRules) != 0 {
		t.Errorf("expected empty policy, got %+v", p)
	}
}

func TestParse_BlockAllowLists(t *testing.T) {
	dir := writeTempPolicy(t, `
block:
  - adult_content
  - illegal
allow:
  - medical
`)
	p, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Block) != 2 || p.Block[0] != "adult_content" || p.Block[1] != "illegal" {
		t.Errorf("unexpected block list: %v", p.Block)
	}
	if len(p.Allow) != 1 || p.Allow[0] != "medical" {
		t.Errorf("unexpected allow list: %v", p.Allow)
	}
}

func TestParse_CustomRules(t *testing.T) {
	dir := writeTempPolicy(t, `
custom_rules:
  - pattern: invest money
    action: block
    reason: financial advice
  - pattern: safe topic
    action: allow
`)
	p, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.CustomRules) != 2 {
		t.Fatalf("expected 2 custom rules, got %d: %+v", len(p.CustomRules), p.CustomRules)
	}
	if p.CustomRules[0].Pattern != "invest money" || p.CustomRules[0].Action != "block" {
		t.Errorf("unexpected first rule: %+v", p.CustomRules[0])
	}
	if p.CustomRules[1].Pattern != "safe topic" || p.CustomRules[1].Action != "allow" {
		t.Errorf("unexpected second rule: %+v", p.CustomRules[1])
	}
}

// --------------------------------------------------------------------------
// MergeInto tests
// --------------------------------------------------------------------------

func TestMergeInto_RatingChildWins(t *testing.T) {
	parent := &Policy{Rating: "16+"}
	child := &Policy{Rating: "12+"}
	merged := MergeInto(child, parent)
	if merged.Rating != "12+" {
		t.Errorf("expected child rating 12+, got %s", merged.Rating)
	}
}

func TestMergeInto_RatingFallbackToParent(t *testing.T) {
	parent := &Policy{Rating: "18+"}
	child := &Policy{Rating: ""}
	merged := MergeInto(child, parent)
	if merged.Rating != "18+" {
		t.Errorf("expected parent rating 18+, got %s", merged.Rating)
	}
}

func TestMergeInto_BlockUnion(t *testing.T) {
	parent := &Policy{Rating: "16+", Block: []string{"adult_content", "illegal"}}
	child := &Policy{Rating: "16+", Block: []string{"gambling"}}
	merged := MergeInto(child, parent)

	want := map[string]bool{"adult_content": true, "illegal": true, "gambling": true}
	if len(merged.Block) != 3 {
		t.Errorf("expected 3 block entries, got %v", merged.Block)
	}
	for _, b := range merged.Block {
		if !want[b] {
			t.Errorf("unexpected block entry: %s", b)
		}
	}
}

func TestMergeInto_BlockDeduplication(t *testing.T) {
	parent := &Policy{Rating: "16+", Block: []string{"adult_content"}}
	child := &Policy{Rating: "16+", Block: []string{"adult_content", "gambling"}}
	merged := MergeInto(child, parent)
	if len(merged.Block) != 2 {
		t.Errorf("expected 2 block entries after dedup, got %v", merged.Block)
	}
}

func TestMergeInto_AllowUnion(t *testing.T) {
	parent := &Policy{Rating: "16+", Allow: []string{"medical"}}
	child := &Policy{Rating: "16+", Allow: []string{"security_educational"}}
	merged := MergeInto(child, parent)
	if len(merged.Allow) != 2 {
		t.Errorf("expected 2 allow entries, got %v", merged.Allow)
	}
}

func TestMergeInto_CustomRulesParentFirst(t *testing.T) {
	parent := &Policy{
		Rating: "16+",
		CustomRules: []CustomRule{
			{Pattern: "invest money", Action: "block", Reason: "financial"},
		},
	}
	child := &Policy{
		Rating: "16+",
		CustomRules: []CustomRule{
			{Pattern: "new pattern", Action: "block", Reason: "new"},
		},
	}
	merged := MergeInto(child, parent)
	if len(merged.CustomRules) != 2 {
		t.Fatalf("expected 2 custom rules, got %d: %+v", len(merged.CustomRules), merged.CustomRules)
	}
	// Parent rule first
	if merged.CustomRules[0].Pattern != "invest money" {
		t.Errorf("expected parent rule first, got %+v", merged.CustomRules[0])
	}
	// Child rule appended
	if merged.CustomRules[1].Pattern != "new pattern" {
		t.Errorf("expected child rule second, got %+v", merged.CustomRules[1])
	}
}

func TestMergeInto_CustomRulesChildOverridesParent(t *testing.T) {
	parent := &Policy{
		Rating: "16+",
		CustomRules: []CustomRule{
			{Pattern: "invest money", Action: "block", Reason: "financial"},
		},
	}
	child := &Policy{
		Rating: "16+",
		CustomRules: []CustomRule{
			{Pattern: "invest money", Action: "allow", Reason: "overridden"},
		},
	}
	merged := MergeInto(child, parent)
	if len(merged.CustomRules) != 1 {
		t.Fatalf("expected 1 merged rule, got %d: %+v", len(merged.CustomRules), merged.CustomRules)
	}
	if merged.CustomRules[0].Action != "allow" {
		t.Errorf("expected child override (allow), got %s", merged.CustomRules[0].Action)
	}
	if merged.CustomRules[0].Reason != "overridden" {
		t.Errorf("expected reason=overridden, got %s", merged.CustomRules[0].Reason)
	}
}

func TestMergeInto_NilParent(t *testing.T) {
	child := &Policy{Rating: "12+", Block: []string{"gambling"}}
	merged := MergeInto(child, nil)
	if merged.Rating != "12+" {
		t.Errorf("expected 12+, got %s", merged.Rating)
	}
	if len(merged.Block) != 1 {
		t.Errorf("expected 1 block entry, got %v", merged.Block)
	}
}

func TestMergeInto_NilChild(t *testing.T) {
	parent := &Policy{Rating: "18+", Block: []string{"adult_content"}}
	merged := MergeInto(nil, parent)
	if merged.Rating != "18+" {
		t.Errorf("expected 18+, got %s", merged.Rating)
	}
}

// --------------------------------------------------------------------------
// LoadWithInheritance tests
// --------------------------------------------------------------------------

func TestLoadWithInheritance_NoLocalNoGlobal(t *testing.T) {
	// Neither local nor global policy; use default.
	// Override global path by running from a temp dir where ~ doesn't have one.
	// We can't easily mock home dir, so just verify that an empty dir returns a valid policy.
	dir := t.TempDir()
	p, err := LoadWithInheritance(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
	if p.Rating == "" {
		t.Error("expected non-empty rating from default/global policy")
	}
}

func TestLoadWithInheritance_LocalOnlyNoGlobal(t *testing.T) {
	// Local policy exists; global doesn't (we use a temp dir trick via explicit extends: none).
	dir := writeTempPolicy(t, `
rating: "12+"
extends: none
block:
  - gambling
`)
	p, err := LoadWithInheritance(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Rating != "12+" {
		t.Errorf("expected 12+, got %s", p.Rating)
	}
	if len(p.Block) != 1 || p.Block[0] != "gambling" {
		t.Errorf("unexpected block: %v", p.Block)
	}
}

func TestLoadWithInheritance_ExtendsNone_NoInheritance(t *testing.T) {
	// extends: none should prevent any inheritance including global.
	dir := writeTempPolicy(t, `
rating: "18+"
extends: none
block:
  - adult_content
`)
	p, err := LoadWithInheritance(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Rating != "18+" {
		t.Errorf("expected 18+, got %s", p.Rating)
	}
	// Should not have inherited any extra blocks.
	if len(p.Block) != 1 {
		t.Errorf("expected exactly 1 block entry, got %v", p.Block)
	}
}

func TestLoadWithInheritance_ExplicitExtendsFile(t *testing.T) {
	// Create a parent policy file and a child that references it.
	dir := t.TempDir()

	parentContent := `
rating: "16+"
block:
  - illegal
  - adult_content
custom_rules:
  - pattern: invest money
    action: block
    reason: financial
`
	parentPath := writePolicyFile(t, dir, "parent.yaml", parentContent)

	childContent := `rating: "12+"
extends: ` + parentPath + `
block:
  - gambling
allow:
  - medical
custom_rules:
  - pattern: invest money
    action: allow
    reason: overridden by project
`
	if err := os.WriteFile(filepath.Join(dir, ".seclint.yaml"), []byte(childContent), 0644); err != nil {
		t.Fatalf("failed to write child policy: %v", err)
	}

	p, err := LoadWithInheritance(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Child rating wins.
	if p.Rating != "12+" {
		t.Errorf("expected 12+, got %s", p.Rating)
	}

	// Block: union of parent [illegal, adult_content] + child [gambling] = 3 entries.
	wantBlock := map[string]bool{"illegal": true, "adult_content": true, "gambling": true}
	if len(p.Block) != 3 {
		t.Errorf("expected 3 block entries, got %v", p.Block)
	}
	for _, b := range p.Block {
		if !wantBlock[b] {
			t.Errorf("unexpected block entry: %s", b)
		}
	}

	// Allow: union of parent [] + child [medical] = 1.
	if len(p.Allow) != 1 || p.Allow[0] != "medical" {
		t.Errorf("unexpected allow list: %v", p.Allow)
	}

	// CustomRules: child overrides parent's "invest money" rule.
	if len(p.CustomRules) != 1 {
		t.Fatalf("expected 1 custom rule (overridden), got %d: %+v", len(p.CustomRules), p.CustomRules)
	}
	if p.CustomRules[0].Action != "allow" {
		t.Errorf("expected action=allow (child override), got %s", p.CustomRules[0].Action)
	}
}

func TestLoadWithInheritance_RelativeExtendsPath(t *testing.T) {
	dir := t.TempDir()

	parentContent := `
rating: "18+"
block:
  - adult_content
`
	writePolicyFile(t, dir, "org-policy.yaml", parentContent)

	childContent := "rating: \"12+\"\nextends: org-policy.yaml\n"
	if err := os.WriteFile(filepath.Join(dir, ".seclint.yaml"), []byte(childContent), 0644); err != nil {
		t.Fatalf("failed to write child policy: %v", err)
	}

	p, err := LoadWithInheritance(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.Rating != "12+" {
		t.Errorf("expected 12+ (child wins), got %s", p.Rating)
	}
	if len(p.Block) != 1 || p.Block[0] != "adult_content" {
		t.Errorf("expected adult_content inherited from parent, got %v", p.Block)
	}
}

func TestLoadWithInheritance_MultiLevel_ExplicitThenGlobal(t *testing.T) {
	// child extends org -> org has its own content -> both merge correctly.
	dir := t.TempDir()

	orgContent := `
rating: "16+"
extends: none
block:
  - illegal
allow:
  - security_educational
`
	writePolicyFile(t, dir, "org.yaml", orgContent)

	projectContent := "rating: \"12+\"\nextends: org.yaml\nblock:\n  - gambling\n"
	if err := os.WriteFile(filepath.Join(dir, ".seclint.yaml"), []byte(projectContent), 0644); err != nil {
		t.Fatalf("failed to write project policy: %v", err)
	}

	p, err := LoadWithInheritance(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.Rating != "12+" {
		t.Errorf("expected 12+, got %s", p.Rating)
	}

	wantBlock := map[string]bool{"illegal": true, "gambling": true}
	if len(p.Block) != 2 {
		t.Errorf("expected 2 block entries, got %v", p.Block)
	}
	for _, b := range p.Block {
		if !wantBlock[b] {
			t.Errorf("unexpected block entry: %s", b)
		}
	}

	if len(p.Allow) != 1 || p.Allow[0] != "security_educational" {
		t.Errorf("expected security_educational in allow, got %v", p.Allow)
	}
}

// --------------------------------------------------------------------------
// resolveExtendsPath tests
// --------------------------------------------------------------------------

func TestResolveExtendsPath_Global(t *testing.T) {
	path := resolveExtendsPath("global", "/some/dir")
	if path == "" {
		t.Skip("home dir not available in this environment")
	}
	if filepath.Base(path) != ".seclint.yaml" {
		t.Errorf("expected ~/.seclint.yaml, got %s", path)
	}
}

func TestResolveExtendsPath_Absolute(t *testing.T) {
	path := resolveExtendsPath("/etc/seclint/policy.yaml", "/irrelevant")
	if path != "/etc/seclint/policy.yaml" {
		t.Errorf("expected absolute path unchanged, got %s", path)
	}
}

func TestResolveExtendsPath_Relative(t *testing.T) {
	path := resolveExtendsPath("policies/org.yaml", "/project")
	want := "/project/policies/org.yaml"
	if path != want {
		t.Errorf("expected %s, got %s", want, path)
	}
}

// --------------------------------------------------------------------------
// mergeStringSlice / mergeCustomRules helpers
// --------------------------------------------------------------------------

func TestMergeStringSlice_Empty(t *testing.T) {
	result := mergeStringSlice(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %v", result)
	}
}

func TestMergeStringSlice_Dedup(t *testing.T) {
	result := mergeStringSlice([]string{"a", "b"}, []string{"b", "c"})
	if len(result) != 3 {
		t.Errorf("expected 3 (deduped), got %v", result)
	}
}

func TestMergeStringSlice_CaseInsensitiveDedup(t *testing.T) {
	result := mergeStringSlice([]string{"Adult_Content"}, []string{"adult_content"})
	if len(result) != 1 {
		t.Errorf("expected 1 (case-insensitive dedup), got %v", result)
	}
}
