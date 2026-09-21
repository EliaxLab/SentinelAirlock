package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EliaxLab/SentinelAirlock/internal/policy"
)

// helpers

func writeTempPolicy(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "airlock.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadPolicy(t *testing.T, path string) *policy.Config {
	t.Helper()
	cfg, err := policy.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return cfg
}

// simInput builds a strings.Reader from lines joined by newline.
func simInput(lines ...string) *strings.Reader {
	return strings.NewReader(strings.Join(lines, "\n") + "\n")
}

// ── containsRule ──────────────────────────────────────────────────────────────

func TestContainsRule_Present(t *testing.T) {
	if !containsRule([]string{"**/.env", "*.key"}, "**/.env") {
		t.Error("expected true")
	}
}

func TestContainsRule_Absent(t *testing.T) {
	if containsRule([]string{"*.key"}, "**/.env") {
		t.Error("expected false")
	}
}

func TestContainsRule_Empty(t *testing.T) {
	if containsRule(nil, "**/.env") {
		t.Error("expected false for nil slice")
	}
}

// ── yesOrDefault ─────────────────────────────────────────────────────────────

func TestYesOrDefault(t *testing.T) {
	for _, in := range []string{"", "y", "Y", "yes", "YES", "  Y  "} {
		if !yesOrDefault(in) {
			t.Errorf("expected true for %q", in)
		}
	}
	for _, in := range []string{"n", "N", "no", "NO"} {
		if yesOrDefault(in) {
			t.Errorf("expected false for %q", in)
		}
	}
}

// ── applyPolicyChanges ────────────────────────────────────────────────────────

func TestApplyPolicyChanges_AddsRules(t *testing.T) {
	cfg := &policy.Config{}
	applyPolicyChanges(cfg, []string{"**/.env", "**/*.key"}, "off")
	if !containsRule(cfg.Policy.DenyWrite, "**/.env") {
		t.Error("expected **/.env in deny_write")
	}
	if !containsRule(cfg.Policy.DenyWrite, "**/*.key") {
		t.Error("expected **/*.key in deny_write")
	}
}

func TestApplyPolicyChanges_NoDuplicates(t *testing.T) {
	cfg := &policy.Config{}
	cfg.Policy.DenyWrite = []string{"**/.env"}
	applyPolicyChanges(cfg, []string{"**/.env", "**/*.key"}, "off")
	count := 0
	for _, r := range cfg.Policy.DenyWrite {
		if r == "**/.env" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 copy of **/.env, got %d", count)
	}
}

func TestApplyPolicyChanges_PreservesExistingUnrelated(t *testing.T) {
	cfg := &policy.Config{}
	cfg.Policy.DenyWrite = []string{".git/**", ".airlock/**"}
	cfg.Policy.AllowWrite = []string{"src/**"}
	applyPolicyChanges(cfg, []string{"**/.env"}, "off")
	if !containsRule(cfg.Policy.DenyWrite, ".git/**") {
		t.Error("existing deny rule .git/** was removed")
	}
	if !containsRule(cfg.Policy.AllowWrite, "src/**") {
		t.Error("allow_write was modified")
	}
}

func TestApplyPolicyChanges_SetsNetworkMode(t *testing.T) {
	cfg := &policy.Config{}
	applyPolicyChanges(cfg, nil, "allowlist")
	if cfg.Network.Mode != "allowlist" {
		t.Errorf("expected network=allowlist, got %q", cfg.Network.Mode)
	}
}

// ── runPolicyConfigure — non-interactive ─────────────────────────────────────

func TestRunPolicyConfigure_NonInteractive(t *testing.T) {
	var out bytes.Buffer
	err := runPolicyConfigure("airlock.yaml", strings.NewReader(""), &out, false)
	if err == nil {
		t.Fatal("expected error for non-interactive terminal")
	}
	if !strings.Contains(out.String(), "requires a terminal") {
		t.Error("expected terminal-required message in output")
	}
}

// ── runPolicyConfigure — interactive ─────────────────────────────────────────

// Simulates: say yes to .env, no to everything else, no custom, network=1, confirm=y.
func TestRunPolicyConfigure_AddsEnvRule(t *testing.T) {
	dir := t.TempDir()
	path := writeTempPolicy(t, dir, "version: 1\n")

	// 6 presets: y, n, n, n, n, n — custom: blank — network: 1 — confirm: y
	in := simInput("y", "n", "n", "n", "n", "n", "", "1", "y")
	var out bytes.Buffer
	if err := runPolicyConfigure(path, in, &out, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := loadPolicy(t, path)
	if !containsRule(cfg.Policy.DenyWrite, "**/.env") {
		t.Error("expected **/.env in deny_write after configure")
	}
}

func TestRunPolicyConfigure_UserCancellation_NoWrite(t *testing.T) {
	dir := t.TempDir()
	path := writeTempPolicy(t, dir, "version: 1\n")
	before, _ := os.ReadFile(path)

	// say yes to .env, then cancel at confirmation
	in := simInput("y", "n", "n", "n", "n", "n", "", "1", "n")
	var out bytes.Buffer
	if err := runPolicyConfigure(path, in, &out, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("file was modified after user cancelled")
	}
	if !strings.Contains(out.String(), "Cancelled") {
		t.Error("expected cancellation message")
	}
}

func TestRunPolicyConfigure_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := writeTempPolicy(t, dir, "version: 1\npolicy:\n  deny_write:\n    - \"**/.env\"\n")

	// All 6 presets: .env already present (skipped), say yes to rest
	// .env is skipped → only 5 prompts for presets
	in := simInput("y", "y", "y", "y", "y", "", "1", "y")
	var out bytes.Buffer
	if err := runPolicyConfigure(path, in, &out, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := loadPolicy(t, path)
	count := 0
	for _, r := range cfg.Policy.DenyWrite {
		if r == "**/.env" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 **/.env after idempotent run, got %d", count)
	}
}

func TestRunPolicyConfigure_CustomPath(t *testing.T) {
	dir := t.TempDir()
	path := writeTempPolicy(t, dir, "version: 1\n")

	// say no to all presets, add custom path, confirm
	in := simInput("n", "n", "n", "n", "n", "n", "**/private/**", "1", "y")
	var out bytes.Buffer
	if err := runPolicyConfigure(path, in, &out, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := loadPolicy(t, path)
	if !containsRule(cfg.Policy.DenyWrite, "**/private/**") {
		t.Error("expected **/private/** in deny_write")
	}
}

func TestRunPolicyConfigure_PreservesUnrelatedConfig(t *testing.T) {
	dir := t.TempDir()
	yaml := "version: 1\npolicy:\n  allow_write:\n    - \"src/**\"\n  deny_write: []\nnetwork:\n  mode: \"off\"\n"
	path := writeTempPolicy(t, dir, yaml)

	// add .env, confirm
	in := simInput("y", "n", "n", "n", "n", "n", "", "1", "y")
	var out bytes.Buffer
	if err := runPolicyConfigure(path, in, &out, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := loadPolicy(t, path)
	if !containsRule(cfg.Policy.AllowWrite, "src/**") {
		t.Error("allow_write was clobbered")
	}
	if !containsRule(cfg.Policy.DenyWrite, "**/.env") {
		t.Error("expected **/.env in deny_write")
	}
}

func TestRunPolicyConfigure_MalformedYAML_NoOverwrite(t *testing.T) {
	dir := t.TempDir()
	bad := "version: 1\npolicy:\n  deny_write: [unclosed"
	path := writeTempPolicy(t, dir, bad)

	var out bytes.Buffer
	err := runPolicyConfigure(path, strings.NewReader(""), &out, true)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}

	// File must be unchanged
	content, _ := os.ReadFile(path)
	if string(content) != bad {
		t.Error("malformed file was overwritten on error")
	}
}

func TestRunPolicyConfigure_NoChanges_NoWrite(t *testing.T) {
	dir := t.TempDir()
	// All preset rules already present — write via writeConfig so quoting is correct.
	cfg := &policy.Config{}
	cfg.Policy.DenyWrite = append([]string(nil), presetDenyPaths...)
	cfg.Network.Mode = "off"
	path := filepath.Join(dir, "airlock.yaml")
	if err := writeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	// All prompts skipped (already configured), blank custom, network same
	in := simInput("", "1")
	var out bytes.Buffer
	if err := runPolicyConfigure(path, in, &out, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("file changed when there were no new rules to add")
	}
	if !strings.Contains(out.String(), "No changes") {
		t.Error("expected no-changes message")
	}
}
