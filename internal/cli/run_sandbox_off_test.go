package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EliaxLab/SentinelAirlock/internal/execution"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

// chdirTempRepo creates a temp dir, chdirs into it, writes a policy allowing
// allow.txt/status.txt and denying .env/secrets/**, and returns the dir. Tests
// invoke `airlock run --repo .` from inside it, matching the manual
// acceptance-test flow (cd into the target repo first).
func chdirTempRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	policy := `version: 1
policy:
  deny_write:
    - "**/.env"
    - "secrets/**"
  allow_write:
    - "allow.txt"
    - "status.txt"
    - "config.txt"
network:
  mode: "off"
`
	if err := os.WriteFile(filepath.Join(dir, "airlock.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runAirlock(t *testing.T, args ...string) error {
	t.Helper()
	cmd := runCmd()
	cmd.SetArgs(args)
	return cmd.Execute()
}

func latestManifest(t *testing.T, dir string) runmeta.RunManifest {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, ".airlock", "runs"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no runs found under .airlock/runs: %v", err)
	}
	// Only one run per test in this suite, so any entry is "the" run.
	runID := entries[0].Name()
	m, err := runmeta.Load(filepath.Join(dir, ".airlock", "runs", runID, "run_manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return m
}

// --- 3/4: sandbox=off executes in the actual resolved --repo ----------------

func TestRun_SandboxOff_ExecutesInRealRepo(t *testing.T) {
	dir := chdirTempRepo(t)

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", ".", "--sandbox", "off",
		"--cmd", `printf "hello\n" > allow.txt`); err != nil {
		t.Fatalf("run: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "allow.txt"))
	if err != nil {
		t.Fatalf("expected allow.txt in the real repo: %v", err)
	}
	if string(content) != "hello\n" {
		t.Errorf("unexpected content: %q", content)
	}
}

// --- 6: the write must NOT appear only in a staged .airlock/workspaces copy -

func TestRun_SandboxOff_NoStagedWorkspaceCreated(t *testing.T) {
	dir := chdirTempRepo(t)

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", ".", "--sandbox", "off",
		"--cmd", `printf "hello\n" > allow.txt`); err != nil {
		t.Fatalf("run: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".airlock", "workspaces")); !os.IsNotExist(err) {
		t.Errorf("expected no .airlock/workspaces directory for sandbox=off, stat err=%v", err)
	}
}

// --- 1/14: sandbox=workspace regression — must still stage a copy -----------

func TestRun_SandboxWorkspace_StillStagesCopy_NotRealRepo(t *testing.T) {
	dir := chdirTempRepo(t)

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", ".", "--sandbox", "workspace",
		"--cmd", `printf "hello\n" > allow.txt`); err != nil {
		t.Fatalf("run: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "allow.txt")); !os.IsNotExist(err) {
		t.Errorf("workspace mode must NOT write into the real repo, stat err=%v", err)
	}
	m := latestManifest(t, dir)
	staged := filepath.Join(m.WorkspacePath, "allow.txt")
	if _, err := os.Stat(staged); err != nil {
		t.Errorf("expected allow.txt in staged workspace %s: %v", staged, err)
	}
}

// --- 5/8: allowed write survives; denied write reverts with existing semantics

func TestRun_SandboxOff_AllowedSurvives_DeniedReverts(t *testing.T) {
	dir := chdirTempRepo(t)
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", ".", "--sandbox", "off",
		"--cmd", `printf "hi\n" > status.txt && printf "SECRET\n" > .env && printf "tok\n" > secrets/token.txt`); err != nil {
		t.Fatalf("run: %v", err)
	}

	if content, err := os.ReadFile(filepath.Join(dir, "status.txt")); err != nil || string(content) != "hi\n" {
		t.Errorf("status.txt should survive in the real repo, err=%v content=%q", err, content)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Errorf("denied .env write must not survive, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "token.txt")); !os.IsNotExist(err) {
		t.Errorf("denied secrets/token.txt write must not survive, stat err=%v", err)
	}
}

// --- 7/11: mutation evidence uses correct repo-relative paths, no .airlock --

func TestRun_SandboxOff_EvidenceUsesRepoRelativePaths_NoAirlockPollution(t *testing.T) {
	dir := chdirTempRepo(t)

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", ".", "--sandbox", "off",
		"--cmd", `printf "hi\n" > status.txt && printf "SECRET\n" > .env`); err != nil {
		t.Fatalf("run: %v", err)
	}

	m := latestManifest(t, dir)
	wantTouched := map[string]bool{"status.txt": false, ".env": false}
	for _, p := range m.TouchedPaths {
		if p == ".airlock" || len(p) >= 9 && p[:9] == ".airlock/" {
			t.Errorf("touched paths must not include Airlock's own metadata, got %q", p)
		}
		if _, ok := wantTouched[p]; ok {
			wantTouched[p] = true
		}
	}
	for p, seen := range wantTouched {
		if !seen {
			t.Errorf("expected %q in touched paths, got %v", p, m.TouchedPaths)
		}
	}
	found := false
	for _, p := range m.DeniedPaths {
		if p == ".env" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected .env in denied paths, got %v", m.DeniedPaths)
	}
}

// --- 9: checkpoint is captured before in-place mutations ---------------------

func TestRun_SandboxOff_CheckpointCapturedBeforeMutation(t *testing.T) {
	dir := chdirTempRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte("pre-run"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", ".", "--sandbox", "off",
		"--cmd", `printf "post-run\n" > config.txt`); err != nil {
		t.Fatalf("run: %v", err)
	}

	m := latestManifest(t, dir)
	if len(m.Checkpoints) == 0 {
		t.Fatal("expected at least one checkpoint")
	}
	cpFile := filepath.Join(m.Checkpoints[0].Path, "config.txt")
	content, err := os.ReadFile(cpFile)
	if err != nil {
		t.Fatalf("checkpoint should contain config.txt: %v", err)
	}
	if string(content) != "pre-run" {
		t.Errorf("checkpoint must capture PRE-run content, got %q", content)
	}
	// Real repo reflects the post-run mutation.
	postContent, err := os.ReadFile(filepath.Join(dir, "config.txt"))
	if err != nil || string(postContent) != "post-run\n" {
		t.Errorf("real repo should reflect the post-run write, got %q err=%v", postContent, err)
	}
}

// --- 12: relative --repo . and absolute --repo /path behave equivalently ----

func TestRun_SandboxOff_RelativeAndAbsoluteRepoEquivalent(t *testing.T) {
	dir := chdirTempRepo(t)

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", dir, "--sandbox", "off",
		"--cmd", `printf "hello\n" > allow.txt`); err != nil {
		t.Fatalf("run with absolute --repo: %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(dir, "allow.txt")); err != nil || string(content) != "hello\n" {
		t.Errorf("absolute --repo should write into the real repo, err=%v content=%q", err, content)
	}
	m := latestManifest(t, dir)
	if m.WorkspacePath != dir {
		t.Errorf("expected manifest workspace_path %q to equal resolved repo %q", m.WorkspacePath, dir)
	}
}

// --- 13: repository paths containing spaces work -----------------------------

func TestRun_SandboxOff_RepoPathWithSpaces(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "my project dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	defer func() { _ = os.Chdir(orig) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	policy := "version: 1\npolicy:\n  allow_write: [\"allow.txt\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "airlock.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", ".", "--sandbox", "off",
		"--cmd", `printf "hello\n" > allow.txt`); err != nil {
		t.Fatalf("run: %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(dir, "allow.txt")); err != nil || string(content) != "hello\n" {
		t.Errorf("expected write to succeed in a path with spaces, err=%v content=%q", err, content)
	}
}

// --- 10/15: rollback for an in-place run restores the actual repo; ----------
// --- inspect/verify metadata remain correct ----------------------------------

func TestRun_SandboxOff_RollbackRestoresRealRepo_InspectVerifySucceed(t *testing.T) {
	dir := chdirTempRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("pre-existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runAirlock(t, "--agent", "generic-shell", "--repo", ".", "--sandbox", "off",
		"--cmd", `printf "hello\n" > allow.txt`); err != nil {
		t.Fatalf("run: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(dir, ".airlock", "runs"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one run: %v %v", entries, err)
	}
	runID := entries[0].Name()

	// inspect and verify must succeed against the in-place run's metadata.
	inspect := inspectCmd()
	inspect.SetArgs([]string{runID})
	if err := inspect.Execute(); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	verify := verifyCmd()
	verify.SetArgs([]string{runID})
	if err := verify.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// rollback --force (skip confirmation prompt) must restore the real repo.
	rb := rollbackCmd()
	rb.SetArgs([]string{runID, "--force"})
	if err := rb.Execute(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "allow.txt")); !os.IsNotExist(err) {
		t.Errorf("allow.txt should be removed by rollback (absent from pre-run checkpoint), stat err=%v", err)
	}
	if content, err := os.ReadFile(filepath.Join(dir, "unrelated.txt")); err != nil || string(content) != "pre-existing" {
		t.Errorf("unrelated.txt must survive rollback untouched, err=%v content=%q", err, content)
	}

	// rollback.json should record this as an in-place restore.
	rbPath := filepath.Join(dir, ".airlock", "runs", runID, "rollback.json")
	b, err := os.ReadFile(rbPath)
	if err != nil {
		t.Fatalf("read rollback.json: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("parse rollback.json: %v", err)
	}
	if inPlace, _ := rec["in_place"].(bool); !inPlace {
		t.Errorf("expected rollback.json in_place=true, got %v", rec["in_place"])
	}
}

// --- 2: sandbox=container behavior must be unaffected by this patch ---------
// selectExecutionRoot is the one branch point introduced for the off-mode
// fix; container and workspace must resolve identically (both stage a copy),
// deterministically, without needing a container runtime installed.

func TestSelectExecutionRoot(t *testing.T) {
	repoAbs := "/abs/real/repo"
	wsDir := ".airlock/workspaces/run1/repo"

	cases := []struct {
		mode execution.Mode
		want string
	}{
		{execution.ModeOff, repoAbs},
		{execution.ModeWorkspace, wsDir},
		{execution.ModeContainer, wsDir},
	}
	for _, tc := range cases {
		got := selectExecutionRoot(tc.mode, repoAbs, wsDir)
		if got != tc.want {
			t.Errorf("selectExecutionRoot(%s, ...) = %q, want %q", tc.mode, got, tc.want)
		}
	}
}
