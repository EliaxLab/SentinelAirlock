package rollback

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

// chdirTemp creates a temp dir, chdirs into it, and returns a cleanup func.
func chdirTemp(t *testing.T) string {
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
	return dir
}

// seedRun writes a run_manifest.json + checkpoint dir under .airlock/runs/<id>,
// simulating what `airlock run` would have produced. workspacePath is the
// manifest's workspace_path (a staged copy dir for non-in-place runs, or the
// real repo root for in-place runs).
func seedRun(t *testing.T, runID, sandboxMode, workspacePath string, touchedPaths []string, checkpointFiles map[string]string) string {
	t.Helper()
	runsDir := filepath.Join(".airlock", "runs", runID)
	cpPath := filepath.Join(runsDir, "checkpoints", "cp-0")
	if err := os.MkdirAll(cpPath, 0o755); err != nil {
		t.Fatal(err)
	}
	for rel, content := range checkpointFiles {
		full := filepath.Join(cpPath, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := runmeta.RunManifest{
		RunID:         runID,
		WorkspacePath: workspacePath,
		TouchedPaths:  touchedPaths,
		Sandbox:       runmeta.SandboxInfo{Mode: sandboxMode},
		Checkpoints:   []runmeta.Checkpoint{{ID: "cp-0", Path: cpPath}},
	}
	if err := runmeta.Save(filepath.Join(runsDir, "run_manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	return runsDir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// TestBuildPlan_InPlace_DetectsModeAndTouchedPaths covers point 10 (rollback
// target resolution must be unambiguous from run metadata) for in-place runs.
func TestBuildPlan_InPlace_DetectsModeAndTouchedPaths(t *testing.T) {
	chdirTemp(t)
	seedRun(t, "run1", "off", "/real/repo", []string{"a.txt", "b.txt"}, nil)

	plan, err := BuildPlan(Options{RunID: "run1"})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if !plan.InPlace {
		t.Error("expected InPlace=true for sandbox=off manifest")
	}
	if len(plan.TouchedPaths) != 2 {
		t.Errorf("expected 2 touched paths, got %v", plan.TouchedPaths)
	}
}

func TestBuildPlan_Workspace_NotInPlace(t *testing.T) {
	chdirTemp(t)
	seedRun(t, "run1", "workspace", ".airlock/workspaces/run1/repo", []string{"a.txt"}, nil)

	plan, err := BuildPlan(Options{RunID: "run1"})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if plan.InPlace {
		t.Error("expected InPlace=false for sandbox=workspace manifest")
	}
}

// TestExecute_InPlace_RestoresOnlyTouchedPaths is the core safety guarantee:
// full-mode restore for an in-place run must NOT os.RemoveAll the real repo
// root. It must restore exactly the touched paths and leave everything else
// (here simulated by unrelated.txt and a .git-like dir) untouched.
func TestExecute_InPlace_RestoresOnlyTouchedPaths(t *testing.T) {
	dir := chdirTemp(t)
	repoRoot := filepath.Join(dir, "real-repo")

	// Checkpoint: pre-run state had none of the touched files.
	seedRun(t, "run1", "off", repoRoot, []string{"new.txt"}, map[string]string{})

	// Simulate post-run real-repo state: the agent created new.txt, and
	// unrelated.txt / .git/config already existed and must survive rollback.
	writeFile(t, filepath.Join(repoRoot, "new.txt"), "created by agent")
	writeFile(t, filepath.Join(repoRoot, "unrelated.txt"), "pre-existing, not touched by run")
	writeFile(t, filepath.Join(repoRoot, ".git", "config"), "fake git config")

	res, err := Execute(Options{RunID: "run1"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.InPlace {
		t.Error("expected result.InPlace=true")
	}

	if _, ok := readFile(t, filepath.Join(repoRoot, "new.txt")); ok {
		t.Error("new.txt should have been removed (not present in checkpoint)")
	}
	if content, ok := readFile(t, filepath.Join(repoRoot, "unrelated.txt")); !ok || content != "pre-existing, not touched by run" {
		t.Error("unrelated.txt must survive an in-place rollback untouched")
	}
	if content, ok := readFile(t, filepath.Join(repoRoot, ".git", "config")); !ok || content != "fake git config" {
		t.Error(".git/config must survive an in-place rollback untouched — full restore must never RemoveAll the real repo")
	}
}

// TestExecute_InPlace_RestoresModifiedFileContent proves the checkpoint's
// prior content is restored for a file that existed before the run and was
// modified during it (not just newly-created files being removed).
func TestExecute_InPlace_RestoresModifiedFileContent(t *testing.T) {
	dir := chdirTemp(t)
	repoRoot := filepath.Join(dir, "real-repo")

	seedRun(t, "run1", "off", repoRoot, []string{"config.txt"}, map[string]string{
		"config.txt": "original content",
	})
	writeFile(t, filepath.Join(repoRoot, "config.txt"), "mutated by agent")

	if _, err := Execute(Options{RunID: "run1"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	content, ok := readFile(t, filepath.Join(repoRoot, "config.txt"))
	if !ok || content != "original content" {
		t.Errorf("expected config.txt restored to checkpoint content, got %q ok=%v", content, ok)
	}
}

// TestExecute_Workspace_FullRestore_StillWipesAndRecopies is a regression
// test: sandbox=workspace/container behavior (RemoveAll + full CopyRepo) must
// be completely unchanged by the in-place fix.
func TestExecute_Workspace_FullRestore_StillWipesAndRecopies(t *testing.T) {
	dir := chdirTemp(t)
	wsPath := filepath.Join(dir, ".airlock", "workspaces", "run1", "repo")

	seedRun(t, "run1", "workspace", wsPath, []string{"out.txt"}, map[string]string{
		"kept.txt": "from checkpoint",
	})
	writeFile(t, filepath.Join(wsPath, "out.txt"), "agent output")
	writeFile(t, filepath.Join(wsPath, "extra-junk.txt"), "should be wiped, staged workspace is disposable")

	res, err := Execute(Options{RunID: "run1"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.InPlace {
		t.Error("expected result.InPlace=false for workspace-mode run")
	}
	if _, ok := readFile(t, filepath.Join(wsPath, "out.txt")); ok {
		t.Error("out.txt should be gone after full workspace restore")
	}
	if _, ok := readFile(t, filepath.Join(wsPath, "extra-junk.txt")); ok {
		t.Error("extra-junk.txt should be gone — staged workspace full-restore wipes the whole dir")
	}
	if content, ok := readFile(t, filepath.Join(wsPath, "kept.txt")); !ok || content != "from checkpoint" {
		t.Error("kept.txt from checkpoint should be present after full workspace restore")
	}
}

// TestExecute_PathMode_WorksForInPlace confirms --path subtree restore
// (already-existing, non-destructive logic) needs no special-casing for
// in-place runs — it only ever touches the one requested path either way.
func TestExecute_PathMode_WorksForInPlace(t *testing.T) {
	dir := chdirTemp(t)
	repoRoot := filepath.Join(dir, "real-repo")

	seedRun(t, "run1", "off", repoRoot, []string{"a.txt", "b.txt"}, map[string]string{
		"a.txt": "checkpoint a",
	})
	writeFile(t, filepath.Join(repoRoot, "a.txt"), "mutated a")
	writeFile(t, filepath.Join(repoRoot, "b.txt"), "mutated b")

	if _, err := Execute(Options{RunID: "run1", Path: "a.txt"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if content, ok := readFile(t, filepath.Join(repoRoot, "a.txt")); !ok || content != "checkpoint a" {
		t.Errorf("a.txt should be restored to checkpoint content, got %q ok=%v", content, ok)
	}
	if content, ok := readFile(t, filepath.Join(repoRoot, "b.txt")); !ok || content != "mutated b" {
		t.Error("b.txt was not part of the --path restore and must be untouched")
	}
}

func TestBuildPlan_MissingManifest_Errors(t *testing.T) {
	chdirTemp(t)
	if _, err := BuildPlan(Options{RunID: "does-not-exist"}); err == nil {
		t.Fatal("expected error for missing run manifest")
	}
}
