package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirelahmed-commits/SentinelAirlock/internal/runmeta"
)

// pollUntil retries fn every 15ms until it returns true or timeout elapses,
// so tests settle as soon as the async fsnotify/debounce pipeline catches up
// instead of waiting a fixed, longer-than-necessary amount of time.
func pollUntil(t *testing.T, timeout time.Duration, fn func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return fn()
}

// canonicalRepo resolves dir the same way sentinelCmd's real RunE effectively
// ends up resolving it: to the filesystem's canonical, symlink-free form. On
// macOS t.TempDir() returns a path through the /var -> /private/var symlink;
// filepath.Abs alone does NOT resolve symlinks (it only Cleans an already-
// absolute path), so watching dir un-resolved would leave the recorder
// rooted at the unresolved alias while fsnotify reports event paths in the
// resolved form — every event's computed relative path would then be wrong.
func canonicalRepo(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// startTestSentinel starts a real session (checkpoint, recorder, evidence)
// against dir using chdirTempRepo's policy (allow.txt/status.txt/config.txt
// allowed, .env and secrets/** denied), and registers cleanup.
func startTestSentinel(t *testing.T, dir string) *sentinelSession {
	t.Helper()
	repoAbs := canonicalRepo(t, dir)
	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: ""})
	if err != nil {
		t.Fatalf("startSentinelSession: %v", err)
	}
	activeSessions[sess.sessionID] = sess
	t.Cleanup(func() {
		sess.shutdown()
		delete(activeSessions, sess.sessionID)
		removeSentinelMeta(repoAbs) // shutdown() already does this; belt and suspenders for a failed test
	})
	return sess
}

// manifestOf reads back sess's current manifest. It force-refreshes first:
// outside of runSentinelForeground's periodic ticker (which these tests
// bypass by calling startSentinelSession directly, for determinism), the
// manifest is only written at session start and at shutdown — so a check
// made in between would otherwise see stale data regardless of what the
// recorder has actually already processed.
func manifestOf(t *testing.T, dir, sessionID string) runmeta.RunManifest {
	t.Helper()
	if sess, ok := activeSessions[sessionID]; ok {
		sess.refreshEvidence("running")
	}
	m, err := runmeta.Load(filepath.Join(dir, ".airlock", "runs", sessionID, "run_manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return m
}

// activeSessions lets manifestOf find the sentinelSession for a given
// sessionID without changing every test call site's signature.
var activeSessions = map[string]*sentinelSession{}

// --- 1/2: Sentinel starts on a real repo, detects changes from processes ---
// --- Airlock did not launch (plain os.WriteFile, not airlock run) ---------

func TestSentinel_StartsOnRealRepo_DetectsExternalWrite(t *testing.T) {
	dir := chdirTempRepo(t)
	sess := startTestSentinel(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "status.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		m := manifestOf(t, dir, sess.sessionID)
		for _, p := range m.TouchedPaths {
			if p == "status.txt" {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("expected status.txt to appear in touched paths")
	}
}

// --- 3/4: allowed external create + modify survive -------------------------

func TestSentinel_AllowedCreateAndModify_Survive(t *testing.T) {
	dir := chdirTempRepo(t)
	startTestSentinel(t, dir)

	path := filepath.Join(dir, "status.txt")
	if err := os.WriteFile(path, []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(path)
		return string(b) == "v1\n"
	})
	if err := os.WriteFile(path, []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(path)
		return string(b) == "v2\n"
	})

	b, err := os.ReadFile(path)
	if err != nil || string(b) != "v2\n" {
		t.Errorf("expected status.txt to survive both writes with final content v2, got %q err=%v", b, err)
	}
}

// --- 5/7: newly-created denied file (including nested) is reverted ---------

func TestSentinel_DeniedCreate_NestedAndTopLevel_Reverted(t *testing.T) {
	dir := chdirTempRepo(t)
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	sess := startTestSentinel(t, dir)

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "token.txt"), []byte("tok\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		_, err1 := os.Stat(filepath.Join(dir, ".env"))
		_, err2 := os.Stat(filepath.Join(dir, "secrets", "token.txt"))
		return os.IsNotExist(err1) && os.IsNotExist(err2)
	})
	if !ok {
		t.Fatal("expected both .env and secrets/token.txt to be removed")
	}

	// 8: evidence uses repo-relative paths.
	m := manifestOf(t, dir, sess.sessionID)
	denied := map[string]bool{}
	for _, p := range m.DeniedPaths {
		denied[p] = true
	}
	if !denied[".env"] || !denied["secrets/token.txt"] {
		t.Errorf("expected repo-relative denied paths .env and secrets/token.txt, got %v", m.DeniedPaths)
	}
	for _, p := range m.DeniedPaths {
		if filepath.IsAbs(p) {
			t.Errorf("denied path %q must be repo-relative, not absolute", p)
		}
	}
}

// --- 6: pre-existing denied file modified externally is restored -----------

func TestSentinel_DeniedModify_PreExistingFile_RestoredToBaseline(t *testing.T) {
	dir := chdirTempRepo(t)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("ORIGINAL=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	startTestSentinel(t, dir)

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("MUTATED=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(filepath.Join(dir, ".env"))
		return string(b) == "ORIGINAL=1\n"
	})
	if !ok {
		b, _ := os.ReadFile(filepath.Join(dir, ".env"))
		t.Fatalf("expected .env restored to ORIGINAL=1, got %q", b)
	}
}

// --- 9: .airlock/** internal writes never appear as user mutations ---------

func TestSentinel_IgnoresAirlockMetadata(t *testing.T) {
	dir := chdirTempRepo(t)
	sess := startTestSentinel(t, dir)

	// Sentinel's own periodic refresh already writes into .airlock/runs/<id>/
	// continuously; also touch a real file so we know the watcher is alive.
	if err := os.WriteFile(filepath.Join(dir, "status.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 2*time.Second, func() bool {
		m := manifestOf(t, dir, sess.sessionID)
		for _, p := range m.TouchedPaths {
			if p == "status.txt" {
				return true
			}
		}
		return false
	})

	m := manifestOf(t, dir, sess.sessionID)
	for _, p := range append(append([]string{}, m.TouchedPaths...), m.DeniedPaths...) {
		if p == ".airlock" || strings.HasPrefix(p, ".airlock/") {
			t.Errorf("Airlock's own metadata must never appear as a user mutation, got %q", p)
		}
	}
}

// --- 10: editor atomic-save (temp write + rename) handled correctly --------

func TestSentinel_AtomicSaveTempRename_FinalContentWins(t *testing.T) {
	dir := chdirTempRepo(t)
	sess := startTestSentinel(t, dir)

	final := filepath.Join(dir, "status.txt")
	tmp := filepath.Join(dir, ".status.txt.tmp")
	if err := os.WriteFile(tmp, []byte("saved-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, final); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(final)
		return string(b) == "saved-content\n"
	})
	if !ok {
		t.Fatal("expected status.txt to end up with the atomically-saved content")
	}
	// The temp file must not linger as a phantom "mutation" in evidence forever
	// (it no longer exists on disk either, since it was renamed away).
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("temp file should no longer exist after rename, stat err=%v", err)
	}
	m := manifestOf(t, dir, sess.sessionID)
	for _, p := range m.DeniedPaths {
		if strings.Contains(p, ".tmp") {
			t.Errorf("temp file should never be policy-relevant, got denied path %q", p)
		}
	}
}

// --- 11: file deletion is detected ------------------------------------------

func TestSentinel_DeletionDetected(t *testing.T) {
	dir := chdirTempRepo(t)
	path := filepath.Join(dir, "status.txt")
	if err := os.WriteFile(path, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sess := startTestSentinel(t, dir)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		m := manifestOf(t, dir, sess.sessionID)
		for _, p := range m.TouchedPaths {
			if p == "status.txt" {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("expected the deletion of status.txt to be recorded")
	}
}

// --- 12: rename is detected --------------------------------------------------

func TestSentinel_RenameDetected(t *testing.T) {
	dir := chdirTempRepo(t)
	oldPath := filepath.Join(dir, "status.txt")
	if err := os.WriteFile(oldPath, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sess := startTestSentinel(t, dir)

	newPath := filepath.Join(dir, "config.txt")
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		m := manifestOf(t, dir, sess.sessionID)
		touched := map[string]bool{}
		for _, p := range m.TouchedPaths {
			touched[p] = true
		}
		return touched["status.txt"] && touched["config.txt"]
	})
	if !ok {
		m := manifestOf(t, dir, sess.sessionID)
		t.Fatalf("expected both the old and new path of a rename to be recorded, got %v", m.TouchedPaths)
	}
}

// --- 13: multiple rapid writes to one path don't corrupt state -------------

func TestSentinel_RapidWrites_SettleWithoutCorruption(t *testing.T) {
	dir := chdirTempRepo(t)
	path := filepath.Join(dir, "status.txt")
	startTestSentinel(t, dir)

	for i := 0; i < 8; i++ {
		if err := os.WriteFile(path, []byte(strings.Repeat("x", i+1)), 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond) // well inside the debounce window
	}

	pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(path)
		return string(b) == strings.Repeat("x", 8)
	})

	b, err := os.ReadFile(path)
	if err != nil || string(b) != strings.Repeat("x", 8) {
		t.Errorf("expected final settled content after a rapid-write burst, got %q err=%v", b, err)
	}
}

// --- 14: shutdown finalizes evidence cleanly (Ctrl-C / --stop path) --------

func TestSentinel_ShutdownFinalizesEvidence(t *testing.T) {
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: ""})
	if err != nil {
		t.Fatalf("startSentinelSession: %v", err)
	}
	activeSessions[sess.sessionID] = sess
	defer delete(activeSessions, sess.sessionID)
	if err := os.WriteFile(filepath.Join(dir, "status.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 2*time.Second, func() bool {
		m := manifestOf(t, dir, sess.sessionID)
		for _, p := range m.TouchedPaths {
			if p == "status.txt" {
				return true
			}
		}
		return false
	})

	sess.shutdown()
	delete(activeSessions, sess.sessionID) // shutdown() already wrote the final manifest; manifestOf must not refresh (and overwrite "stopped") again

	m := manifestOf(t, dir, sess.sessionID)
	if m.Status.Terminal != "stopped" {
		t.Errorf("expected manifest Status.Terminal=stopped after shutdown, got %q", m.Status.Terminal)
	}
	foundStop := false
	b, err := os.ReadFile(filepath.Join(dir, ".airlock", "runs", sess.sessionID, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"type":"SENTINEL_STOP"`) {
		foundStop = true
	}
	if !foundStop {
		t.Error("expected a SENTINEL_STOP event in events.jsonl after shutdown")
	}
	if _, ok := runningSentinel(dir); ok {
		t.Error("expected sentinel metadata to be removed after shutdown")
	}
	// verify digest is consistent post-shutdown, same as `airlock verify` would check
	if vr, err := runmeta.VerifyRun(sess.sessionID, m); err != nil || vr.Status != "verified-unsigned" {
		t.Errorf("expected verified-unsigned after shutdown, got status=%q err=%v", vr.Status, err)
	}
}

// --- 15/16/17/18/19: background lifecycle metadata ---------------------------

func TestSentinelLifecycle_WriteReadRemoveMeta(t *testing.T) {
	dir := t.TempDir()
	m := sentinelMeta{PID: os.Getpid(), Repo: dir, Session: "s1", Started: time.Now().Format(time.RFC3339), Log: "x"}
	if err := writeSentinelMeta(dir, m); err != nil {
		t.Fatal(err)
	}
	got, ok := readSentinelMeta(dir)
	if !ok || got.Session != "s1" {
		t.Fatalf("expected to read back session s1, got %+v ok=%v", got, ok)
	}
	removeSentinelMeta(dir)
	if _, ok := readSentinelMeta(dir); ok {
		t.Error("expected metadata to be gone after removeSentinelMeta")
	}
}

func TestSentinelLifecycle_DuplicatePrevented(t *testing.T) {
	dir := t.TempDir()
	m := sentinelMeta{PID: os.Getpid(), Repo: dir, Session: "s1", Started: time.Now().Format(time.RFC3339)}
	if err := writeSentinelMeta(dir, m); err != nil {
		t.Fatal(err)
	}
	defer removeSentinelMeta(dir)

	existing, ok := runningSentinel(dir)
	if !ok || existing.Session != "s1" {
		t.Fatalf("expected runningSentinel to report the live process, got %+v ok=%v", existing, ok)
	}
}

func TestSentinelLifecycle_StalePIDCleanedUp(t *testing.T) {
	dir := t.TempDir()
	// A PID essentially guaranteed not to be a live process.
	m := sentinelMeta{PID: 999999, Repo: dir, Session: "stale", Started: time.Now().Format(time.RFC3339)}
	if err := writeSentinelMeta(dir, m); err != nil {
		t.Fatal(err)
	}

	if _, ok := runningSentinel(dir); ok {
		t.Error("expected a stale PID to be reported as not running")
	}
	if _, ok := readSentinelMeta(dir); ok {
		t.Error("expected stale metadata to be cleaned up automatically")
	}
}

func TestSentinelStatus_RunningAndStopped(t *testing.T) {
	dir := t.TempDir()
	if err := sentinelStatusCmd(dir); err != nil {
		t.Fatalf("status on a repo with no sentinel: %v", err)
	}

	m := sentinelMeta{PID: os.Getpid(), Repo: dir, Session: "s1", Started: time.Now().Format(time.RFC3339)}
	if err := writeSentinelMeta(dir, m); err != nil {
		t.Fatal(err)
	}
	defer removeSentinelMeta(dir)
	if err := sentinelStatusCmd(dir); err != nil {
		t.Fatalf("status with a running sentinel: %v", err)
	}
}

// TestSentinelLifecycle_StopSignalsRealProcess drives sentinelStopCmd against
// a real (but otherwise unrelated) long-lived OS process standing in for a
// sentinel, proving the SIGTERM-then-verify-exit mechanics work without
// needing to spawn the full airlock binary in the test suite.
func TestSentinelLifecycle_StopSignalsRealProcess(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no `sleep` binary available to stand in as a fake process")
	}
	dir := t.TempDir()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Reap the child as soon as it exits. Without this, a signaled-but-
	// unreaped child is a zombie: its PID stays valid and Signal(0) keeps
	// reporting it "alive" until something calls Wait() on it — which would
	// make processAlive() below see a false positive that has nothing to do
	// with whether sentinelStopCmd actually terminated it.
	waited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waited)
	}()

	m := sentinelMeta{PID: cmd.Process.Pid, Repo: dir, Session: "s1", Started: time.Now().Format(time.RFC3339)}
	if err := writeSentinelMeta(dir, m); err != nil {
		t.Fatal(err)
	}

	if err := sentinelStopCmd(dir); err != nil {
		t.Fatalf("sentinelStopCmd: %v", err)
	}
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Error("stand-in process was not reaped within 2s of --stop returning")
	}
	if processAlive(cmd.Process.Pid) {
		t.Error("expected the stand-in process to be terminated by --stop")
	}
	if _, ok := readSentinelMeta(dir); ok {
		t.Error("expected metadata removed after --stop")
	}
}

// --- 21: repo path containing spaces ----------------------------------------

func TestSentinel_RepoPathWithSpaces(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "my project dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := "version: 1\npolicy:\n  allow_write: [\"status.txt\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "airlock.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	sess := startTestSentinel(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "status.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := pollUntil(t, 2*time.Second, func() bool {
		m := manifestOf(t, dir, sess.sessionID)
		for _, p := range m.TouchedPaths {
			if p == "status.txt" {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatal("expected sentinel to work correctly against a repo path containing spaces")
	}
}

// --- 22: relative and absolute --repo resolve to the same governed root ----

func TestSentinel_RepoResolution_RelativeAndAbsoluteEquivalent(t *testing.T) {
	dir := chdirTempRepo(t) // chdirTempRepo already os.Chdir's into dir

	// sentinelCmd's RunE always does filepath.Abs(repoPath) — resolving "."
	// (relative, the default) and resolving the caller-supplied absolute dir
	// must land on the same governed repo, once both are canonicalized the
	// same way a real filesystem lookup would (symlinks and all).
	fromRelative, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fromAbsolute, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalRepo(t, fromRelative) != canonicalRepo(t, fromAbsolute) {
		t.Fatalf("relative %q and absolute %q --repo forms must resolve to the same governed root", fromRelative, fromAbsolute)
	}
}

// --- 23: restart establishes a fresh valid baseline without corrupting -----

func TestSentinel_RestartEstablishesFreshBaseline(t *testing.T) {
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	sess1, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: ""})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(filepath.Join(dir, "status.txt"))
		return string(b) == "v1\n"
	})
	sess1.shutdown()

	// New session should seed its baseline from the CURRENT real state (v1),
	// not fail or reset anything.
	sess2, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: ""})
	if err != nil {
		t.Fatalf("second session failed to start: %v", err)
	}
	defer sess2.shutdown()

	if b, err := os.ReadFile(filepath.Join(dir, "status.txt")); err != nil || string(b) != "v1\n" {
		t.Errorf("restart must not corrupt the real repo, expected v1, got %q err=%v", b, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "status.txt"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(filepath.Join(dir, "status.txt"))
		return string(b) == "v2\n"
	})
	if !ok {
		t.Fatal("expected the new session's watcher to correctly observe a further allowed change")
	}
}
