package recorder

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/governance"
	"github.com/EliaxLab/SentinelAirlock/internal/policy"
)

// pollUntil retries fn every 10ms until it returns true or timeout elapses.
// Used instead of a fixed sleep so tests settle as soon as the async
// fsnotify pipeline catches up, without waiting longer than necessary.
func pollUntil(t *testing.T, timeout time.Duration, fn func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}

func newTestLogger(t *testing.T, dir string) *events.Logger {
	t.Helper()
	l, err := events.NewLogger(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func denyingPolicy() *policy.Config {
	cfg := &policy.Config{}
	cfg.Policy.DenyWrite = []string{"**/.env", "secrets/**"}
	return cfg
}

// --- Seed: pre-existing denied file, modified externally, restored --------

func TestRecorder_Seed_DeniedModifyRestoresOriginalContent(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("ORIGINAL=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	rec, err := New(root, log, denyingPolicy(), governance.ApprovalAuto)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	if err := os.WriteFile(envPath, []byte("MUTATED=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Wait on the EVENT, not on the file's contents. The recorder reverts the
	// file before it logs the denial (see evaluate in recorder.go), so polling
	// the file can succeed inside that gap and then find no event yet -- a
	// race that is invisible on a fast machine and reproducible on a loaded
	// one. Observing the event implies the revert already happened, so this
	// order is both correct and strictly stronger.
	var denial events.Event
	ok := pollUntil(t, 2*time.Second, func() bool {
		for _, e := range log.EventsSnapshot() {
			if e.Type == "POLICY_DENY" && e.Path == ".env" {
				denial = e
				return true
			}
		}
		return false
	})
	if !ok {
		b, _ := os.ReadFile(envPath)
		t.Fatalf("expected a POLICY_DENY event for .env (file content is now %q)", b)
	}
	if reverted, _ := denial.Meta["reverted"].(bool); !reverted {
		t.Errorf("expected Meta[reverted]=true, got %v", denial.Meta["reverted"])
	}
	if b, _ := os.ReadFile(envPath); string(b) != "ORIGINAL=1\n" {
		t.Fatalf("expected .env restored to ORIGINAL=1, got %q", b)
	}
}

// --- Seed: pre-existing denied file, deleted externally, recreated --------

func TestRecorder_Seed_DeniedDeleteRestoresFile(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	tokenPath := filepath.Join(root, "secrets", "token.txt")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("tok-original"), 0o644); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	rec, err := New(root, log, denyingPolicy(), governance.ApprovalAuto)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		b, err := os.ReadFile(tokenPath)
		return err == nil && string(b) == "tok-original"
	})
	if !ok {
		t.Fatal("expected secrets/token.txt to be recreated with its original content after being deleted")
	}
}

// --- Newly-created denied file is removed, not "restored" -----------------

func TestRecorder_NewDeniedFile_Removed(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	rec, err := New(root, log, denyingPolicy(), governance.ApprovalAuto)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		_, err := os.Stat(envPath)
		return os.IsNotExist(err)
	})
	if !ok {
		t.Fatal("expected newly-created .env to be removed")
	}
}

// --- Allowed write survives -------------------------------------------------

func TestRecorder_AllowedWrite_Survives(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	rec, err := New(root, log, denyingPolicy(), governance.ApprovalAuto)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	okPath := filepath.Join(root, "status.txt")
	if err := os.WriteFile(okPath, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		found := false
		for _, e := range log.EventsSnapshot() {
			if e.Path == "status.txt" {
				found = true
			}
		}
		return found
	})
	if !ok {
		t.Fatal("expected an event recorded for status.txt")
	}
	b, err := os.ReadFile(okPath)
	if err != nil || string(b) != "hi\n" {
		t.Errorf("status.txt should survive untouched, got %q err=%v", b, err)
	}
}

// --- .airlock/** never appears as a user mutation --------------------------

func TestRecorder_IgnoresAirlockMetadata(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".airlock", "runs", "x"), 0o755); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	rec, err := New(root, log, denyingPolicy(), governance.ApprovalAuto)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	if err := os.WriteFile(filepath.Join(root, ".airlock", "runs", "x", "events.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Also touch a real user file so we have positive proof the watcher is alive.
	if err := os.WriteFile(filepath.Join(root, "status.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pollUntil(t, 2*time.Second, func() bool {
		for _, e := range log.EventsSnapshot() {
			if e.Path == "status.txt" {
				return true
			}
		}
		return false
	})

	for _, e := range log.EventsSnapshot() {
		if e.Path == ".airlock" || (len(e.Path) >= 9 && e.Path[:9] == ".airlock/") {
			t.Errorf("Airlock's own metadata must never appear as a user mutation, got event for %q", e.Path)
		}
	}
}

// --- Debounced mode coalesces a rapid burst of writes into one evaluation --

func TestRecorder_Debounced_CoalescesRapidWrites(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	path := filepath.Join(root, "status.txt")
	if err := os.WriteFile(path, []byte("v0"), 0o644); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	// A 2s debounce window against ~15ms writes. The window has to be wide
	// relative to SCHEDULING JITTER, not just to the sleeps: if the goroutine
	// running this loop is descheduled for longer than the window between two
	// writes -- routine on a loaded CI runner, never seen on an idle laptop --
	// the window closes mid-burst and the burst is legitimately recorded as
	// several events. That measures the machine, not the coalescing. The
	// assertion below is unchanged and just as strict; only the headroom grew,
	// and Stop() drains the pending evaluation so the test stays fast.
	rec, err := NewDebounced(root, log, denyingPolicy(), governance.ApprovalAuto, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte("v"+string(rune('1'+i))), 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(15 * time.Millisecond) // well inside the debounce window
	}

	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, e := range log.EventsSnapshot() {
		if e.Path == "status.txt" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 coalesced event for a rapid burst on one path, got %d", count)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "v5" {
		t.Errorf("expected final settled content v5 to survive, got %q err=%v", b, err)
	}
}

// --- Immediate (non-debounced) mode is unaffected: existing airlock-run ---
// --- behavior evaluates every event individually, no coalescing -----------

func TestRecorder_Immediate_DoesNotCoalesce(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	path := filepath.Join(root, "status.txt")
	if err := os.WriteFile(path, []byte("v0"), 0o644); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	rec, err := New(root, log, denyingPolicy(), governance.ApprovalAuto) // debounce=0
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := os.WriteFile(path, []byte("v"+string(rune('1'+i))), 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
	}

	pollUntil(t, 2*time.Second, func() bool {
		count := 0
		for _, e := range log.EventsSnapshot() {
			if e.Path == "status.txt" {
				count++
			}
		}
		return count >= 1
	})
	_ = rec.Stop()

	count := 0
	for _, e := range log.EventsSnapshot() {
		if e.Path == "status.txt" {
			count++
		}
	}
	if count < 2 {
		t.Errorf("expected immediate mode to log multiple individual events for spaced-out writes, got %d", count)
	}
}

// --- Revert error is captured in evidence, not silently swallowed ---------

func TestRecorder_RevertError_CapturedInMeta(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission-based revert-failure simulation is unix-specific")
	}
	root := t.TempDir()
	evDir := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("ORIGINAL=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	rec, err := New(root, log, denyingPolicy(), governance.ApprovalAuto)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chmod(envPath, 0o644) // restore so TempDir cleanup can remove it
		_ = rec.Stop()
	}()

	if err := os.WriteFile(envPath, []byte("MUTATED=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Make the FILE itself read-only so the recorder's revert write fails
	// (directory perms alone don't block rewriting an existing file's bytes).
	if err := os.Chmod(envPath, 0o444); err != nil {
		t.Fatal(err)
	}

	ok := pollUntil(t, 2*time.Second, func() bool {
		for _, e := range log.EventsSnapshot() {
			if e.Type == "POLICY_DENY" && e.Path == ".env" {
				if reverted, has := e.Meta["reverted"].(bool); has && !reverted {
					return true
				}
			}
		}
		return false
	})
	if !ok {
		t.Skip("could not reliably force a revert failure in this environment (e.g. running as root)")
	}
}

// =====================================================================
// New-directory reconciliation: fixes the missed-child-event race where a
// writer creates a directory and immediately writes into it before the
// recorder's watch on that directory is installed. See recorder.go's
// reconcileSubtree and progress.md for the reproduction that motivated this
// (100/100 child writes missed, including 50/50 denied files surviving,
// against the pre-fix implementation on this project's own dev machine).
// =====================================================================

// countEvents returns how many log entries exist for path -- used to assert
// "exactly one," not just "at least one," so reconciliation's dedup
// (selfEventSuppressWindow) is actually verified, not merely assumed.
func countEvents(log *events.Logger, path string) int {
	n := 0
	for _, e := range log.EventsSnapshot() {
		if e.Path == path {
			n++
		}
	}
	return n
}

// --- 1/2: existing directory, allowed/denied create (pre-existing coverage,
// restated here for matrix completeness) -----------------------------------

func TestRecorder_ExistingDir_AllowedCreate(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	rec, err := NewDebounced(root, log, denyingPolicy(), governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	target := filepath.Join(root, "src", "allowed.txt")
	if err := os.WriteFile(target, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool { return countEvents(log, "src/allowed.txt") >= 1 }) {
		t.Fatal("expected an event for src/allowed.txt")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "hi" {
		t.Errorf("allowed file should survive, got %q err=%v", b, err)
	}
}

func TestRecorder_ExistingDir_DeniedCreate(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	rec, err := NewDebounced(root, log, denyingPolicy(), governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	target := filepath.Join(root, "secrets", "token.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(target)
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected denied secrets/token.txt to be removed")
	}
}

// --- 3/4: brand-new directory, immediate allowed/denied child create ------

func TestRecorder_NewDir_ImmediateAllowedChild_Converges(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	dir := filepath.Join(root, "app")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "hn-success-two.txt")
	if err := os.WriteFile(target, []byte("created by an external writer"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !pollUntil(t, 2*time.Second, func() bool { return countEvents(log, "app/hn-success-two.txt") >= 1 }) {
		t.Fatal("expected app/hn-success-two.txt to be observed despite the new-directory race")
	}
	if got := countEvents(log, "app/hn-success-two.txt"); got != 1 {
		t.Errorf("expected exactly 1 event for the reconciled file, got %d (possible duplicate)", got)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "created by an external writer" {
		t.Errorf("allowed file should survive with its real content, got %q err=%v", b, err)
	}
}

func TestRecorder_NewDir_ImmediateDeniedChild_Reverts(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	rec, err := NewDebounced(root, log, denyingPolicy(), governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	dir := filepath.Join(root, "newsecrets")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, ".env")
	if err := os.WriteFile(target, []byte("SECRET=1"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(target)
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected denied newsecrets/.env to converge to absent despite the new-directory race")
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		for _, e := range log.EventsSnapshot() {
			if e.Path == "newsecrets/.env" && e.Type == "POLICY_DENY" {
				return true
			}
		}
		return false
	}) {
		t.Fatal("expected a POLICY_DENY event for newsecrets/.env")
	}
}

// --- 5/6: deep new directory tree (mkdir -p a/b/c), immediate allowed/denied

func TestRecorder_DeepNewTree_ImmediateAllowedFile_Converges(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	// os.MkdirAll issues separate mkdir syscalls for a, a/b, a/b/c in sequence
	// with no watch installed on any of them at the time -- only the CREATE
	// for "a" (the direct child of the already-watched root) is ever fired.
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(deep, "file.txt")
	if err := os.WriteFile(target, []byte("deep"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !pollUntil(t, 2*time.Second, func() bool { return countEvents(log, "a/b/c/file.txt") >= 1 }) {
		t.Fatal("expected a/b/c/file.txt to be observed despite three levels of new directories")
	}
	if got := countEvents(log, "a/b/c/file.txt"); got != 1 {
		t.Errorf("expected exactly 1 event, got %d", got)
	}
}

func TestRecorder_DeepNewTree_ImmediateDeniedFile_Reverts(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	rec, err := NewDebounced(root, log, denyingPolicy(), governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	deep := filepath.Join(root, "secrets", "nested", "deep")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(deep, "token.txt")
	if err := os.WriteFile(target, []byte("tok"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(target)
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected denied secrets/nested/deep/token.txt to converge to absent")
	}
}

// --- 7: multiple files created rapidly in one new directory ---------------

func TestRecorder_NewDir_MultipleRapidChildren_AllConverge(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	dir := filepath.Join(root, "burst")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const n = 20
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+strconv.Itoa(i)+".txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if !pollUntil(t, 2*time.Second, func() bool {
		for i := 0; i < n; i++ {
			if countEvents(log, "burst/f"+strconv.Itoa(i)+".txt") < 1 {
				return false
			}
		}
		return true
	}) {
		for i := 0; i < n; i++ {
			if countEvents(log, "burst/f"+strconv.Itoa(i)+".txt") < 1 {
				t.Errorf("burst/f%d.txt was never observed", i)
			}
		}
		t.Fatal("not all rapidly-created files in a new directory converged")
	}
}

// --- 8/9: allowed/denied modification in a subtree only known through
// reconciliation (i.e. modify a file after its create was already missed and
// recovered) ----------------------------------------------------------------

func TestRecorder_ModifyAfterReconciledCreate_Allowed(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	dir := filepath.Join(root, "app2")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(target, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool { return countEvents(log, "app2/file.txt") >= 1 }) {
		t.Fatal("expected the reconciled create to be observed first")
	}

	// Now modify it through the normal, already-watched path -- ordinary
	// modification semantics must apply unchanged.
	if err := os.WriteFile(target, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(target)
		return string(b) == "v2"
	}) {
		t.Fatal("expected v2 to survive as an allowed modification")
	}
}

func TestRecorder_ModifyAfterReconciledCreate_DeniedRestoresReconciledBaseline(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	rec, err := NewDebounced(root, log, denyingPolicy(), governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	// secrets/** is denied, but the initial create still lands on disk before
	// Sentinel evaluates it (detect->evaluate->revert) -- reconciliation must
	// still catch it via the new-directory path, establishing "" as baseline
	// (there was no prior legitimate content), then a further external
	// rewrite attempt must be reverted back to that same baseline, not to the
	// attacker-controlled content.
	dir := filepath.Join(root, "secrets2")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "token.txt")
	if err := os.WriteFile(target, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(target)
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected the reconciled denied create to be reverted (removed)")
	}

	// Recreate it (simulating a further denied attempt) -- must be removed
	// again, not "restored" with any attacker content.
	if err := os.WriteFile(target, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(target)
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected the re-created denied file to be removed again")
	}
}

// --- 10: delete behavior is unchanged -------------------------------------

func TestRecorder_Delete_UnchangedByReconciliation(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "src", "existing.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool { return countEvents(log, "src/existing.txt") >= 1 }) {
		t.Fatal("expected a delete event for src/existing.txt")
	}
	for _, e := range log.EventsSnapshot() {
		if e.Path == "src/existing.txt" {
			if e.Type != "FILE_REMOVE" {
				t.Errorf("expected FILE_REMOVE, got %s", e.Type)
			}
		}
	}
}

// --- 11/12: .git/** and .airlock/** stay ignored even when newly created --

func TestRecorder_NewGitDirectory_Ignored(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	// .git did not exist at Start() -- created fresh, exercising the same
	// CREATE-triggered reconciliation path as any other new directory, and
	// must still be fully ignored.
	gitDir := filepath.Join(root, ".git", "objects")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "pack"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Positive proof the watcher/reconciler is alive and processing events.
	if err := os.WriteFile(filepath.Join(root, "status.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 2*time.Second, func() bool { return countEvents(log, "status.txt") >= 1 })

	for _, e := range log.EventsSnapshot() {
		if strings.HasPrefix(e.Path, ".git/") || e.Path == ".git" {
			t.Errorf(".git/** must never appear as a user mutation even when newly created, got event for %q", e.Path)
		}
	}
}

func TestRecorder_NewAirlockDirectory_Ignored(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	airlockDir := filepath.Join(root, ".airlock", "runs", "x")
	if err := os.MkdirAll(airlockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(airlockDir, "events.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "status.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	pollUntil(t, 2*time.Second, func() bool { return countEvents(log, "status.txt") >= 1 })

	for _, e := range log.EventsSnapshot() {
		if strings.HasPrefix(e.Path, ".airlock/") || e.Path == ".airlock" {
			t.Errorf(".airlock/** must never appear as a user mutation even when newly created, got event for %q", e.Path)
		}
	}
}

// --- 13: no duplicate evidence for a normally-observed mutation (existing,
// already-watched directory -- no reconciliation involved at all) ----------

func TestRecorder_NoDuplicateEvidence_NormalMutation(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "src", "once.txt")
	if err := os.WriteFile(target, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool { return countEvents(log, "src/once.txt") >= 1 }) {
		t.Fatal("expected an event for src/once.txt")
	}
	// Let the periodic-safety-reconciliation-adjacent machinery settle, then
	// stop and assert no second, duplicate event ever appeared for it.
	time.Sleep(300 * time.Millisecond)
	_ = rec.Stop()

	if got := countEvents(log, "src/once.txt"); got != 1 {
		t.Errorf("expected exactly 1 event for a normally-observed mutation, got %d", got)
	}
}

// --- 14: shutdown remains clean with the reconciliation goroutine running -

func TestRecorder_Shutdown_CleanWithReconciliationGoroutine(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(root, "app3")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		_ = rec.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return -- reconcileLoop goroutine may not be shutting down cleanly")
	}
}

// --- Stress: many unique new-directory-plus-immediate-child creations, both
// allowed and denied, must all converge with no denied file left behind ----

func TestRecorder_Stress_ManyNewDirsImmediateChildren_Converge(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test skipped in -short mode")
	}
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	rec, err := NewDebounced(root, log, denyingPolicy(), governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	const n = 100
	for i := 0; i < n; i++ {
		allowedDir := filepath.Join(root, "ok"+strconv.Itoa(i))
		if err := os.Mkdir(allowedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(allowedDir, "file.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}

		deniedDir := filepath.Join(root, "denied"+strconv.Itoa(i))
		if err := os.Mkdir(deniedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(deniedDir, ".env"), []byte("SECRET"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if !pollUntil(t, 5*time.Second, func() bool {
		for i := 0; i < n; i++ {
			if countEvents(log, "ok"+strconv.Itoa(i)+"/file.txt") < 1 {
				return false
			}
			if _, statErr := os.Stat(filepath.Join(root, "denied"+strconv.Itoa(i), ".env")); statErr == nil {
				return false
			}
		}
		return true
	}) {
		missingAllowed, survivedDenied := 0, 0
		for i := 0; i < n; i++ {
			if countEvents(log, "ok"+strconv.Itoa(i)+"/file.txt") < 1 {
				missingAllowed++
			}
			if _, statErr := os.Stat(filepath.Join(root, "denied"+strconv.Itoa(i), ".env")); statErr == nil {
				survivedDenied++
			}
		}
		t.Fatalf("stress convergence failed after %d iterations: %d allowed file(s) unobserved, %d denied file(s) survived", n, missingAllowed, survivedDenied)
	}
	t.Logf("stress: %d/%d allowed+denied new-dir pairs converged correctly", n, n)
}

// --- SetPolicy: live policy hot-swap (Prompt 14A Fleet reconciliation) -----

func TestRecorder_SetPolicy_TakesEffectOnNextEvaluation(t *testing.T) {
	root := t.TempDir()
	evDir := t.TempDir()

	log := newTestLogger(t, evDir)
	allowAll := &policy.Config{} // no deny_write rules: everything allowed
	rec, err := New(root, log, allowAll, governance.ApprovalAuto)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	target := filepath.Join(root, "config.txt")
	if err := os.WriteFile(target, []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Wait for the recorder to have actually finished evaluating (and thus
	// cached as baseline) the first write before swapping policy -- not just
	// for the disk content to match, which would race SetPolicy against the
	// recorder's own goroutine still processing the first fsnotify event.
	if !pollUntil(t, 2*time.Second, func() bool {
		for _, e := range log.EventsSnapshot() {
			if e.Path == "config.txt" {
				return true
			}
		}
		return false
	}) {
		t.Fatal("expected the first write to be recorded before swapping policy")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "v1\n" {
		t.Fatalf("write under the initial allow-all policy should have survived, got %q err=%v", b, err)
	}

	// Swap to a policy that denies config.txt -- must take effect on the very
	// next evaluation without restarting the recorder.
	deny := &policy.Config{}
	deny.Policy.DenyWrite = []string{"config.txt"}
	rec.SetPolicy(deny)

	if err := os.WriteFile(target, []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(target)
		return string(b) == "v1\n" // reverted back to the pre-swap baseline
	}) {
		t.Fatal("write after SetPolicy should have been denied and reverted under the new policy")
	}
}

// --- Benchmark: cost of a full periodic reconciliation pass on a large tree.
// This is the steady-state cost paid every reconcileInterval by a long-running
// Sentinel session -- the same order of work Seed() already does once at
// startup, just repeated infrequently rather than a one-off.

func BenchmarkReconcileSubtree_LargeTree(b *testing.B) {
	root := b.TempDir()
	const dirs, filesPerDir = 200, 25 // 5,000 files across 200 directories
	for d := 0; d < dirs; d++ {
		dir := filepath.Join(root, "pkg"+strconv.Itoa(d))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatal(err)
		}
		for f := 0; f < filesPerDir; f++ {
			if err := os.WriteFile(filepath.Join(dir, "file"+strconv.Itoa(f)+".go"), []byte("package pkg"), 0o644); err != nil {
				b.Fatal(err)
			}
		}
	}

	evDir := b.TempDir()
	log, err := events.NewLogger(filepath.Join(evDir, "events.jsonl"))
	if err != nil {
		b.Fatal(err)
	}
	defer log.Close()
	allowAll := &policy.Config{}
	rec, err := NewDebounced(root, log, allowAll, governance.ApprovalAuto, 200*time.Millisecond)
	if err != nil {
		b.Fatal(err)
	}
	if err := rec.Seed(); err != nil {
		b.Fatal(err)
	}
	if err := rec.Start(); err != nil {
		b.Fatal(err)
	}
	defer rec.Stop()

	// Let the initial watch-installation walk settle before measuring the
	// steady-state re-reconciliation cost (everything already known -> the
	// realistic repeated-pass cost, not the one-off startup cost).
	rec.reconcileSubtree(root)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.reconcileSubtree(root) // steady state: every path already known
	}
}
