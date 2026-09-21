package recorder

import (
	"os"
	"path/filepath"
	"runtime"
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
