package recorder

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/governance"
)

// startSymlinkRecorder seeds and starts a recorder on root. "outside" is a
// separate disposable temp dir standing in for anything beyond the governed
// workspace; nothing in these tests touches a real path outside t.TempDir().
func startSymlinkRecorder(t *testing.T, root string) *events.Logger {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	log := newTestLogger(t, t.TempDir())
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
	t.Cleanup(func() { _ = rec.Stop() })
	return log
}

func waitDeny(t *testing.T, log *events.Logger, path string) events.Event {
	t.Helper()
	var got events.Event
	if !pollUntil(t, 3*time.Second, func() bool {
		for _, e := range log.EventsSnapshot() {
			if e.Type == "POLICY_DENY" && e.Path == path {
				got = e
				return true
			}
		}
		return false
	}) {
		t.Fatalf("expected POLICY_DENY for %s", path)
	}
	return got
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func isGone(p string) bool {
	_, err := os.Lstat(p)
	return os.IsNotExist(err)
}

// New symlink at a denied path, target inside the workspace: the link is
// removed and the target is untouched.
func TestSymlink_NewLinkAtDeniedPath_InWorkspaceTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "status.txt")
	if err := os.WriteFile(target, []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := startSymlinkRecorder(t, root)

	if err := os.Symlink("status.txt", filepath.Join(root, ".env")); err != nil {
		t.Fatal(err)
	}
	waitDeny(t, log, ".env")
	if !pollUntil(t, 2*time.Second, func() bool { return isGone(filepath.Join(root, ".env")) }) {
		t.Fatal("denied symlink .env must be removed, it survived")
	}
	if got := mustRead(t, target); got != "orig" {
		t.Fatalf("target must be untouched, got %q", got)
	}
}

// New symlink at a denied path pointing outside the workspace: the link is
// removed, the outside file is untouched, and the outside file's content must
// not be copied into the evidence diff.
func TestSymlink_NewLinkAtDeniedPath_OutsideTarget_NoLeakNoMutation(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(outside, []byte("EXTERNAL-SENSITIVE-CONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := startSymlinkRecorder(t, root)

	if err := os.Symlink(outside, filepath.Join(root, ".env")); err != nil {
		t.Fatal(err)
	}
	ev := waitDeny(t, log, ".env")
	if !pollUntil(t, 2*time.Second, func() bool { return isGone(filepath.Join(root, ".env")) }) {
		t.Fatal("denied symlink .env must be removed, it survived")
	}
	if got := mustRead(t, outside); got != "EXTERNAL-SENSITIVE-CONTENT" {
		t.Fatalf("outside file was mutated: %q", got)
	}
	if strings.Contains(ev.Diff, "EXTERNAL-SENSITIVE-CONTENT") {
		t.Fatalf("content of a file outside the workspace leaked into evidence diff: %q", ev.Diff)
	}
}

// A symlink atomically renamed over an existing denied regular file. The
// invariant: converge to the pre-mutation state (regular file, original
// content) and never write through the link into its target.
func TestSymlink_RenameOverExistingDeniedFile_RestoresRegularFile(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(outside, []byte("EXTERNAL"), 0o644); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("ORIGINAL=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := startSymlinkRecorder(t, root)

	tmp := filepath.Join(root, "lnk")
	if err := os.Symlink(outside, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, envPath); err != nil {
		t.Fatal(err)
	}
	waitDeny(t, log, ".env")

	converged := pollUntil(t, 3*time.Second, func() bool {
		st, err := os.Lstat(envPath)
		return err == nil && st.Mode().IsRegular() && mustRead(t, envPath) == "ORIGINAL=1\n"
	})
	if got := mustRead(t, outside); got != "EXTERNAL" {
		t.Fatalf("rollback wrote THROUGH the symlink into a file outside the workspace: %q", got)
	}
	if !converged {
		st, _ := os.Lstat(envPath)
		t.Fatalf(".env did not converge to its pre-mutation regular file (mode %v)", st.Mode())
	}
}

// A symlink in an allowed path that points at a denied file inside the
// workspace; a write through the link modifies the denied file.
func TestSymlink_AllowedLinkToDeniedFile_WriteThrough(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("ORIGINAL=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(".env", filepath.Join(root, "link.txt")); err != nil {
			t.Fatal(err)
		}
	}
	startSymlinkRecorder(t, root)

	if err := os.WriteFile(filepath.Join(root, "link.txt"), []byte("MUTATED=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 3*time.Second, func() bool { return mustRead(t, envPath) == "ORIGINAL=1\n" }) {
		t.Fatalf("write through an allowed-path symlink changed the denied .env and it was not restored: %q", mustRead(t, envPath))
	}
}

// A write that lands in a directory reached through a directory symlink is
// outside the governed workspace. Some watcher backends (macOS kqueue)
// report such events anyway; the recorder must never evaluate or revert a
// path outside its root, so the outside file must be left exactly as written.
// (This is a limitation of coverage, not enforcement: such writes are not
// governed.)
func TestSymlink_SymlinkedDirectory_NeverActsOutsideWorkspace(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	if err := os.Symlink(outsideDir, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}
	log := startSymlinkRecorder(t, root)

	if err := os.WriteFile(filepath.Join(root, "linkdir", ".env"), []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	for _, e := range log.EventsSnapshot() {
		if e.Type == "POLICY_DENY" {
			t.Fatalf("unexpected enforcement through a directory symlink: %+v", e)
		}
	}
	if got := mustRead(t, filepath.Join(outsideDir, ".env")); got != "SECRET=1\n" {
		t.Fatalf("expected the write to land untouched in the (ungoverned) target, got %q", got)
	}
}
