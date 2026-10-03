package recorder

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// These tests pin the before-state model: "path existed with zero bytes" and
// "path did not exist" are different pre-states and must roll back differently.

func existsWithSize(p string, size int64) bool {
	st, err := os.Lstat(p)
	return err == nil && st.Mode().IsRegular() && st.Size() == size
}

// A: pre-existing empty denied file, denied modification -> empty file restored.
func TestRollback_PreexistingEmptyDeniedFile_ModifyRestoresEmptyFile(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	log := startSymlinkRecorder(t, root)

	if err := os.WriteFile(envPath, []byte("X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitDeny(t, log, ".env")
	if !pollUntil(t, 3*time.Second, func() bool { return existsWithSize(envPath, 0) }) {
		st, err := os.Lstat(envPath)
		t.Fatalf("pre-existing empty .env must be restored as an empty file (stat=%v err=%v)", st, err)
	}
}

// A2: pre-existing empty denied file deleted -> recreated empty.
func TestRollback_PreexistingEmptyDeniedFile_DeleteRestoresEmptyFile(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	log := startSymlinkRecorder(t, root)

	if err := os.Remove(envPath); err != nil {
		t.Fatal(err)
	}
	waitDeny(t, log, ".env")
	if !pollUntil(t, 3*time.Second, func() bool { return existsWithSize(envPath, 0) }) {
		t.Fatal("deleted pre-existing empty .env must be recreated as an empty file")
	}
}

// B: previously absent path, denied creation -> removed (not left as empty).
func TestRollback_AbsentDeniedPath_CreateIsRemoved(t *testing.T) {
	root := t.TempDir()
	log := startSymlinkRecorder(t, root)

	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, nil, 0o644); err != nil { // even an empty creation
		t.Fatal(err)
	}
	waitDeny(t, log, ".env")
	if !pollUntil(t, 3*time.Second, func() bool { return isGone(envPath) }) {
		t.Fatal("a denied creation of a previously absent path must be removed")
	}
}

// C: pre-existing non-empty denied file, denied modification -> bytes restored.
func TestRollback_PreexistingNonEmptyDeniedFile_RestoresBytes(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("ORIGINAL=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := startSymlinkRecorder(t, root)

	if err := os.WriteFile(envPath, nil, 0o644); err != nil { // truncate to empty
		t.Fatal(err)
	}
	waitDeny(t, log, ".env")
	if !pollUntil(t, 3*time.Second, func() bool { return mustRead(t, envPath) == "ORIGINAL=1\n" }) {
		t.Fatalf("non-empty original must be restored, got %q", mustRead(t, envPath))
	}
}

// D: an allowed empty-file mutation is normal: no denial, content stays.
func TestRollback_AllowedEmptyFileMutation_IsNormal(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "status.txt")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	log := startSymlinkRecorder(t, root)

	if err := os.WriteFile(p, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 3*time.Second, func() bool {
		for _, e := range log.EventsSnapshot() {
			if e.Path == "status.txt" {
				return true
			}
		}
		return false
	}) {
		t.Fatal("expected an event for the allowed write")
	}
	for _, e := range log.EventsSnapshot() {
		if e.Type == "POLICY_DENY" {
			t.Fatalf("allowed write was denied: %+v", e)
		}
	}
	if got := mustRead(t, p); got != "hi\n" {
		t.Fatalf("allowed write must survive, got %q", got)
	}
}

// E: empty denied file replaced by a symlink -> empty regular file restored,
// outside target untouched.
func TestRollback_PreexistingEmptyDeniedFile_ReplacedBySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(outside, []byte("EXTERNAL"), 0o644); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, nil, 0o644); err != nil {
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
	if !pollUntil(t, 3*time.Second, func() bool { return existsWithSize(envPath, 0) }) {
		st, err := os.Lstat(envPath)
		t.Fatalf("empty .env must be restored as an empty regular file (stat=%v err=%v)", st, err)
	}
	if got := mustRead(t, outside); got != "EXTERNAL" {
		t.Fatalf("outside file was mutated: %q", got)
	}
}

// A directory symlink created AFTER Sentinel starts: writing through it must
// never be evaluated or reverted, so the outside file stays exactly as written.
func TestSymlink_DirSymlinkCreatedAfterStart_NoOutsideMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	root := t.TempDir()
	outsideDir := t.TempDir()
	startSymlinkRecorder(t, root)

	if err := os.Symlink(outsideDir, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	outFile := filepath.Join(outsideDir, ".env")
	if err := os.WriteFile(filepath.Join(root, "linkdir", ".env"), []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if got, err := os.ReadFile(outFile); err != nil || string(got) != "SECRET=1\n" {
		t.Fatalf("a path outside the workspace was mutated or removed by Sentinel (content=%q err=%v)", got, err)
	}
}
