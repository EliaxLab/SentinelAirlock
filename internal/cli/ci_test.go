package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var (
	ciTestBinOnce sync.Once
	ciTestBinPath string
	ciTestBinErr  error
)

// useRealAirlockBinary points ciSelfExe at a freshly built airlock binary for
// the duration of the test (os.Executable is the test binary under go test,
// which would re-run the whole suite when asked to `verify`).
func useRealAirlockBinary(t *testing.T) string {
	t.Helper()
	ciTestBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "airlock-ci-bin")
		if err != nil {
			ciTestBinErr = err
			return
		}
		ciTestBinPath = filepath.Join(dir, "airlock")
		out, err := exec.Command("go", "build", "-o", ciTestBinPath, "github.com/EliaxLab/SentinelAirlock/cmd/airlock").CombinedOutput()
		if err != nil {
			ciTestBinErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if ciTestBinErr != nil {
		t.Fatal(ciTestBinErr)
	}
	orig := ciSelfExe
	ciSelfExe = func() (string, error) { return ciTestBinPath, nil }
	t.Cleanup(func() { ciSelfExe = orig })
	return ciTestBinPath
}

func runCI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := ciCmd()
	cmd.SetArgs(args)
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	execErr := cmd.Execute()
	w.Close()
	os.Stdout = old
	return <-done, execErr
}

func parseCI(t *testing.T, out string) ciSchema {
	t.Helper()
	var res ciSchema
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("parse ci json: %v\n%s", err, out)
	}
	return res
}

func TestCI_Exec_Success_RealChildExitCode(t *testing.T) {
	useRealAirlockBinary(t)
	dir := chdirTempRepo(t)

	out, err := runCI(t, "exec", "--workspace", ".", "--json", "--",
		"sh", "-c", "printf hi > "+filepath.Join(dir, "allow.txt"))
	if err != nil {
		t.Fatalf("ci exec: %v\n%s", err, out)
	}
	res := parseCI(t, out)
	if res.ExitCode != ExitCISuccess || res.Child == nil || res.Child.ExitCode != 0 || res.Child.Error != "" {
		t.Fatalf("unexpected exec result: %+v child=%+v", res, res.Child)
	}
	if _, err := os.Stat(filepath.Join(dir, "allow.txt")); err != nil {
		t.Fatalf("allowed write should be present: %v", err)
	}
	if res.Verify == nil {
		t.Fatalf("expected verify result from real binary")
	}
}

func TestCI_Exec_WorkloadFailure_Exit10(t *testing.T) {
	useRealAirlockBinary(t)
	chdirTempRepo(t)

	out, err := runCI(t, "exec", "--workspace", ".", "--json", "--", "sh", "-c", "exit 7")
	ce, ok := err.(*ciExitError)
	if !ok || ce.code != ExitCIWorkloadFailed {
		t.Fatalf("expected exit %d, got %v\n%s", ExitCIWorkloadFailed, err, out)
	}
	if res := parseCI(t, out); res.Child == nil || res.Child.ExitCode != 7 {
		t.Fatalf("expected child exit 7, got %+v", res.Child)
	}
}

func TestCI_Exec_PolicyViolationExitCode(t *testing.T) {
	useRealAirlockBinary(t)
	dir := chdirTempRepo(t)

	// The child also exits nonzero: policy violation (20) must outrank it (10).
	out, err := runCI(t, "exec", "--workspace", ".", "--json", "--",
		"sh", "-c", "printf secret > "+filepath.Join(dir, ".env")+"; exit 3")
	ce, ok := err.(*ciExitError)
	if !ok {
		t.Fatalf("expected ciExitError, got %v\n%s", err, out)
	}
	if ce.code != ExitCIPolicyViolation && ce.code != ExitCIRevertFailed {
		t.Fatalf("expected policy-violation or revert-failure exit code, got %d\n%s", ce.code, out)
	}
	res := parseCI(t, out)
	if res.Governance == nil || res.Governance.Denied == 0 {
		t.Fatalf("expected at least one denied write, got %+v", res.Governance)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Fatalf("denied .env write should have been reverted, stat err = %v", err)
	}
}

func TestCI_Exec_RefusesWhenSentinelActive(t *testing.T) {
	dir := chdirTempRepo(t)
	dir = canonicalRepo(t, dir)
	sess, err := startSentinelSession(dir, filepath.Join(dir, "airlock.yaml"), "", false, fleetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()

	out, err := runCI(t, "exec", "--workspace", ".", "--json", "--", "true")
	ce, ok := err.(*ciExitError)
	if !ok || ce.code != ExitCIInternalError {
		t.Fatalf("expected exit %d, got %v\n%s", ExitCIInternalError, err, out)
	}
}

func TestCI_Status_NotStarted(t *testing.T) {
	chdirTempRepo(t)
	out, err := runCI(t, "status", "--workspace", ".", "--json")
	if err != nil {
		t.Fatalf("ci status: %v\n%s", err, out)
	}
	if res := parseCI(t, out); res.Status != "not_started" || res.ExitCode != ExitCISuccess {
		t.Fatalf("unexpected status result: %+v", res)
	}
}

func TestCI_Finalize_NoLifecycle_Errors(t *testing.T) {
	chdirTempRepo(t)
	out, err := runCI(t, "finalize", "--workspace", ".", "--json")
	ce, ok := err.(*ciExitError)
	if !ok || ce.code != ExitCIInternalError {
		t.Fatalf("expected exit %d, got %v\n%s", ExitCIInternalError, err, out)
	}
}

// The ownership invariant: finalize must never stop or finalize a Sentinel
// this CI lifecycle did not start. The "foreign" Sentinel here is a live
// in-process session (its metadata carries this test process's PID), so a
// buggy finalize that stopped it would SIGTERM the test binary itself.
func TestCI_Finalize_NeverStopsUnownedSentinel(t *testing.T) {
	useRealAirlockBinary(t)
	dir := canonicalRepo(t, chdirTempRepo(t))
	sess, err := startSentinelSession(dir, filepath.Join(dir, "airlock.yaml"), "", false, fleetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()

	// Attached (unowned) lifecycle for the live session.
	if err := writeCILifecycle(dir, ciLifecycle{
		SessionID: sess.sessionID, PID: os.Getpid(), Workspace: dir,
		Owned: false, StartedAt: time.Now().UTC(), Status: "running",
	}); err != nil {
		t.Fatal(err)
	}
	out, err := runCI(t, "finalize", "--workspace", dir, "--json")
	if err != nil {
		t.Fatalf("finalize (attached): %v\n%s", err, out)
	}
	if _, running := runningSentinel(dir); !running {
		t.Fatalf("finalize stopped a sentinel it did not own")
	}

	// A lifecycle for a *different* session than the running one must be refused.
	if err := writeCILifecycle(dir, ciLifecycle{
		SessionID: "some-other-session", PID: 1, Workspace: dir,
		Owned: true, StartedAt: time.Now().UTC(), Status: "running",
	}); err != nil {
		t.Fatal(err)
	}
	out, err = runCI(t, "finalize", "--workspace", dir, "--json")
	ce, ok := err.(*ciExitError)
	if !ok || ce.code != ExitCIInternalError {
		t.Fatalf("expected refusal exit %d, got %v\n%s", ExitCIInternalError, err, out)
	}
	if _, running := runningSentinel(dir); !running {
		t.Fatalf("finalize touched a sentinel belonging to a different session")
	}
}

// ci start/finalize spawn the real airlock binary via os.Executable(), which
// is the test binary under `go test`; that path is covered end-to-end against
// a real built binary by samples/demo.sh instead.
