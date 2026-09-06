package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Sentinel background lifecycle: mirrors the `airlock serve --background`
// pattern in viewer_lifecycle.go (PID file, JSON metadata, log file, stale-PID
// cleanup, graceful-then-forced stop). State is repo-qualified — it lives
// under <repo>/.airlock/, so multiple repos can each have their own Sentinel
// without colliding, the same way each repo has its own .airlock/ already.
//
// osProcAlive / osDetachCmd / osSendStop are shared, platform-specific helpers
// already defined in viewer_lifecycle_unix.go / viewer_lifecycle_windows.go —
// they are generic OS-process helpers, not viewer-specific, so Sentinel reuses
// them directly instead of duplicating platform code.

const (
	sentinelLogName  = "sentinel.log"
	sentinelPIDName  = "sentinel.pid"
	sentinelMetaName = "sentinel.json"
)

type sentinelMeta struct {
	PID        int    `json:"pid"`
	Repo       string `json:"repo"`
	Session    string `json:"session"`
	Started    string `json:"started"`
	Log        string `json:"log"`
	Background bool   `json:"background"`
}

func sentinelDir(repoAbs string) string { return filepath.Join(repoAbs, ".airlock") }
func sentinelLogPath(repoAbs string) string {
	return filepath.Join(sentinelDir(repoAbs), sentinelLogName)
}
func sentinelPIDPath(repoAbs string) string {
	return filepath.Join(sentinelDir(repoAbs), sentinelPIDName)
}
func sentinelMetaPath(repoAbs string) string {
	return filepath.Join(sentinelDir(repoAbs), sentinelMetaName)
}

func writeSentinelMeta(repoAbs string, m sentinelMeta) error {
	if err := os.MkdirAll(sentinelDir(repoAbs), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(sentinelMetaPath(repoAbs), b, 0o644); err != nil {
		return err
	}
	return os.WriteFile(sentinelPIDPath(repoAbs), []byte(fmt.Sprintf("%d\n", m.PID)), 0o644)
}

func readSentinelMeta(repoAbs string) (sentinelMeta, bool) {
	m, ok, _ := readSentinelMetaDetailed(repoAbs)
	return m, ok
}

func readSentinelMetaDetailed(repoAbs string) (sentinelMeta, bool, error) {
	var m sentinelMeta
	b, err := os.ReadFile(sentinelMetaPath(repoAbs))
	if err != nil {
		if os.IsNotExist(err) {
			return m, false, nil
		}
		return m, false, fmt.Errorf("read sentinel lifecycle metadata: %w", err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, false, fmt.Errorf("parse sentinel lifecycle metadata: %w", err)
	}
	if m.PID <= 0 || m.Repo == "" || m.Session == "" || filepath.Base(m.Session) != m.Session {
		return m, false, fmt.Errorf("sentinel lifecycle metadata is incomplete or malformed")
	}
	recordedRepo, err := filepath.Abs(m.Repo)
	if err != nil || filepath.Clean(recordedRepo) != filepath.Clean(repoAbs) {
		return m, false, fmt.Errorf("sentinel lifecycle repository does not match viewer repository")
	}
	return m, true, nil
}

func removeSentinelMeta(repoAbs string) {
	_ = os.Remove(sentinelMetaPath(repoAbs))
	_ = os.Remove(sentinelPIDPath(repoAbs))
}

// runningSentinel returns the recorded Sentinel metadata for repoAbs if a
// live process holds it. A stale metadata file (process gone, e.g. after a
// crash) is cleaned up and reported as not running.
func runningSentinel(repoAbs string) (sentinelMeta, bool) {
	m, ok, _ := runningSentinelDetailed(repoAbs)
	return m, ok
}

func runningSentinelDetailed(repoAbs string) (sentinelMeta, bool, error) {
	m, ok, err := readSentinelMetaDetailed(repoAbs)
	if err != nil {
		return sentinelMeta{}, false, err
	}
	if !ok {
		return sentinelMeta{}, false, nil
	}
	if !processAlive(m.PID) {
		removeSentinelMeta(repoAbs)
		return sentinelMeta{}, false, nil
	}
	return m, true, nil
}

// startSentinelBackground launches a detached child running the foreground
// Sentinel loop against repoAbs, then returns control to the terminal.
func startSentinelBackground(repoAbs, policyPath, policyPack string, fo fleetOptions) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate airlock binary: %w", err)
	}
	if err := os.MkdirAll(sentinelDir(repoAbs), 0o755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(sentinelLogPath(repoAbs), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("cannot open sentinel log: %w", err)
	}
	defer logFile.Close()

	args := []string{"sentinel", "--repo", repoAbs, "--managed"}
	if policyPath != "" {
		args = append(args, "--policy", policyPath)
	}
	if policyPack != "" {
		args = append(args, "--policy-pack", policyPack)
	}
	if fo.URL != "" {
		args = append(args, "--fleet", fo.URL)
	}
	if fo.Token != "" {
		args = append(args, "--fleet-token", fo.Token)
	}
	if fo.EnrollToken != "" {
		args = append(args, "--fleet-enroll-token", fo.EnrollToken)
	}
	if fo.PublicKey != "" {
		args = append(args, "--fleet-pubkey", fo.PublicKey)
	}
	if fo.CACert != "" {
		args = append(args, "--fleet-ca", fo.CACert)
	}
	if fo.HistorySyncDisabled {
		args = append(args, "--fleet-history=false")
	}

	cmd := exec.Command(self, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	osDetachCmd(cmd) // detach into its own process group so it survives this terminal (Unix only)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start background sentinel: %w", err)
	}
	_ = cmd.Process.Release() // don't reap the child when this process exits

	m, ok := waitForSentinel(repoAbs, 3*time.Second)
	if !ok {
		fmt.Printf("Background Sentinel starting (pid %d), but it did not report ready in time.\n", cmd.Process.Pid)
		fmt.Printf("  Log: %s\n", sentinelLogPath(repoAbs))
		fmt.Printf("Check status with: airlock sentinel --repo %s --status\n", repoAbs)
		return nil
	}

	fmt.Println("Background Sentinel started.")
	fmt.Printf("  Repository: %s\n", m.Repo)
	fmt.Printf("  Session:    %s\n", m.Session)
	fmt.Printf("  PID:        %d\n", m.PID)
	fmt.Printf("  Log:        %s\n", m.Log)
	fmt.Printf("  Stop:       airlock sentinel --repo %s --stop\n", repoAbs)
	fmt.Printf("  Status:     airlock sentinel --repo %s --status\n", repoAbs)
	return nil
}

func waitForSentinel(repoAbs string, timeout time.Duration) (sentinelMeta, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m, ok := readSentinelMeta(repoAbs); ok && processAlive(m.PID) {
			return m, true
		}
		time.Sleep(80 * time.Millisecond)
	}
	return sentinelMeta{}, false
}

// sentinelStatusCmd reports whether Sentinel is active for repoAbs.
func sentinelStatusCmd(repoAbs string) error {
	m, running := runningSentinel(repoAbs)
	if !running {
		fmt.Println("Sentinel: not running")
		fmt.Printf("Repository: %s\n", repoAbs)
		fmt.Printf("Start one with: airlock sentinel --repo %s --background\n", repoAbs)
		return nil
	}
	fmt.Println("Sentinel: running")
	fmt.Printf("Repository: %s\n", m.Repo)
	fmt.Printf("PID:        %d\n", m.PID)
	fmt.Printf("Started:    %s\n", m.Started)
	if started, err := time.Parse(time.RFC3339, m.Started); err == nil {
		fmt.Printf("Uptime:     %s\n", time.Since(started).Round(time.Second))
	}
	fmt.Printf("Session:    %s\n", m.Session)
	fmt.Printf("Log:        %s\n", m.Log)
	printFleetTrustStatus(repoAbs)
	fmt.Printf("Stop with:  airlock sentinel --repo %s --stop\n", repoAbs)
	return nil
}

// printFleetTrustStatus shows the Fleet trust state of a Fleet-managed
// Sentinel (Prompt 14B), or nothing at all for a standalone one.
//
// This is the local half of the trust UI, and it is the half that still works
// when the control plane is gone: what identity this Sentinel holds, which
// key it verified its policy against, what it is enforcing, and how much it
// has buffered while disconnected -- all readable without reaching anything
// over the network.
func printFleetTrustStatus(repoAbs string) {
	st, ok := loadFleetStatus(repoAbs)
	if !ok {
		return
	}
	fmt.Println()
	fmt.Println("Fleet")
	reach := "reachable"
	switch {
	case st.Identity == "REVOKED" && st.Connected:
		// Reached it; it refused us. Say that, rather than blaming the network.
		reach = "reachable, but rejecting this Sentinel's credential"
	case !st.Connected:
		reach = "UNREACHABLE -- local governance continues regardless"
	}
	fmt.Printf("  Control plane:   %s (%s)\n", st.FleetURL, reach)
	fmt.Printf("  Identity:        %s\n", st.Identity)
	if st.SignatureState != "" {
		fmt.Printf("  Policy signature: %s\n", st.SignatureState)
	}
	if st.SignerKeyID != "" {
		fmt.Printf("  Policy signer:   %s\n", st.SignerKeyID)
	}
	if st.PolicyID != "" {
		fmt.Printf("  Policy:          %s v%d (hash %s)\n", st.PolicyID, st.PolicyVersion, st.PolicyHash)
	}
	if st.BufferedReports > 0 {
		fmt.Printf("  Buffered reports: %d (will upload when the control plane is reachable)\n", st.BufferedReports)
	}
	if st.DroppedReports > 0 {
		fmt.Printf("  Dropped reports:  %d (buffer limit reached during a long outage)\n", st.DroppedReports)
	}
	if st.LastError != "" {
		fmt.Printf("  Last issue:      %s\n", st.LastError)
	}
	if st.Identity == "REVOKED" {
		fmt.Println("  NOTE: this Sentinel's Fleet credential was revoked. It is no longer part of the fleet,")
		fmt.Println("        and it is still governing this repository with its last-known-good policy.")
	}
}

// sentinelStopCmd terminates the running Sentinel for repoAbs and clears its
// metadata. The running process's own signal handler does the graceful
// finalize (flush evidence, rebuild digest/report/index, remove metadata);
// this only forces the shutdown and waits for it, force-killing as a
// last resort so --stop never hangs indefinitely.
func sentinelStopCmd(repoAbs string) error {
	m, running := runningSentinel(repoAbs)
	if !running {
		fmt.Println("Sentinel: not running (nothing to stop)")
		return nil
	}
	proc, err := os.FindProcess(m.PID)
	if err != nil {
		removeSentinelMeta(repoAbs)
		return fmt.Errorf("could not find sentinel process %d: %w", m.PID, err)
	}
	if err := osSendStop(proc); err != nil {
		_ = proc.Kill()
	}
	for i := 0; i < 100; i++ { // up to ~5s for graceful finalize (checkpoint/digest/report rebuild)
		if !processAlive(m.PID) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if processAlive(m.PID) {
		_ = proc.Kill()
	}
	removeSentinelMeta(repoAbs)
	fmt.Printf("Stopped Sentinel (pid %d) for %s.\n", m.PID, m.Repo)
	return nil
}
