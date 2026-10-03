package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

// Exit codes for the `airlock ci` command family. Every other command in this
// package still exits 0/1 via root.go's default cobra error handling; these
// codes exist because a CI system gating on "did anything policy-relevant
// happen" needs more than a boolean.
//
// Precedence when more than one applies (most severe wins): InternalError >
// RevertFailed > PolicyViolation > WorkloadFailed > Success. An internal
// error makes the rest of the result untrustworthy, so it always wins. A
// revert failure means denied content may still be sitting in the workspace
// -- the single worst concrete outcome Sentinel exists to catch -- so it
// outranks a cleanly-reverted violation, which in turn outranks a plain
// nonzero exit from the governed workload: the whole reason to run Airlock is
// to catch the security-relevant outcomes, so those are surfaced over "the
// build script also happened to fail."
const (
	ExitCISuccess         = 0
	ExitCIWorkloadFailed  = 10
	ExitCIPolicyViolation = 20
	ExitCIRevertFailed    = 21
	ExitCIInternalError   = 30
)

const ciSchemaVersion = "1"

// ciSelfExe locates the airlock binary used to run `airlock verify`. It is a
// variable only so tests, where os.Executable() is the test binary, can point
// it at a real built binary.
var ciSelfExe = os.Executable

// ciSchema is the single machine-readable envelope every `airlock ci`
// subcommand marshals for --json. Fields are populated best-effort: a field
// left nil/empty means "not applicable to this call," never "silently
// unavailable."
type ciSchema struct {
	SchemaVersion string                `json:"schema_version"`
	Command       string                `json:"command"`
	Status        string                `json:"status"`
	Workspace     string                `json:"workspace"`
	Owned         bool                  `json:"owned"`
	SessionID     string                `json:"session_id,omitempty"`
	SentinelID    string                `json:"sentinel_id,omitempty"`
	PID           int                   `json:"pid,omitempty"`
	StartedAt     string                `json:"started_at,omitempty"`
	Policy        *ciPolicy             `json:"policy,omitempty"`
	Fleet         *fleetStatusFile      `json:"fleet,omitempty"`
	Governance    *ciGovernance         `json:"governance,omitempty"`
	Evidence      *ciEvidence           `json:"evidence,omitempty"`
	Verify        *runmeta.VerifyResult `json:"verify,omitempty"`
	Child         *ciChild              `json:"child,omitempty"`
	ExitCode      int                   `json:"exit_code"`
	Error         string                `json:"error,omitempty"`
}

type ciPolicy struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Hash    string `json:"hash,omitempty"`
}

type ciGovernance struct {
	Allowed      int        `json:"allowed"`
	Denied       int        `json:"denied"`
	Reverted     int        `json:"reverted"`
	RevertFailed int        `json:"revert_failed"`
	LastEventAt  *time.Time `json:"last_event_at,omitempty"`
}

type ciEvidence struct {
	RunDir   string `json:"run_dir,omitempty"`
	Events   string `json:"events,omitempty"`
	Manifest string `json:"manifest,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Report   string `json:"report,omitempty"`
}

type ciChild struct {
	Command  []string `json:"command"`
	ExitCode int      `json:"exit_code"`
	Error    string   `json:"error,omitempty"`
}

// ciExitError lets `airlock ci` subcommands signal a specific process exit
// code through cobra's normal error-return path instead of calling os.Exit
// directly. Calling os.Exit directly would kill any test that drives these
// commands in-process via cmd.Execute(), exactly like every other command in
// this package (see run_sandbox_off_test.go's runAirlock helper). Only
// root.go's real Execute() (the actual `airlock` binary entrypoint) unwraps
// this and calls os.Exit with the intended code; a test calling
// cmd.Execute() on a ci subcommand directly instead observes this as an
// ordinary returned error to assert against.
type ciExitError struct {
	code int
	res  *ciSchema
}

func (e *ciExitError) Error() string {
	if e.res != nil && e.res.Error != "" {
		return e.res.Error
	}
	return fmt.Sprintf("airlock ci: exit %d", e.code)
}

// ciFinish prints res (JSON or human) and returns an error carrying res's
// exit code for anything other than success, so root.go's Execute() can
// os.Exit with it. Every `ci` subcommand funnels its result through this one
// function so output shape and exit-code delivery are identical everywhere.
func ciFinish(res *ciSchema, asJSON bool) error {
	printCIResult(res, asJSON)
	if res.ExitCode == ExitCISuccess {
		return nil
	}
	return &ciExitError{code: res.ExitCode, res: res}
}

func ciErrorResult(command, workspace string, err error) *ciSchema {
	return &ciSchema{
		SchemaVersion: ciSchemaVersion,
		Command:       command,
		Status:        "error",
		Workspace:     workspace,
		ExitCode:      ExitCIInternalError,
		Error:         err.Error(),
	}
}

func printCIResult(res *ciSchema, asJSON bool) {
	if asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("airlock ci %s: %s\n", res.Command, res.Status)
	fmt.Printf("  workspace:  %s\n", res.Workspace)
	if res.SessionID != "" {
		fmt.Printf("  session:    %s (owned=%v)\n", res.SessionID, res.Owned)
	}
	if res.Policy != nil {
		fmt.Printf("  policy:     %s v%s (hash %s)\n", res.Policy.ID, res.Policy.Version, res.Policy.Hash)
	}
	if res.Governance != nil {
		fmt.Printf("  governance: allowed=%d denied=%d reverted=%d revert_failed=%d\n",
			res.Governance.Allowed, res.Governance.Denied, res.Governance.Reverted, res.Governance.RevertFailed)
	}
	if res.Evidence != nil {
		fmt.Printf("  evidence:   %s\n", res.Evidence.RunDir)
	}
	if res.Verify != nil {
		fmt.Printf("  verify:     %s\n", res.Verify.Status)
	}
	if res.Child != nil {
		fmt.Printf("  child:      exit=%d command=%q\n", res.Child.ExitCode, strings.Join(res.Child.Command, " "))
	}
	if res.Error != "" {
		fmt.Printf("  error:      %s\n", res.Error)
	}
	fmt.Printf("  exit_code:  %d\n", res.ExitCode)
}

// ciExitCodeFor derives the exit-code contract from a governance summary and
// (for `ci exec`) the governed child's own exit code, applying the precedence
// documented on the Exit* constants above.
func ciExitCodeFor(gov *ciGovernance, childExitCode *int) int {
	if gov != nil {
		if gov.RevertFailed > 0 {
			return ExitCIRevertFailed
		}
		if gov.Denied > 0 {
			return ExitCIPolicyViolation
		}
	}
	if childExitCode != nil && *childExitCode != 0 {
		return ExitCIWorkloadFailed
	}
	return ExitCISuccess
}

// ciLifecycle is the CI-layer-only ownership marker at <workspace>/.airlock/
// ci.json. It is not part of the evidence schema (runmeta.RunManifest,
// events.Event, etc. are all untouched) -- it exists purely so `ci status`
// and `ci finalize` can answer "which session is this CI lifecycle
// responsible for" without guessing, and so a second `ci finalize` call is a
// safe, deterministic no-op instead of re-running the stop sequence.
type ciLifecycle struct {
	SessionID   string     `json:"session_id"`
	PID         int        `json:"pid"`
	Workspace   string     `json:"workspace"`
	Owned       bool       `json:"owned"` // true: this lifecycle started the session; false: attached via --attach-existing
	StartedAt   time.Time  `json:"started_at"`
	Status      string     `json:"status"` // "running" | "finalized"
	FinalizedAt *time.Time `json:"finalized_at,omitempty"`
	// LastResult caches the exact result finalize produced, so a repeated
	// `ci finalize` call (e.g. from a CI "always" cleanup block that already
	// ran once) returns the identical answer instead of re-deriving it.
	LastResult *ciSchema `json:"last_result,omitempty"`
}

func ciLifecyclePath(repoAbs string) string {
	return filepath.Join(repoAbs, ".airlock", "ci.json")
}

func readCILifecycle(repoAbs string) (ciLifecycle, bool, error) {
	var l ciLifecycle
	b, err := os.ReadFile(ciLifecyclePath(repoAbs))
	if err != nil {
		if os.IsNotExist(err) {
			return l, false, nil
		}
		return l, false, fmt.Errorf("read ci lifecycle metadata: %w", err)
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return l, false, fmt.Errorf("parse ci lifecycle metadata (%s): %w", ciLifecyclePath(repoAbs), err)
	}
	return l, true, nil
}

func writeCILifecycle(repoAbs string, l ciLifecycle) error {
	if err := os.MkdirAll(filepath.Join(repoAbs, ".airlock"), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ciLifecyclePath(repoAbs), b, 0o644)
}

// resolveCIWorkspace validates --workspace the same way Sentinel resolves
// --repo (sentinel.go:131, plain filepath.Abs), plus an explicit existence/
// directory check so a typo'd path fails immediately with a clear error
// instead of surfacing later as a confusing recorder/session failure.
func resolveCIWorkspace(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve workspace path %q: %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("workspace %q: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("workspace %q is not a directory", abs)
	}
	return abs, nil
}

type ciEvidenceLoad struct {
	Manifest runmeta.RunManifest
	Events   []events.Event
}

// loadSessionEvidence reads a session's manifest/events directly from an
// absolute run directory, deliberately bypassing runmeta.LoadArtifacts (which
// assumes the process's cwd is the workspace root, per
// internal/runmeta/loader.go) since `ci` subcommands operate on an arbitrary
// --workspace, not necessarily the process's cwd.
func loadSessionEvidence(repoAbs, sessionID string) (ciEvidenceLoad, string, error) {
	runDir := filepath.Join(repoAbs, ".airlock", "runs", sessionID)
	manifestPath := filepath.Join(runDir, "run_manifest.json")
	eventsPath := filepath.Join(runDir, "events.jsonl")
	m, err := runmeta.Load(manifestPath)
	if err != nil {
		return ciEvidenceLoad{}, runDir, fmt.Errorf("load manifest for session %s: %w", sessionID, err)
	}
	evs, err := events.ReadJSONL(eventsPath)
	if err != nil {
		return ciEvidenceLoad{}, runDir, fmt.Errorf("load events for session %s: %w", sessionID, err)
	}
	return ciEvidenceLoad{Manifest: m, Events: evs}, runDir, nil
}

func ciEvidencePaths(runDir string) *ciEvidence {
	return &ciEvidence{
		RunDir:   runDir,
		Events:   filepath.Join(runDir, "events.jsonl"),
		Manifest: filepath.Join(runDir, "run_manifest.json"),
		Digest:   filepath.Join(runDir, "run_digest.json"),
		Report:   filepath.Join(runDir, "report", "index.html"),
	}
}

func ciGovernanceFromEvents(evs []events.Event) *ciGovernance {
	allow, deny, reverted, revertFailed, lastAt := governanceCounters(evs)
	return &ciGovernance{Allowed: allow, Denied: deny, Reverted: reverted, RevertFailed: revertFailed, LastEventAt: lastAt}
}

// policyIdentityFromManifest mirrors (*sentinelSession).policyIdentity's
// non-Fleet branch (sentinel.go:1072) using what a manifest already recorded
// on disk, so `ci status`/`ci finalize` can derive the same policy id/
// version/hash for a session whose live *sentinelSession object may no
// longer exist (process already stopped).
func policyIdentityFromManifest(m runmeta.RunManifest) (id, version, hash string) {
	id = "local"
	if m.PolicyPack.Name != "" {
		id = m.PolicyPack.Name
		version = m.PolicyPack.Version
	}
	b, _ := json.Marshal(m.PolicySummary)
	sum := sha256.Sum256(b)
	hash = hex.EncodeToString(sum[:])[:16]
	return id, version, hash
}

// fleetPolicyOverride prefers a Fleet-managed policy identity (kept fresh in
// fleet-status.json independent of the manifest, see sentinel_trust.go) over
// the locally-derived one, mirroring policyIdentity()'s own precedence.
func fleetPolicyOverride(res *ciSchema, repoAbs string) {
	st, ok := loadFleetStatus(repoAbs)
	if !ok {
		return
	}
	res.Fleet = &st
	if st.PolicyID != "" {
		res.Policy = &ciPolicy{ID: st.PolicyID, Version: fmt.Sprintf("%d", st.PolicyVersion), Hash: st.PolicyHash}
	}
}

// shellOutVerify reuses the existing `airlock verify <id> --json` command
// exactly as an external caller would, rather than duplicating
// runmeta.VerifyRun's logic -- that function hardcodes ".airlock/runs/<id>"
// relative to the process's own cwd (internal/runmeta/verify.go:27), which
// does not hold for an arbitrary --workspace. Running the real binary with
// its working directory set to repoAbs sidesteps that without touching this
// process's own cwd or reimplementing verification.
func shellOutVerify(repoAbs, sessionID string) (*runmeta.VerifyResult, error) {
	self, err := ciSelfExe()
	if err != nil {
		return nil, fmt.Errorf("cannot locate airlock binary for verify: %w", err)
	}
	cmd := exec.Command(self, "verify", sessionID, "--json")
	cmd.Dir = repoAbs
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("airlock verify failed: %w", err)
	}
	var res runmeta.VerifyResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("parse verify output: %w", err)
	}
	return &res, nil
}

// writeCIEnvFile writes AIRLOCK_* values as shell-consumable KEY=VALUE lines.
// It never writes secrets/tokens. A child process cannot export environment
// variables into its parent's shell, so this is deliberately a file the
// caller must `source` themselves -- documented at the --env-file flag and in
// docs/ci-integration.md, never claimed to happen automatically.
func writeCIEnvFile(path string, res *ciSchema) error {
	var b strings.Builder
	fmt.Fprintf(&b, "AIRLOCK_SESSION_ID=%s\n", res.SessionID)
	fmt.Fprintf(&b, "AIRLOCK_SENTINEL_ID=%s\n", res.SentinelID)
	fmt.Fprintf(&b, "AIRLOCK_WORKSPACE=%s\n", res.Workspace)
	if res.Evidence != nil {
		fmt.Fprintf(&b, "AIRLOCK_EVIDENCE_DIR=%s\n", res.Evidence.RunDir)
	}
	if res.Policy != nil {
		fmt.Fprintf(&b, "AIRLOCK_POLICY_HASH=%s\n", res.Policy.Hash)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func ciCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Embed Sentinel's governance lifecycle into an existing workflow (CI/CD pipelines, scripts, containers)",
		Long: `airlock ci orchestrates the existing Sentinel lifecycle (start/status/finalize)
around a workflow Airlock does not launch -- Jenkins, Buildkite, GitLab
runners, Docker, Kubernetes, or a plain shell script. It does not add a new
enforcement engine: every allow/deny/revert decision is still made by the
same detect -> evaluate -> revert Sentinel described in SECURITY.md.`,
	}
	cmd.AddCommand(ciStartCmd())
	cmd.AddCommand(ciStatusCmd())
	cmd.AddCommand(ciFinalizeCmd())
	cmd.AddCommand(ciExecCmd())
	return cmd
}
