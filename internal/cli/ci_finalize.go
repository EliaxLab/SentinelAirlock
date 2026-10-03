package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
	"github.com/EliaxLab/SentinelAirlock/internal/index"
	"github.com/EliaxLab/SentinelAirlock/internal/report"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

func ciFinalizeCmd() *cobra.Command {
	var workspacePath string
	var sessionOverride string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "finalize",
		Short: "Deterministically stop (if owned) and report the governance result for a CI lifecycle",
		Long: `ci finalize is idempotent and safe to call from a CI "always"/"post" cleanup
block: a second call re-emits the exact result the first call produced
instead of re-running the stop sequence. If this lifecycle owns the Sentinel
session it stops it (via the same path 'airlock sentinel --stop' uses); if it
only attached to one (--attach-existing at start), it snapshots evidence
without stopping anything.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repoAbs, err := resolveCIWorkspace(workspacePath)
			if err != nil {
				return ciFinish(ciErrorResult("finalize", workspacePath, err), asJSON)
			}

			lifecycle, hasLifecycle, err := readCILifecycle(repoAbs)
			if err != nil {
				return ciFinish(ciErrorResult("finalize", repoAbs, err), asJSON)
			}
			if !hasLifecycle {
				if strings.TrimSpace(sessionOverride) == "" {
					return ciFinish(ciErrorResult("finalize", repoAbs, fmt.Errorf(
						"no CI lifecycle recorded for %s (no prior 'airlock ci start' found here); "+
							"pass --session <id> to recover after ci.json was lost", repoAbs)), asJSON)
				}
				meta, running := runningSentinel(repoAbs)
				lifecycle = ciLifecycle{
					SessionID: sessionOverride,
					Workspace: repoAbs,
					Owned:     running && meta.Session == sessionOverride,
					Status:    "running",
				}
			}

			if lifecycle.Status == "finalized" && lifecycle.LastResult != nil {
				cached := *lifecycle.LastResult
				cached.Command = "finalize"
				return ciFinish(&cached, asJSON)
			}

			meta, running := runningSentinel(repoAbs)
			cleanStop := true
			switch {
			case running && meta.Session == lifecycle.SessionID && lifecycle.Owned:
				realStdout := os.Stdout
				os.Stdout = os.Stderr // reused helper prints human text; keep stdout pure JSON
				stopErr := sentinelStopCmd(repoAbs)
				os.Stdout = realStdout
				if err := stopErr; err != nil {
					return ciFinish(ciErrorResult("finalize", repoAbs, fmt.Errorf("stop sentinel: %w", err)), asJSON)
				}
			case running && meta.Session == lifecycle.SessionID && !lifecycle.Owned:
				// Attached, not owned: report a snapshot, never stop it.
			case running && meta.Session != lifecycle.SessionID:
				return ciFinish(ciErrorResult("finalize", repoAbs, fmt.Errorf(
					"a different Sentinel session (%s) is now running for %s than the one this CI lifecycle started (%s); refusing to touch it",
					meta.Session, repoAbs, lifecycle.SessionID)), asJSON)
			default:
				// Nothing running: an unclean stop (crash, kill -9, or a
				// `sentinel --stop` that bypassed this lifecycle). Evidence
				// on disk is finalized defensively -- the same idempotent
				// steps (*sentinelSession).shutdown always runs -- rather
				// than trusted as already-consistent.
				cleanStop = false
				runDir := filepath.Join(repoAbs, ".airlock", "runs", lifecycle.SessionID)
				if !runmeta.Exists(filepath.Join(runDir, "run_manifest.json")) {
					return ciFinish(ciErrorResult("finalize", repoAbs, fmt.Errorf(
						"no evidence found for session %s under %s; nothing to finalize", lifecycle.SessionID, runDir)), asJSON)
				}
				if digest, err := runmeta.BuildDigest(lifecycle.SessionID, runDir); err == nil {
					_ = runmeta.SaveDigest(filepath.Join(runDir, "run_digest.json"), digest)
				}
				if evs, err := events.ReadJSONL(filepath.Join(runDir, "events.jsonl")); err == nil {
					_ = report.Generate(runDir, evs)
				}
				if store, err := index.Rebuild(filepath.Join(repoAbs, ".airlock", "runs")); err == nil {
					_ = index.Save(filepath.Join(repoAbs, ".airlock", "index.json"), store)
				}
			}

			ev, runDir, err := loadSessionEvidence(repoAbs, lifecycle.SessionID)
			if err != nil {
				return ciFinish(ciErrorResult("finalize", repoAbs, fmt.Errorf("load finalized evidence: %w", err)), asJSON)
			}
			id, version, hash := policyIdentityFromManifest(ev.Manifest)
			gov := ciGovernanceFromEvents(ev.Events)

			status := "finalized"
			if !cleanStop {
				status = "finalized_after_crash"
			}

			res := &ciSchema{
				SchemaVersion: ciSchemaVersion, Command: "finalize", Status: status,
				Workspace: repoAbs, Owned: lifecycle.Owned, SessionID: lifecycle.SessionID,
				Policy:     &ciPolicy{ID: id, Version: version, Hash: hash},
				Governance: gov,
				Evidence:   ciEvidencePaths(runDir),
			}
			if sentinelID, err := fleet.SentinelID(repoAbs); err == nil {
				res.SentinelID = sentinelID
			}
			fleetPolicyOverride(res, repoAbs)
			if verifyRes, err := shellOutVerify(repoAbs, lifecycle.SessionID); err == nil {
				res.Verify = verifyRes
			}
			res.ExitCode = ciExitCodeFor(gov, nil)
			if !cleanStop {
				// The enforcement boundary stopped existing before finalize:
				// writes after the crash were never governed, so this must
				// not read as a clean result no matter what was recorded.
				res.ExitCode = ExitCIInternalError
				res.Error = "sentinel was not running at finalize; governance was not continuous for this session (evidence covers only the period before it stopped)"
			}

			finalizedAt := time.Now().UTC()
			resultCopy := *res
			lifecycle.Status = "finalized"
			lifecycle.FinalizedAt = &finalizedAt
			lifecycle.LastResult = &resultCopy
			if err := writeCILifecycle(repoAbs, lifecycle); err != nil {
				return ciFinish(ciErrorResult("finalize", repoAbs, fmt.Errorf("record finalize result: %w", err)), asJSON)
			}

			return ciFinish(res, asJSON)
		},
	}
	cmd.Flags().StringVar(&workspacePath, "workspace", ".", "Path to the workspace to finalize")
	cmd.Flags().StringVar(&sessionOverride, "session", "", "Explicit session ID to finalize if ci.json is missing (e.g. after a crash)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit a structured JSON result on stdout")
	return cmd
}
