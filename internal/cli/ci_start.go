package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
	"github.com/spf13/cobra"
)

func ciStartCmd() *cobra.Command {
	var (
		workspacePath  string
		policyPath     string
		policyPack     string
		fo             fleetOptions
		attachExisting bool
		asJSON         bool
		envFile        string
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start (or attach to) Sentinel governance for a workspace, without launching the workload",
		Long: `ci start brings up the same background Sentinel 'airlock sentinel' does
(detect -> evaluate -> revert against the real workspace filesystem) and
records which session this CI lifecycle owns in <workspace>/.airlock/ci.json.
It never launches your build/test/deploy step itself -- run that separately,
then call 'airlock ci finalize' when it's done.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repoAbs, err := resolveCIWorkspace(workspacePath)
			if err != nil {
				return ciFinish(ciErrorResult("start", workspacePath, err), asJSON)
			}

			existing, running := runningSentinel(repoAbs)
			lifecycle, hasLifecycle, err := readCILifecycle(repoAbs)
			if err != nil {
				return ciFinish(ciErrorResult("start", repoAbs, err), asJSON)
			}

			owned := true
			switch {
			case !running:
				// The reused helper prints human progress to stdout; keep
				// stdout a single machine-readable document.
				realStdout := os.Stdout
				os.Stdout = os.Stderr
				startErr := startSentinelBackground(repoAbs, policyPath, policyPack, fo)
				os.Stdout = realStdout
				if startErr != nil {
					err := startErr
					return ciFinish(ciErrorResult("start", repoAbs, fmt.Errorf("start sentinel: %w", err)), asJSON)
				}
			case hasLifecycle && lifecycle.Status == "running" && lifecycle.SessionID == existing.Session:
				// Idempotent: a prior `ci start` already brought this exact
				// session up. Re-emit the same answer rather than erroring.
				owned = lifecycle.Owned
			case attachExisting:
				owned = false
			default:
				return ciFinish(ciErrorResult("start", repoAbs, fmt.Errorf(
					"a Sentinel (pid %d, session %s) is already governing %s outside this CI lifecycle; "+
						"pass --attach-existing to govern it read-only, or stop it first with "+
						"'airlock sentinel --repo %s --stop'", existing.PID, existing.Session, repoAbs, repoAbs)), asJSON)
			}

			meta, ok := runningSentinel(repoAbs)
			if !ok {
				return ciFinish(ciErrorResult("start", repoAbs, fmt.Errorf("sentinel did not report ready after start")), asJSON)
			}

			if err := writeCILifecycle(repoAbs, ciLifecycle{
				SessionID: meta.Session,
				PID:       meta.PID,
				Workspace: repoAbs,
				Owned:     owned,
				StartedAt: time.Now().UTC(),
				Status:    "running",
			}); err != nil {
				return ciFinish(ciErrorResult("start", repoAbs, fmt.Errorf("record ci lifecycle: %w", err)), asJSON)
			}

			res := &ciSchema{
				SchemaVersion: ciSchemaVersion,
				Command:       "start",
				Status:        "running",
				Workspace:     repoAbs,
				Owned:         owned,
				SessionID:     meta.Session,
				PID:           meta.PID,
				StartedAt:     meta.Started,
				Evidence:      ciEvidencePaths(filepath.Join(repoAbs, ".airlock", "runs", meta.Session)),
				ExitCode:      ExitCISuccess,
			}
			if sentinelID, err := fleet.SentinelID(repoAbs); err == nil {
				res.SentinelID = sentinelID
			}
			if ev, _, err := loadSessionEvidence(repoAbs, meta.Session); err == nil {
				id, version, hash := policyIdentityFromManifest(ev.Manifest)
				res.Policy = &ciPolicy{ID: id, Version: version, Hash: hash}
			}
			fleetPolicyOverride(res, repoAbs)

			if envFile != "" {
				if err := writeCIEnvFile(envFile, res); err != nil {
					return ciFinish(ciErrorResult("start", repoAbs, fmt.Errorf("write env file: %w", err)), asJSON)
				}
			}

			return ciFinish(res, asJSON)
		},
	}
	cmd.Flags().StringVar(&workspacePath, "workspace", ".", "Path to the workspace to govern")
	cmd.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path, resolved relative to --workspace unless absolute")
	cmd.Flags().StringVar(&policyPack, "policy-pack", "", "Policy pack to apply (strict, balanced, oss-maintainer, ci-safe, research)")
	cmd.Flags().BoolVar(&attachExisting, "attach-existing", false, "Govern an already-running Sentinel read-only instead of starting a new one")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit a structured JSON result on stdout")
	cmd.Flags().StringVar(&envFile, "env-file", "", "Write AIRLOCK_* values as KEY=VALUE lines to this path; the caller must source it themselves (never auto-exported into a parent shell)")
	cmd.Flags().StringVar(&fo.URL, "fleet", "", "Airlock Fleet control plane URL to enroll with and heartbeat to (optional)")
	cmd.Flags().StringVar(&fo.Token, "fleet-token", "", "Shared operator token for the fleet control plane, if required")
	cmd.Flags().StringVar(&fo.EnrollToken, "fleet-enroll-token", "", "One-time enrollment token (first enrollment only)")
	cmd.Flags().StringVar(&fo.PublicKey, "fleet-pubkey", "", "Pin the control plane's policy signing key explicitly")
	cmd.Flags().StringVar(&fo.CACert, "fleet-ca", "", "PEM bundle to trust for an https:// control plane behind a private CA")
	return cmd
}
