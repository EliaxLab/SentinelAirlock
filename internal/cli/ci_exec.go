package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
	"github.com/spf13/cobra"
)

func ciExecCmd() *cobra.Command {
	var (
		workspacePath string
		policyPath    string
		policyPack    string
		fo            fleetOptions
		asJSON        bool
	)
	cmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Convenience: start Sentinel, run one command against the workspace, finalize, and report",
		Long: `ci exec is convenience-only: unlike 'ci start'/'ci finalize', Airlock owns
the child process's lifecycle here, the same way 'airlock run' owns its
adapter's lifecycle. It builds directly on the same startSentinelSession used
by 'airlock sentinel' and by 'ci start' -- it does not reimplement or share
code with 'airlock run', and it never attaches to a Sentinel this invocation
did not start itself. The command to run must follow "--" so its own flags
are never parsed as Airlock's.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repoAbs, err := resolveCIWorkspace(workspacePath)
			if err != nil {
				return ciFinish(ciErrorResult("exec", workspacePath, err), asJSON)
			}

			if meta, running := runningSentinel(repoAbs); running {
				return ciFinish(ciErrorResult("exec", repoAbs, fmt.Errorf(
					"a Sentinel (pid %d, session %s) is already governing %s; 'ci exec' owns its lifecycle end-to-end "+
						"and will not attach to an existing one -- use 'ci start'/'ci finalize' around your own step instead",
					meta.PID, meta.Session, repoAbs)), asJSON)
			}

			sess, err := startSentinelSession(repoAbs, policyPath, policyPack, false, fo)
			if err != nil {
				return ciFinish(ciErrorResult("exec", repoAbs, fmt.Errorf("start sentinel: %w", err)), asJSON)
			}

			ctx, cancel := context.WithCancel(context.Background())
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				cancel()
			}()

			child := exec.CommandContext(ctx, args[0], args[1:]...)
			child.Dir = repoAbs
			child.Stdout = os.Stdout
			if asJSON {
				child.Stdout = os.Stderr // keep stdout a single parseable JSON document
			}
			child.Stderr = os.Stderr
			child.Stdin = os.Stdin
			runErr := child.Run()
			signal.Stop(sigCh)
			cancel()

			// Evidence is always finalized, whether the child succeeded,
			// failed, or was cancelled by a signal -- mirrors ci finalize's
			// guarantee that a run's evidence is never left half-written.
			sess.shutdown()

			ev, runDir, loadErr := loadSessionEvidence(repoAbs, sess.sessionID)
			if loadErr != nil {
				return ciFinish(ciErrorResult("exec", repoAbs, fmt.Errorf("load finalized evidence: %w", loadErr)), asJSON)
			}
			id, version, hash := policyIdentityFromManifest(ev.Manifest)
			gov := ciGovernanceFromEvents(ev.Events)
			childExit := exitCodeOf(runErr)

			res := &ciSchema{
				SchemaVersion: ciSchemaVersion, Command: "exec", Status: "finalized",
				Workspace: repoAbs, Owned: true, SessionID: sess.sessionID,
				Policy:     &ciPolicy{ID: id, Version: version, Hash: hash},
				Governance: gov,
				Evidence:   ciEvidencePaths(runDir),
				Child:      &ciChild{Command: args, ExitCode: childExit},
			}
			if runErr != nil && childExit < 0 {
				res.Child.Error = runErr.Error()
			}
			if runErr != nil && childExit < 0 {
				res.Child.Error = runErr.Error()
			}
			if sentinelID, err := fleet.SentinelID(repoAbs); err == nil {
				res.SentinelID = sentinelID
			}
			fleetPolicyOverride(res, repoAbs)
			if verifyRes, err := shellOutVerify(repoAbs, sess.sessionID); err == nil {
				res.Verify = verifyRes
			}
			res.ExitCode = ciExitCodeFor(gov, &childExit)

			return ciFinish(res, asJSON)
		},
	}
	cmd.Flags().StringVar(&workspacePath, "workspace", ".", "Path to the workspace to govern")
	cmd.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path, resolved relative to --workspace unless absolute")
	cmd.Flags().StringVar(&policyPack, "policy-pack", "", "Policy pack to apply (strict, balanced, oss-maintainer, ci-safe, research)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit a structured JSON result on stdout")
	cmd.Flags().StringVar(&fo.URL, "fleet", "", "Airlock Fleet control plane URL to enroll with and heartbeat to (optional)")
	cmd.Flags().StringVar(&fo.Token, "fleet-token", "", "Shared operator token for the fleet control plane, if required")
	cmd.Flags().StringVar(&fo.EnrollToken, "fleet-enroll-token", "", "One-time enrollment token (first enrollment only)")
	cmd.Flags().StringVar(&fo.PublicKey, "fleet-pubkey", "", "Pin the control plane's policy signing key explicitly")
	cmd.Flags().StringVar(&fo.CACert, "fleet-ca", "", "PEM bundle to trust for an https:// control plane behind a private CA")
	return cmd
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
