package cli

import (
	"fmt"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
	"github.com/spf13/cobra"
)

func ciStatusCmd() *cobra.Command {
	var workspacePath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report the current Sentinel/CI-lifecycle state for a workspace",
		Long: `ci status is purely observational: it never starts, stops, or otherwise
mutates anything. It answers "what is the CI lifecycle for this workspace
doing right now" by combining the live process state ('airlock sentinel'
liveness) with the .airlock/ci.json ownership marker and, if a session
exists, its on-disk evidence.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repoAbs, err := resolveCIWorkspace(workspacePath)
			if err != nil {
				return ciFinish(ciErrorResult("status", workspacePath, err), asJSON)
			}

			lifecycle, hasLifecycle, err := readCILifecycle(repoAbs)
			if err != nil {
				return ciFinish(ciErrorResult("status", repoAbs, err), asJSON)
			}
			if !hasLifecycle {
				res := &ciSchema{
					SchemaVersion: ciSchemaVersion, Command: "status", Status: "not_started",
					Workspace: repoAbs, ExitCode: ExitCISuccess,
				}
				return ciFinish(res, asJSON)
			}

			if lifecycle.Status == "finalized" && lifecycle.LastResult != nil {
				cached := *lifecycle.LastResult
				cached.Command = "status"
				return ciFinish(&cached, asJSON)
			}

			meta, running := runningSentinel(repoAbs)
			status := "stopped_unclean"
			pid := lifecycle.PID
			startedAt := lifecycle.StartedAt.Format(time.RFC3339)
			switch {
			case running && meta.Session == lifecycle.SessionID:
				status = "running"
				pid = meta.PID
				startedAt = meta.Started
			case running && meta.Session != lifecycle.SessionID:
				status = "conflict"
			}

			res := &ciSchema{
				SchemaVersion: ciSchemaVersion, Command: "status", Status: status,
				Workspace: repoAbs, Owned: lifecycle.Owned, SessionID: lifecycle.SessionID,
				PID: pid, StartedAt: startedAt, ExitCode: ExitCISuccess,
			}
			if sentinelID, err := fleet.SentinelID(repoAbs); err == nil {
				res.SentinelID = sentinelID
			}
			if ev, runDir, err := loadSessionEvidence(repoAbs, lifecycle.SessionID); err == nil {
				id, version, hash := policyIdentityFromManifest(ev.Manifest)
				res.Policy = &ciPolicy{ID: id, Version: version, Hash: hash}
				res.Evidence = ciEvidencePaths(runDir)
				res.Governance = ciGovernanceFromEvents(ev.Events)
			} else if status != "not_started" {
				res.Error = fmt.Sprintf("evidence unavailable: %v", err)
			}
			fleetPolicyOverride(res, repoAbs)

			return ciFinish(res, asJSON)
		},
	}
	cmd.Flags().StringVar(&workspacePath, "workspace", ".", "Path to the workspace to inspect")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit a structured JSON result on stdout")
	return cmd
}
