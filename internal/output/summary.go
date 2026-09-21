package output

import (
	"fmt"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

func PrintRunSummary(a runmeta.Artifacts, approvalMode string, executionMode string) {
	fmt.Println("Run complete")
	fmt.Printf("Run ID: %s\n", a.RunID)
	fmt.Printf("Workspace: %s\n", a.Manifest.WorkspacePath)
	if executionMode != "" {
		fmt.Printf("Mode: %s\n", executionMode)
	}
	if a.Manifest.Execution.Target != "" {
		fmt.Printf("Target: %s\n", a.Manifest.Execution.Target)
	}
	if a.Manifest.Execution.WorkerName != "" {
		fmt.Printf("Worker: %s\n", a.Manifest.Execution.WorkerName)
	}
	if a.Manifest.PolicyPack.Name != "" {
		fmt.Printf("Policy pack: %s@%s (%s)\n", a.Manifest.PolicyPack.Name, a.Manifest.PolicyPack.Version, a.Manifest.PolicyPack.Source)
	}
	if a.Manifest.Adapter.Name != "" {
		fmt.Printf("Adapter: %s", a.Manifest.Adapter.Name)
		if a.Manifest.Adapter.Version != "" {
			fmt.Printf(" (%s)", a.Manifest.Adapter.Version)
		}
		if a.Manifest.Adapter.Readiness != "" {
			fmt.Printf(" readiness=%s", a.Manifest.Adapter.Readiness)
		}
		fmt.Println()
	}
	if a.Manifest.Sandbox.Mode != "" {
		fmt.Printf("Sandbox: %s", a.Manifest.Sandbox.Mode)
		if a.Manifest.Sandbox.Runtime != "" {
			fmt.Printf(" (runtime=%s", a.Manifest.Sandbox.Runtime)
			if a.Manifest.Sandbox.FallbackUsed {
				fmt.Printf(", fallback=true")
			}
			fmt.Printf(")")
		}
		fmt.Println()
		if a.Manifest.Sandbox.Mode == "off" {
			fmt.Println("Execution: in-place")
			fmt.Printf("Execution root: %s\n", a.Manifest.WorkspacePath)
		}
	}
	if a.Manifest.Network.Mode != "" {
		fmt.Printf("Network: %s (allowlist=%d deny=%d)\n", a.Manifest.Network.Mode, len(a.Manifest.Network.Allowlist), a.Manifest.Network.DenyCount)
	}
	fmt.Printf("Env allowlist: %d\n", len(a.Manifest.Env.Allowed))
	fmt.Printf("Approval mode: %s\n", approvalMode)
	fmt.Printf("Risk summary: low=%d medium=%d high=%d\n",
		a.Manifest.RiskSummary.LowCount, a.Manifest.RiskSummary.MediumCount, a.Manifest.RiskSummary.HighCount)
	fmt.Printf("Approval summary: approved=%d prompted=%d denied=%d\n",
		a.Manifest.ApprovalSummary.ApprovedCount, a.Manifest.ApprovalSummary.PromptedCount, a.Manifest.ApprovalSummary.DeniedCount)
	fmt.Printf("Touched paths: %d\n", len(a.Manifest.TouchedPaths))
	fmt.Printf("Denied paths: %d\n", len(a.Manifest.DeniedPaths))
	fmt.Printf("Checkpoints: %d\n", len(a.Manifest.Checkpoints))
	if a.Manifest.PatchPath != "" {
		fmt.Printf("Patch: %s\n", a.Manifest.PatchPath)
	} else {
		fmt.Println("Patch: <none>")
	}
	fmt.Printf("Report: %s\n", a.ReportPath)
	if a.Manifest.Digest.Path != "" {
		fmt.Printf("Digest: %s\n", a.Manifest.Digest.Path)
		if a.Manifest.Digest.Signed {
			fmt.Printf("Signature: %s\n", a.Manifest.Digest.SignaturePath)
		}
	}
	if a.Manifest.Status.Terminal != "" {
		fmt.Printf("Status: %s", a.Manifest.Status.Terminal)
		if a.Manifest.Status.FailureClass != "" {
			fmt.Printf(" class=%s", a.Manifest.Status.FailureClass)
		}
		fmt.Println()
	}
	fmt.Printf("Manifest: %s\n", a.ManifestPath)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  ./airlock inspect %s\n", a.RunID)
	fmt.Printf("  ./airlock replay %s --tail 20\n", a.RunID)
	fmt.Printf("  ./airlock review %s --state approved --note \"reviewed\"\n", a.RunID)
	fmt.Printf("  ./airlock verify %s\n", a.RunID)
	fmt.Printf("  ./airlock export %s --format zip\n", a.RunID)
	fmt.Println("  ./airlock serve --read-only")
	fmt.Println()
	fmt.Println("  Tip: use 'latest' as a shorthand for any of the above, e.g.:")
	fmt.Println("    ./airlock inspect latest")
}

func PrintInspectSummary(a runmeta.Artifacts) {
	fmt.Printf("Run ID: %s\n", a.RunID)
	fmt.Printf("Workspace: %s\n", a.Manifest.WorkspacePath)
	if a.Manifest.Execution.Target != "" {
		fmt.Printf("Target: %s\n", a.Manifest.Execution.Target)
	}
	if a.Manifest.Execution.WorkerName != "" {
		fmt.Printf("Worker: %s\n", a.Manifest.Execution.WorkerName)
	}
	if a.Manifest.ExecutionMode != "" {
		fmt.Printf("Mode: %s\n", a.Manifest.ExecutionMode)
	}
	if a.Manifest.PolicyPack.Name != "" {
		fmt.Printf("Policy pack: %s@%s (%s)\n", a.Manifest.PolicyPack.Name, a.Manifest.PolicyPack.Version, a.Manifest.PolicyPack.Source)
	}
	if a.Manifest.Adapter.Name != "" {
		fmt.Printf("Adapter: %s", a.Manifest.Adapter.Name)
		if a.Manifest.Adapter.Version != "" {
			fmt.Printf(" (%s)", a.Manifest.Adapter.Version)
		}
		if a.Manifest.Adapter.Readiness != "" {
			fmt.Printf(" readiness=%s", a.Manifest.Adapter.Readiness)
		}
		fmt.Println()
	}
	if a.Manifest.Sandbox.Mode != "" {
		fmt.Printf("Sandbox: %s", a.Manifest.Sandbox.Mode)
		if a.Manifest.Sandbox.Runtime != "" {
			fmt.Printf(" (runtime=%s", a.Manifest.Sandbox.Runtime)
			if a.Manifest.Sandbox.FallbackUsed {
				fmt.Printf(", fallback=true")
			}
			fmt.Printf(")")
		}
		fmt.Println()
		if a.Manifest.Sandbox.Mode == "off" {
			fmt.Println("Execution: in-place")
			fmt.Printf("Execution root: %s\n", a.Manifest.WorkspacePath)
		}
	}
	if a.Manifest.Network.Mode != "" {
		fmt.Printf("Network: %s (allowlist=%d deny=%d)\n", a.Manifest.Network.Mode, len(a.Manifest.Network.Allowlist), a.Manifest.Network.DenyCount)
	}
	fmt.Printf("Env allowlist: %d\n", len(a.Manifest.Env.Allowed))
	cmd, task, approvalMode := commandTaskMode(a.Events)
	if cmd != "" {
		fmt.Printf("Command: %s\n", cmd)
	}
	if task != "" {
		fmt.Printf("Task: %s\n", task)
	}
	if approvalMode != "" {
		fmt.Printf("Approval mode: %s\n", approvalMode)
	}
	fmt.Printf("Risk summary: low=%d medium=%d high=%d\n",
		a.Manifest.RiskSummary.LowCount, a.Manifest.RiskSummary.MediumCount, a.Manifest.RiskSummary.HighCount)
	fmt.Printf("Approval summary: approved=%d prompted=%d denied=%d\n",
		a.Manifest.ApprovalSummary.ApprovedCount, a.Manifest.ApprovalSummary.PromptedCount, a.Manifest.ApprovalSummary.DeniedCount)
	fmt.Printf("Touched paths: %s\n", strings.Join(a.Manifest.TouchedPaths, ", "))
	fmt.Printf("Denied paths: %s\n", strings.Join(a.Manifest.DeniedPaths, ", "))
	fmt.Printf("Checkpoints: %d\n", len(a.Manifest.Checkpoints))
	if a.Manifest.PatchPath != "" {
		fmt.Printf("Patch: %s\n", a.Manifest.PatchPath)
	} else {
		fmt.Println("Patch: <none>")
	}
	fmt.Printf("Report: %s\n", a.ReportPath)
	if a.Manifest.Digest.Path != "" {
		fmt.Printf("Digest: %s\n", a.Manifest.Digest.Path)
		if a.Manifest.Digest.Signed {
			fmt.Printf("Signature: %s\n", a.Manifest.Digest.SignaturePath)
		}
	}
	if a.Manifest.Export.Path != "" {
		fmt.Printf("Export: %s (%s)\n", a.Manifest.Export.Path, a.Manifest.Export.Format)
	}
	fmt.Printf("Latest status: %s\n", latestStatus(a.Events))
}

func commandTaskMode(evs []events.Event) (string, string, string) {
	for _, e := range evs {
		if e.Type != "CMD" {
			continue
		}
		cmd, _ := e.Meta["cmd"].(string)
		task, _ := e.Meta["task"].(string)
		mode, _ := e.Approval["mode"].(string)
		return cmd, task, mode
	}
	return "", "", ""
}

func latestStatus(evs []events.Event) string {
	sentinelStarted := false
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		switch e.Type {
		case "SENTINEL_START":
			sentinelStarted = true
			continue
		case "SENTINEL_STOP":
			return "sentinel stopped"
		case "RUN_END":
		default:
			continue
		}
		if errStr, ok := e.Meta["error"].(string); ok && errStr != "" {
			return "failed: " + errStr
		}
		return "success"
	}
	if sentinelStarted {
		return "sentinel active"
	}
	return "unknown"
}
