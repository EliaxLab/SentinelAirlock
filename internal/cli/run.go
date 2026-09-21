package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/adapters"
	"github.com/EliaxLab/SentinelAirlock/internal/agents"
	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/execution"
	"github.com/EliaxLab/SentinelAirlock/internal/gitops"
	"github.com/EliaxLab/SentinelAirlock/internal/governance"
	"github.com/EliaxLab/SentinelAirlock/internal/output"
	"github.com/EliaxLab/SentinelAirlock/internal/policy"
	"github.com/EliaxLab/SentinelAirlock/internal/policypack"
	"github.com/EliaxLab/SentinelAirlock/internal/recorder"
	"github.com/EliaxLab/SentinelAirlock/internal/report"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/EliaxLab/SentinelAirlock/internal/session"
	"github.com/EliaxLab/SentinelAirlock/internal/util"
	"github.com/EliaxLab/SentinelAirlock/internal/workspace"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func runCmd() *cobra.Command {
	var (
		repoPath          string
		agentName         string
		agentCmd          string
		task              string
		policyPath        string
		approval          string
		sandboxMode       string
		sandboxImage      string
		networkMode       string
		allowEnvCSV       string
		containerRuntime  string
		fallbackWorkspace bool
		allowDomains      []string
		policyPack        string
		executionMode     string
		printEffective    bool
		timeoutSec        int
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run an agent adapter inside a controlled workspace and generate replay artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoPath = util.DefaultIfEmpty(repoPath, ".")
			policyPath = util.DefaultIfEmpty(policyPath, "airlock.yaml")
			approval = util.DefaultIfEmpty(approval, string(governance.ApprovalAuto))
			sandboxMode = util.DefaultIfEmpty(sandboxMode, string(execution.ModeWorkspace))
			networkMode = util.DefaultIfEmpty(networkMode, string(execution.NetworkOff))
			executionMode = util.DefaultIfEmpty(executionMode, "dev")

			if approval != string(governance.ApprovalAuto) && approval != string(governance.ApprovalPrompt) && approval != string(governance.ApprovalDenyHighRisk) {
				return fmt.Errorf("invalid --approval value: %s", approval)
			}
			if agentName == "generic-shell" && strings.TrimSpace(agentCmd) == "" {
				return fmt.Errorf("generic-shell requires --cmd")
			}
			if executionMode != "dev" && executionMode != "team" && executionMode != "ci" {
				return fmt.Errorf("invalid --mode value: %s", executionMode)
			}

			cfg, cfgErr := policy.Load(policyPath)
			if cfgErr != nil {
				fmt.Printf("WARN: could not load %s (%v). Running with built-in ignores.\n", policyPath, cfgErr)
			}
			if !cmd.Flags().Changed("agent") && cfg != nil && strings.TrimSpace(cfg.Defaults.Agent) != "" {
				agentName = cfg.Defaults.Agent
			}
			agentName = util.DefaultIfEmpty(agentName, "generic-shell")
			if !cmd.Flags().Changed("mode") && cfg != nil && strings.TrimSpace(cfg.Defaults.Mode) != "" {
				executionMode = cfg.Defaults.Mode
			}
			if !cmd.Flags().Changed("policy-pack") && cfg != nil && strings.TrimSpace(cfg.Defaults.PolicyPack) != "" {
				policyPack = cfg.Defaults.PolicyPack
			}
			if !cmd.Flags().Changed("sandbox") && cfg != nil && strings.TrimSpace(cfg.Defaults.Sandbox) != "" {
				sandboxMode = cfg.Defaults.Sandbox
			}

			selectedPack, err := resolvePolicyPack(policyPack, executionMode, cmd.Flags().Changed("policy-pack"))
			if err != nil {
				return err
			}
			if selectedPack != nil {
				packCfg, err := policypack.ParseConfig(*selectedPack)
				if err != nil {
					return err
				}
				cfg = policypack.Merge(cfg, packCfg)
				policyPack = selectedPack.Name
			}

			applyModeDefaults(cmd.Flags(), executionMode, &sandboxMode, &networkMode, &approval)
			if cfg != nil && networkMode == string(execution.NetworkOff) && cfg.Network.Mode != "" {
				networkMode = cfg.Network.Mode
			}

			// Resolved once, up front, so every downstream system (adapter cwd,
			// mutation recorder, checkpoint source, patch diff, manifest) agrees
			// on the same execution root instead of each guessing independently.
			mode := execution.ParseMode(sandboxMode)
			repoAbs, err := filepath.Abs(repoPath)
			if err != nil {
				return fmt.Errorf("could not resolve --repo %q: %w", repoPath, err)
			}

			effectiveCfg := map[string]any{
				"policy_pack":       policyPack,
				"execution_mode":    executionMode,
				"approval":          approval,
				"sandbox":           sandboxMode,
				"network":           networkMode,
				"allow_env":         parseCSV(allowEnvCSV),
				"allow_domains":     allowDomains,
				"container_runtime": containerRuntime,
				"policy_path":       policyPath,
			}
			if printEffective {
				b, _ := json.MarshalIndent(effectiveCfg, "", "  ")
				fmt.Println(string(b))
			}

			registry := adapters.NewRegistry()
			adapter, err := registry.Resolve(agentName)
			if err != nil {
				diag := agents.Diagnose(agentName)
				if !diag.Installed {
					return fmt.Errorf("%w\nhint: adapter %q is unavailable. %s. try: ./airlock agents install-hints or use --agent generic-shell", err, agentName, diag.Hint)
				}
				return err
			}
			adapterDiag := agents.Diagnose(agentName)

			runID := strings.TrimSpace(os.Getenv("AIRLOCK_RUN_ID_FORCE"))
			if runID == "" {
				runID = uuid.New().String()
			}
			runsDir := filepath.Join(".airlock", "runs", runID)
			wsDir := filepath.Join(".airlock", "workspaces", runID, "repo")
			if err := os.MkdirAll(runsDir, 0o755); err != nil {
				return err
			}

			logger, err := events.NewLogger(filepath.Join(runsDir, "events.jsonl"))
			if err != nil {
				return err
			}
			defer logger.Close()
			sessionSink, err := session.NewSink(filepath.Join(runsDir, "session_events.jsonl"))
			if err != nil {
				return err
			}
			defer sessionSink.Close()

			logger.Add(events.Event{TS: time.Now().UTC(), Type: "RUN_START", Summary: fmt.Sprintf("adapter=%q repo=%q task=%q", agentName, repoPath, task), Meta: map[string]any{"run_id": runID}})
			if strings.EqualFold(os.Getenv("AIRLOCK_EXEC_TARGET"), "remote") {
				logger.Add(events.Event{TS: time.Now().UTC(), Type: "REMOTE_ACCEPTED", Summary: "remote worker accepted run"})
				logger.Add(events.Event{TS: time.Now().UTC(), Type: "REMOTE_EXEC_START", Summary: "remote worker execution started"})
			}
			logger.Add(events.Event{TS: time.Now().UTC(), Type: "ADAPTER_SELECTED", Summary: "adapter selected", Meta: map[string]any{"name": adapter.Name(), "capabilities": capabilityMap(adapter.Capabilities())}})

			ignore := []string{".git/**", ".airlock/**", "node_modules/**"}
			if cfg != nil && len(cfg.Workspace.Ignore) > 0 {
				ignore = cfg.Workspace.Ignore
			}

			// executionRoot is the single directory every downstream system
			// (adapter cwd, mutation recorder, patch diff, rollback target)
			// treats as "the thing being governed":
			//   workspace/container -> the staged .airlock/workspaces/<run>/repo copy
			//   off                 -> the real --repo, in place, unstaged
			// Internal Airlock storage (.airlock/runs/<run>/...) is separate from
			// this and is never the governed target itself.
			executionRoot := selectExecutionRoot(mode, repoAbs, wsDir)
			checkpointSrc := wsDir
			checkpointIgnore := []string(nil) // wsDir is already filtered by the copy above
			if mode == execution.ModeOff {
				checkpointSrc = repoAbs
				checkpointIgnore = ignore // repoAbs is unfiltered; apply ignores now
			} else {
				if err := workspace.CopyRepo(repoPath, wsDir, ignore); err != nil {
					return err
				}
			}

			checkpointPath := filepath.Join(runsDir, "checkpoints", "cp-0")
			if err := workspace.CopyRepo(checkpointSrc, checkpointPath, checkpointIgnore); err != nil {
				return err
			}
			logger.Add(events.Event{TS: time.Now().UTC(), Type: "CHECKPOINT_CREATED", Summary: "checkpoint captured", Meta: map[string]any{"id": "cp-0", "path": checkpointPath}})

			runCtx := adapters.RunContext{RunID: runID, WorkspacePath: executionRoot, RepoPath: repoAbs, Task: task, ApprovalMode: approval, Environment: adapters.BaseEnv(task), AdapterName: adapter.Name(), Command: agentCmd, SessionSink: sessionSink}
			inv, err := adapter.Prepare(runCtx)
			if err != nil {
				return err
			}
			logger.Add(events.Event{TS: time.Now().UTC(), Type: "ADAPTER_PREPARED", Summary: "adapter invocation prepared", Meta: map[string]any{"display_command": inv.DisplayCommand, "executable": inv.Executable, "args": inv.Args}})

			netMode := execution.ParseNetworkMode(networkMode)
			selectedRuntime := execution.Runtime(containerRuntime)
			if selectedRuntime == "" {
				selectedRuntime = execution.RuntimeAuto
			}
			fallbackUsed := false
			if mode == execution.ModeContainer {
				if rtInfo, rtErr := execution.DetectRuntime(selectedRuntime); rtErr != nil || !rtInfo.Available || !rtInfo.CanAccess {
					if fallbackWorkspace {
						fallbackUsed = true
						mode = execution.ModeWorkspace
						logger.Add(events.Event{TS: time.Now().UTC(), Type: "SANDBOX_FALLBACK", Summary: "container unavailable; downgraded to workspace sandbox", Meta: map[string]any{"requested_mode": "container", "runtime": string(selectedRuntime), "hint": rtInfo.Hint}})
					} else {
						hint := ""
						if rtInfo.Hint != "" {
							hint = " " + rtInfo.Hint
						}
						return fmt.Errorf("container sandbox unavailable:%s", hint)
					}
				} else {
					selectedRuntime = rtInfo.Name
					logger.Add(events.Event{TS: time.Now().UTC(), Type: "SANDBOX_RUNTIME_SELECTED", Summary: "container runtime selected", Meta: map[string]any{"runtime": string(selectedRuntime), "socket": rtInfo.SocketPath}})
				}
			}
			allowEnv := parseCSV(allowEnvCSV)
			allowDomainSet := map[string]struct{}{}
			if cfg != nil {
				for _, d := range cfg.Network.Allowlist {
					d = strings.TrimSpace(strings.ToLower(d))
					if d != "" {
						allowDomainSet[d] = struct{}{}
					}
				}
			}
			for _, d := range allowDomains {
				d = strings.TrimSpace(strings.ToLower(d))
				if d != "" {
					allowDomainSet[d] = struct{}{}
				}
			}
			mergedAllowDomains := mapKeysSorted(allowDomainSet)
			logger.Add(events.Event{TS: time.Now().UTC(), Type: "SANDBOX_SELECTED", Summary: "sandbox selected", Meta: map[string]any{"mode": string(mode), "image": sandboxImage, "runtime": string(selectedRuntime), "fallback_used": fallbackUsed}})
			logger.Add(events.Event{TS: time.Now().UTC(), Type: "SANDBOX_NETWORK", Summary: "sandbox network mode", Meta: map[string]any{"mode": string(netMode)}})
			if netMode == execution.NetworkAllowlist && mode != execution.ModeContainer {
				logger.Add(events.Event{TS: time.Now().UTC(), Type: "SANDBOX_NETWORK_UNSUPPORTED", Summary: "allowlist unsupported for non-container sandbox", Meta: map[string]any{"mode": string(mode)}})
			}

			evalSensitiveDenials(logger, inv.DisplayCommand)
			envDenied := deniedEnv(adapters.BaseEnv(task), allowEnv)
			for i, k := range envDenied {
				if i >= 20 {
					break
				}
				logger.Add(events.Event{TS: time.Now().UTC(), Type: "ENV_DENY", Summary: "env variable excluded from sandbox", Meta: map[string]any{"key": k}})
			}

			cmdRisk := governance.ClassifyCommand(inv.DisplayCommand)
			cmdDecision := governance.Decide(governance.ApprovalMode(approval), cmdRisk)
			logger.Add(events.Event{TS: time.Now().UTC(), Type: "CMD", Summary: "agent command", Meta: map[string]any{"cmd": inv.DisplayCommand, "task": task, "repo": repoPath}, Risk: map[string]any{"level": string(cmdRisk.Level), "category": string(cmdRisk.Category), "reason": cmdRisk.Reason}, Approval: map[string]any{"mode": approval, "decision": string(cmdDecision)}})

			rec, err := recorder.New(executionRoot, logger, cfg, governance.ApprovalMode(approval))
			if err != nil {
				return err
			}
			// Seed the before-state cache so a denied write to a file that
			// already existed in executionRoot (e.g. modified via
			// --sandbox off, or already present in the staged workspace
			// copy) reverts to its real prior content instead of being
			// deleted outright.
			if err := rec.Seed(); err != nil {
				return err
			}
			if err := rec.Start(); err != nil {
				return err
			}

			exitCode := 0
			out := ""
			var runErr error
			if cmdDecision != governance.DecisionAllow {
				exitCode = 1
				runErr = fmt.Errorf("command blocked by approval mode: %s", cmdDecision)
			} else {
				if netMode == execution.NetworkAllowlist {
					domains := extractDomains(inv.DisplayCommand)
					for _, d := range domains {
						if containsString(mergedAllowDomains, d) {
							logger.Add(events.Event{TS: time.Now().UTC(), Type: "NET_ALLOW", Summary: "domain allowed by network policy", Meta: map[string]any{"domain": d}})
						} else {
							logger.Add(events.Event{TS: time.Now().UTC(), Type: "NET_DENY", Summary: "domain blocked by network allowlist", Meta: map[string]any{"domain": d}})
							exitCode = 1
							runErr = fmt.Errorf("network allowlist denied domain: %s", d)
							break
						}
					}
				}
				if runErr == nil {
					sessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MODEL_INFO", Meta: map[string]any{"provider": adapter.Name(), "model": adapter.Name(), "config": map[string]any{"sandbox": string(mode), "network": string(netMode)}}})
					if task != "" {
						sessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MSG_USER", Content: task})
					}
					sessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "TOOL_CALL", Content: inv.DisplayCommand})
					exitCode, out, runErr = execution.Run(inv, adapters.BaseEnv(task), execution.Options{Mode: mode, Image: sandboxImage, Network: netMode, AllowEnvKeys: allowEnv, ContainerRuntime: selectedRuntime, FallbackWorkspace: fallbackWorkspace, AllowDomains: mergedAllowDomains, TimeoutSec: timeoutSec})
					sessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "TOOL_RESULT", Content: out, Meta: map[string]any{"exit_code": exitCode}})
					if runErr == nil {
						sessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MSG_ASSISTANT", Content: out})
					}
					sessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "SESSION_SUMMARY", Content: "session complete", Meta: map[string]any{"exit_code": exitCode}})
				}
			}
			logger.Add(events.Event{TS: time.Now().UTC(), Type: "AGENT_STDOUT", Summary: "agent output", Meta: map[string]any{"stdout": out}})

			// The command has exited, but fsnotify delivery is asynchronous —
			// its last write(s) may not have reached the recorder's goroutine
			// yet. Stopping immediately can silently drop trailing events
			// (including a denial that should have been reverted). Give the
			// OS/recorder a short bounded window to catch up before tearing
			// the watcher down.
			time.Sleep(150 * time.Millisecond)
			_ = rec.Stop()

			evs := logger.EventsSnapshot()
			patchPath := ""
			// For in-place runs, repoAbs/executionRoot IS the mutated target, so
			// the "before" side of the diff must be the pre-run checkpoint, not
			// the (unchanged, staged-mode-only) original --repo.
			patchOrig, patchNew := repoPath, wsDir
			if mode == execution.ModeOff {
				patchOrig, patchNew = checkpointPath, executionRoot
			}
			patchBytes, patchErr := gitops.CreatePatchForPaths(patchOrig, patchNew, changedPathsFromEvents(evs))
			if patchErr != nil {
				logger.Add(events.Event{TS: time.Now().UTC(), Type: "PATCH_ERROR", Summary: "failed to generate patch", Meta: map[string]any{"error": patchErr.Error()}})
			} else {
				patchPath = filepath.Join(runsDir, "changes.patch")
				if err := os.WriteFile(patchPath, patchBytes, 0o644); err != nil {
					logger.Add(events.Event{TS: time.Now().UTC(), Type: "PATCH_ERROR", Summary: "failed to write patch", Meta: map[string]any{"error": err.Error()}})
				} else {
					logger.Add(events.Event{TS: time.Now().UTC(), Type: "PATCH_READY", Summary: "patch generated", Meta: map[string]any{"path": patchPath}})
				}
			}

			failureClass, failureReason := "", ""
			if runErr != nil {
				failureClass, failureReason = classifyFailure(runErr)
				evType := "RUN_FAILED"
				if failureClass == "timeout" {
					evType = "RUN_TIMEOUT"
				} else if failureClass == "cancelled" {
					evType = "RUN_CANCELLED"
				}
				logger.Add(events.Event{TS: time.Now().UTC(), Type: evType, Summary: "run failed", Meta: map[string]any{"class": failureClass, "reason": failureReason}})
			}
			if strings.EqualFold(os.Getenv("AIRLOCK_EXEC_TARGET"), "remote") {
				logger.Add(events.Event{TS: time.Now().UTC(), Type: "REMOTE_EXEC_END", Summary: "remote worker execution completed", Meta: map[string]any{"exit_code": exitCode}})
			}
			endEv := events.Event{TS: time.Now().UTC(), Type: "RUN_END", Summary: "agent finished", Meta: map[string]any{"exit_code": exitCode}}
			if runErr != nil {
				endEv.Meta["error"] = runErr.Error()
			}
			logger.Add(endEv)

			manifest := runmeta.RunManifest{
				RunID:           runID,
				WorkspacePath:   executionRoot,
				PolicySummary:   runmeta.BuildPolicySummary(policyPath, cfg),
				ExecutionMode:   executionMode,
				TouchedPaths:    touchedPathsFromEvents(logger.EventsSnapshot()),
				DeniedPaths:     deniedPathsFromEvents(logger.EventsSnapshot()),
				PatchPath:       patchPath,
				Checkpoints:     []runmeta.Checkpoint{{ID: "cp-0", Path: checkpointPath}},
				RiskSummary:     riskSummaryFromEvents(logger.EventsSnapshot()),
				ApprovalSummary: approvalSummaryFromEvents(logger.EventsSnapshot()),
				Adapter:         runmeta.AdapterSummary{Name: adapter.Name(), Readiness: string(adapterDiag.Status), Version: adapterDiag.Version, Capabilities: capabilityMap(adapter.Capabilities())},
				Invocation:      runmeta.InvocationSummary{DisplayCommand: inv.DisplayCommand},
				Sandbox:         runmeta.SandboxInfo{Mode: string(mode), Image: sandboxImage, Runtime: string(selectedRuntime), FallbackUsed: fallbackUsed},
				Network:         runmeta.NetworkInfo{Mode: string(netMode), Allowlist: mergedAllowDomains, DenyCount: countType(logger.EventsSnapshot(), "NET_DENY"), AllowCount: countType(logger.EventsSnapshot(), "NET_ALLOW")},
				Env:             runmeta.EnvInfo{Allowed: allowEnv, Denied: envDenied},
				SandboxSummary:  sandboxSummaryFromEvents(logger.EventsSnapshot(), mode),
				Digest:          runmeta.DigestInfo{Path: filepath.Join(runsDir, "run_digest.json")},
				EffectiveConfig: effectiveCfg,
				Status: runmeta.RunStatus{
					Terminal:      ternary(runErr == nil, "success", "failed"),
					FailureClass:  failureClass,
					FailureReason: failureReason,
					TimeoutSec:    timeoutSec,
				},
				Product: runmeta.ProductInfo{Version: Version, Commit: Commit, BuildDate: BuildDate},
			}
			manifest.Execution = runmeta.ExecutionInfo{
				Target:        envOrDefault("AIRLOCK_EXEC_TARGET", "local"),
				WorkerName:    strings.TrimSpace(os.Getenv("AIRLOCK_EXEC_WORKER_NAME")),
				WorkerID:      strings.TrimSpace(os.Getenv("AIRLOCK_EXEC_WORKER_ID")),
				SubmittedBy:   strings.TrimSpace(os.Getenv("AIRLOCK_SUBMITTED_BY")),
				SourceMachine: strings.TrimSpace(os.Getenv("AIRLOCK_SOURCE_MACHINE")),
			}
			if cfg != nil && strings.TrimSpace(cfg.Team.Name) != "" {
				manifest.Team = runmeta.TeamInfo{Name: strings.TrimSpace(cfg.Team.Name)}
			}
			if selectedPack != nil {
				manifest.PolicyPack = runmeta.PolicyPackInfo{Name: selectedPack.Name, Version: selectedPack.Version, Source: selectedPack.Source}
			}
			signer, sigErr := prepareDigestSigner(cfg, manifest.Digest.Path)
			if sigErr != nil {
				return sigErr
			}
			if signer != nil {
				manifest.Digest.Signed = true
				manifest.Digest.SignaturePath = signer.sigPath
				manifest.Digest.SigningKeyID = signer.keyID
			}
			if err := runmeta.Save(filepath.Join(runsDir, "run_manifest.json"), manifest); err != nil {
				return err
			}
			digestPath := manifest.Digest.Path
			logger.Add(events.Event{TS: time.Now().UTC(), Type: "RUN_DIGEST_READY", Summary: "run digest generated", Meta: map[string]any{"path": digestPath}})
			if signer != nil {
				logger.Add(events.Event{TS: time.Now().UTC(), Type: "RUN_DIGEST_SIGNED", Summary: "run digest signed", Meta: map[string]any{"path": signer.sigPath, "key_id": signer.keyID}})
			}
			digest, dgErr := runmeta.BuildDigest(runID, runsDir)
			if dgErr == nil && runmeta.SaveDigest(digestPath, digest) == nil {
				if signer != nil {
					if err := signDigestFile(digestPath, signer); err != nil {
						return err
					}
				}
			}
			if err := report.Generate(runsDir, logger.EventsSnapshot()); err != nil {
				return err
			}

			artifacts, loadErr := runmeta.LoadArtifacts(runID)
			if loadErr == nil {
				output.PrintRunSummary(artifacts, approval, executionMode)
			} else {
				fmt.Printf("Run complete\nRun ID: %s\nReport: %s\nManifest: %s\n", runID, filepath.Join(runsDir, "report", "index.html"), filepath.Join(runsDir, "run_manifest.json"))
			}
			refreshIndex()
			if runErr != nil {
				return runErr
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&repoPath, "repo", ".", "Path to repo/workdir")
	cmd.Flags().StringVar(&agentName, "agent", "generic-shell", "Adapter name (e.g. generic-shell, codex, ollama)")
	cmd.Flags().StringVar(&agentCmd, "cmd", "", "Command for generic-shell adapter")
	cmd.Flags().StringVar(&task, "task", "", "Optional task string")
	cmd.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path")
	cmd.Flags().StringVar(&approval, "approval", string(governance.ApprovalAuto), "Approval mode: auto | prompt | deny-high-risk")
	cmd.Flags().StringVar(&sandboxMode, "sandbox", string(execution.ModeWorkspace), "Sandbox mode: off | workspace | container")
	cmd.Flags().StringVar(&sandboxImage, "sandbox-image", "", "Container image for --sandbox container")
	cmd.Flags().StringVar(&networkMode, "network", string(execution.NetworkOff), "Network mode: off | on | allowlist")
	cmd.Flags().StringVar(&allowEnvCSV, "allow-env", "", "Comma-separated env keys to pass into container sandbox")
	cmd.Flags().StringVar(&containerRuntime, "container-runtime", string(execution.RuntimeAuto), "Container runtime: auto | docker | colima | podman")
	cmd.Flags().BoolVar(&fallbackWorkspace, "fallback-workspace", false, "Fallback to workspace sandbox when container runtime is unavailable")
	cmd.Flags().StringSliceVar(&allowDomains, "allow-domain", nil, "Allowed network domains (repeatable, used with --network allowlist)")
	cmd.Flags().StringVar(&policyPack, "policy-pack", "", "Policy pack to apply (strict, balanced, oss-maintainer, ci-safe, research)")
	cmd.Flags().StringVar(&executionMode, "mode", "dev", "Execution mode defaults: dev | team | ci")
	cmd.Flags().BoolVar(&printEffective, "print-effective-config", false, "Print effective merged config before running")
	cmd.Flags().IntVar(&timeoutSec, "timeout-sec", 0, "Execution timeout in seconds (0 disables timeout)")
	return cmd
}

// selectExecutionRoot picks the single directory that every downstream
// system (adapter cwd, mutation recorder, patch diff, checkpoint,
// rollback target) treats as "the thing being governed" for this run.
// workspace and container modes are intentionally identical here — both
// execute against the staged .airlock/workspaces/<run>/repo copy. Only
// sandbox=off diverges: it governs the real --repo directly, in place.
func selectExecutionRoot(mode execution.Mode, repoAbs, wsDir string) string {
	if mode == execution.ModeOff {
		return repoAbs
	}
	return wsDir
}

func capabilityMap(c adapters.CapabilitySet) map[string]any {
	return map[string]any{
		"supports_task_arg":           c.SupportsTaskArg,
		"supports_env_task":           c.SupportsEnvTask,
		"supports_streaming_output":   c.SupportsStreamingOutput,
		"supports_native_events":      c.SupportsNativeEvents,
		"supports_native_checkpoints": c.SupportsNativeCheckpoints,
		"supports_native_diff":        c.SupportsNativeDiff,
		"supports_native_approval":    c.SupportsNativeApproval,
	}
}

func applyModeDefaults(flags interface{ Changed(string) bool }, mode string, sandboxMode, networkMode, approval *string) {
	switch mode {
	case "team":
		if !flags.Changed("sandbox") {
			*sandboxMode = string(execution.ModeContainer)
		}
		if !flags.Changed("network") {
			*networkMode = string(execution.NetworkAllowlist)
		}
		if !flags.Changed("approval") {
			*approval = string(governance.ApprovalDenyHighRisk)
		}
	case "ci":
		if !flags.Changed("sandbox") {
			*sandboxMode = string(execution.ModeContainer)
		}
		if !flags.Changed("network") {
			*networkMode = string(execution.NetworkOff)
		}
		if !flags.Changed("approval") {
			*approval = string(governance.ApprovalDenyHighRisk)
		}
	default:
		if !flags.Changed("sandbox") {
			*sandboxMode = string(execution.ModeWorkspace)
		}
		if !flags.Changed("network") {
			*networkMode = string(execution.NetworkOff)
		}
	}
}

func resolvePolicyPack(packName, mode string, explicit bool) (*policypack.Pack, error) {
	name := strings.TrimSpace(packName)
	if name == "" && !explicit {
		switch mode {
		case "team":
			name = "strict"
		case "ci":
			name = "ci-safe"
		default:
			name = "balanced"
		}
	}
	if name == "" {
		return nil, nil
	}
	p, err := policypack.Get(name)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

type digestSigner struct {
	priv    ed25519.PrivateKey
	keyID   string
	sigPath string
}

func prepareDigestSigner(cfg *policy.Config, digestPath string) (*digestSigner, error) {
	keyPath := strings.TrimSpace(os.Getenv("AIRLOCK_SIGNING_KEY"))
	keyID := strings.TrimSpace(os.Getenv("AIRLOCK_SIGNING_KEY_ID"))
	if keyPath == "" && cfg != nil {
		keyPath = strings.TrimSpace(cfg.Signing.PrivateKey)
		if keyID == "" {
			keyID = strings.TrimSpace(cfg.Signing.KeyID)
		}
	}
	if keyPath == "" {
		return nil, nil
	}
	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	sigPath := filepath.Join(filepath.Dir(digestPath), "run_digest.sig")
	if keyID == "" {
		pub := priv.Public().(ed25519.PublicKey)
		keyHash := sha256.Sum256(pub)
		keyID = hex.EncodeToString(keyHash[:8])
	}
	return &digestSigner{priv: priv, keyID: keyID, sigPath: sigPath}, nil
}

func signDigestFile(digestPath string, signer *digestSigner) error {
	digestBytes, err := os.ReadFile(digestPath)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(digestBytes)
	sig := ed25519.Sign(signer.priv, hash[:])
	return os.WriteFile(signer.sigPath, []byte(hex.EncodeToString(sig)), 0o644)
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if raw, err := hex.DecodeString(s); err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw), nil
		}
		if len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw), nil
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw), nil
		}
		if len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw), nil
		}
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func parseCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := []string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func deniedEnv(env []string, allow []string) []string {
	allowSet := map[string]struct{}{"AIRLOCK_TASK": {}}
	for _, k := range allow {
		allowSet[k] = struct{}{}
	}
	out := []string{}
	seen := map[string]struct{}{}
	for _, kv := range env {
		i := strings.Index(kv, "=")
		if i <= 0 {
			continue
		}
		k := kv[:i]
		if _, ok := allowSet[k]; !ok {
			if _, exists := seen[k]; !exists {
				seen[k] = struct{}{}
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

func evalSensitiveDenials(logger *events.Logger, displayCmd string) {
	lc := strings.ToLower(displayCmd)
	if strings.Contains(lc, ".env") {
		logger.Add(events.Event{TS: time.Now().UTC(), Type: "SECRET_DENY", Summary: "sensitive secret path referenced", Meta: map[string]any{"match": ".env"}})
	}
	if strings.Contains(lc, ".ssh") || strings.Contains(lc, ".aws") || strings.Contains(lc, ".git") {
		logger.Add(events.Event{TS: time.Now().UTC(), Type: "PATH_DENY", Summary: "sensitive path referenced", Meta: map[string]any{"command": displayCmd}})
	}
}

func changedPathsFromEvents(evs []events.Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		if e.Path == "" {
			continue
		}
		if strings.HasPrefix(e.Type, "FILE_") || e.Type == "POLICY_DENY" || e.Type == "APPROVAL_REQUIRED" {
			out = append(out, e.Path)
		}
	}
	return out
}

func touchedPathsFromEvents(evs []events.Event) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, e := range evs {
		if e.Path == "" {
			continue
		}
		if !strings.HasPrefix(e.Type, "FILE_") && e.Type != "POLICY_DENY" && e.Type != "APPROVAL_REQUIRED" {
			continue
		}
		if _, ok := seen[e.Path]; ok {
			continue
		}
		seen[e.Path] = struct{}{}
		out = append(out, e.Path)
	}
	sort.Strings(out)
	return out
}

func deniedPathsFromEvents(evs []events.Event) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, e := range evs {
		if (e.Type != "POLICY_DENY" && e.Type != "APPROVAL_REQUIRED") || e.Path == "" {
			continue
		}
		if _, ok := seen[e.Path]; ok {
			continue
		}
		seen[e.Path] = struct{}{}
		out = append(out, e.Path)
	}
	sort.Strings(out)
	return out
}

func riskSummaryFromEvents(evs []events.Event) runmeta.RiskSummary {
	out := runmeta.RiskSummary{}
	for _, e := range evs {
		level, _ := e.Risk["level"].(string)
		switch level {
		case "low":
			out.LowCount++
		case "medium":
			out.MediumCount++
		case "high":
			out.HighCount++
		}
	}
	return out
}

func approvalSummaryFromEvents(evs []events.Event) runmeta.ApprovalSummary {
	out := runmeta.ApprovalSummary{}
	for _, e := range evs {
		decision, _ := e.Approval["decision"].(string)
		switch decision {
		case "allow":
			out.ApprovedCount++
		case "prompt":
			out.PromptedCount++
		case "deny":
			out.DeniedCount++
		}
	}
	return out
}

func sandboxSummaryFromEvents(evs []events.Event, mode execution.Mode) runmeta.SandboxSummary {
	out := runmeta.SandboxSummary{}
	switch mode {
	case execution.ModeContainer:
		out.ContainerModeRuns = 1
	case execution.ModeWorkspace:
		out.WorkspaceModeRuns = 1
	default:
		out.HostModeRuns = 1
	}
	for _, e := range evs {
		switch e.Type {
		case "SECRET_DENY":
			out.SecretDenials++
		case "PATH_DENY":
			out.PathDenials++
		case "ENV_DENY":
			out.EnvDenials++
		}
	}
	return out
}

func mapKeysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func extractDomains(s string) []string {
	re := regexp.MustCompile(`https?://[^\s'"]+`)
	matches := re.FindAllString(s, -1)
	set := map[string]struct{}{}
	for _, m := range matches {
		u, err := url.Parse(m)
		if err != nil || u.Hostname() == "" {
			continue
		}
		set[strings.ToLower(u.Hostname())] = struct{}{}
	}
	return mapKeysSorted(set)
}

func countType(evs []events.Event, t string) int {
	n := 0
	for _, e := range evs {
		if e.Type == t {
			n++
		}
	}
	return n
}

func envOrDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func classifyFailure(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "deadline exceeded") || strings.Contains(s, "timeout"):
		return "timeout", err.Error()
	case strings.Contains(s, "signal: killed") || strings.Contains(s, "interrupt"):
		return "cancelled", err.Error()
	case strings.Contains(s, "network"):
		return "network", err.Error()
	case strings.Contains(s, "container"):
		return "sandbox", err.Error()
	case strings.Contains(s, "approval") || strings.Contains(s, "policy"):
		return "policy", err.Error()
	default:
		return "adapter", err.Error()
	}
}

func ternary(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}
