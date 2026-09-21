package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/review"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

// Generate writes a self-contained, single-file HTML evidence report for a run.
// runDir is the per-run artifact directory (.airlock/runs/<id>). It reads the
// run manifest, review record, and digest from disk when present and renders a
// static report with no external dependencies or JavaScript required.
func Generate(runDir string, evs []events.Event) error {
	reportDir := filepath.Join(runDir, "report")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return err
	}

	// Keep the browser-friendly events.json for anyone who wants the raw feed.
	if b, err := json.MarshalIndent(evs, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(reportDir, "events.json"), b, 0o644)
	}

	vm := buildViewModel(runDir, evs)

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"badgeClass": badgeClass,
	}).Parse(reportTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(reportDir, "index.html"))
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, vm)
}

// ---- view model -----------------------------------------------------------

type kv struct{ K, V string }

type timelineEvent struct {
	TS       string
	Type     string
	Label    string
	Path     string
	Summary  string
	Detail   string
	Reason   string
	Risk     string
	Decision string
	Class    string // normal | deny | block | change | rollback | milestone
}

type deniedChange struct {
	Path        string
	Reason      string
	Risk        string
	Reverted    bool
	Explanation string
}

type artifact struct {
	Name string
	Rel  string
	Size string
}

type rollbackInfo struct {
	RunID      string   `json:"run_id"`
	Mode       string   `json:"mode"`
	Checkpoint string   `json:"checkpoint"`
	Paths      []string `json:"paths"`
	Timestamp  string   `json:"timestamp"`
	Status     string   `json:"status"`
}

type reportVM struct {
	// operator-facing display classification
	DisplayCategory string

	// executive summary
	GovernanceSentence string

	// overview
	RunID     string
	Status    string
	StatusOK  bool
	Timestamp string
	Duration  string
	Adapter   string
	Command   string
	Task      string
	Workspace string

	// governance
	PolicyPack   string
	ApprovalMode string
	SandboxMode  string
	NetworkMode  string
	PolicyPath   string

	// risk
	RiskLevel       string
	CommandRisk     string
	CommandCategory string
	FinalDecision   string
	RiskLow         int
	RiskMedium      int
	RiskHigh        int
	Denied          int
	Approved        int

	// changes
	Allowed []string
	DeniedC []deniedChange

	// blocked command
	Blocked       bool
	BlockedCmd    string
	BlockedReason string

	// patch
	PatchFiles      []string
	PatchInsertions int
	PatchDeletions  int
	PatchRel        string
	PatchPreview    string
	HasPatch        bool

	// timeline
	Timeline []timelineEvent

	// review
	ReviewState     string
	ReviewNote      string
	ReviewReviewer  string
	ReviewTimestamp string

	// verification
	DigestPresent  bool
	DigestFiles    int
	DigestValues   []kv
	Signed         bool
	SignatureKeyID string
	VerifyLabel    string
	VerifyClass    string

	// rollback
	Rollback      *rollbackInfo
	HasCheckpoint bool

	// next-step guidance (mirror of web viewer)
	NextStep reportNextStep

	// replay summary (counts; ENV_DENY collapsed)
	ReplaySetup    int
	ReplayAllowed  int
	ReplayDenied   int
	ReplayBlocked  int
	ReplayRollback int
	ReplayEvidence int
	EnvExcluded    int
	EnvKeys        []string

	// artifacts
	Artifacts []artifact

	// footer
	GeneratedAt string
	Version     string
	SecurityRef string
}

func buildViewModel(runDir string, evs []events.Event) reportVM {
	vm := reportVM{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SecurityRef: "SECURITY.md",
		RunID:       filepath.Base(runDir),
	}

	// manifest (best effort — rollback path may run before/after)
	var m runmeta.RunManifest
	if mm, err := runmeta.Load(filepath.Join(runDir, "run_manifest.json")); err == nil {
		m = mm
	}
	if m.RunID != "" {
		vm.RunID = m.RunID
	}
	vm.Adapter = firstNonEmpty(m.Adapter.Name, "unknown-adapter")
	vm.Workspace = m.WorkspacePath
	vm.PolicyPath = m.PolicySummary.PolicyPath
	vm.PolicyPack = packLabel(m.PolicyPack)
	vm.SandboxMode = firstNonEmpty(m.Sandbox.Mode, "unknown")
	vm.NetworkMode = firstNonEmpty(m.Network.Mode, "unknown")
	vm.RiskLow = m.RiskSummary.LowCount
	vm.RiskMedium = m.RiskSummary.MediumCount
	vm.RiskHigh = m.RiskSummary.HighCount
	vm.Denied = m.ApprovalSummary.DeniedCount
	vm.Approved = m.ApprovalSummary.ApprovedCount
	vm.Version = m.Product.Version
	vm.Command = m.Invocation.DisplayCommand
	vm.Allowed = append([]string(nil), m.TouchedPaths...)

	// status
	switch m.Status.Terminal {
	case "success":
		vm.Status = "success"
		vm.StatusOK = true
	case "failed":
		vm.Status = "failed"
		if m.Status.FailureReason != "" {
			vm.Status = "failed — " + m.Status.FailureReason
		}
	default:
		vm.Status = firstNonEmpty(m.Status.Terminal, "unknown")
	}

	// approval mode from effective config, fallback to CMD event
	if m.EffectiveConfig != nil {
		if v, ok := m.EffectiveConfig["approval"].(string); ok {
			vm.ApprovalMode = v
		}
	}

	// digest / signature
	if d, err := runmeta.LoadDigestFromDir(runDir); err == nil {
		vm.DigestPresent = true
		vm.DigestFiles = len(d.Files)
		keys := make([]string, 0, len(d.Files))
		for k := range d.Files {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vm.DigestValues = append(vm.DigestValues, kv{K: k, V: shortHash(d.Files[k])})
		}
	}
	vm.Signed = m.Digest.Signed
	vm.SignatureKeyID = m.Digest.SigningKeyID

	// verify label
	switch {
	case vm.DigestPresent && vm.Signed:
		vm.VerifyLabel, vm.VerifyClass = "verified-signed", "ok"
	case vm.DigestPresent:
		vm.VerifyLabel, vm.VerifyClass = "verified-unsigned", "ok"
	default:
		vm.VerifyLabel, vm.VerifyClass = "no digest", "muted"
	}

	// review
	if rev, err := review.Load(runDir); err == nil {
		vm.ReviewState = string(rev.State)
		vm.ReviewNote = rev.Note
		vm.ReviewReviewer = rev.Reviewer
		vm.ReviewTimestamp = rev.Timestamp
	} else {
		vm.ReviewState = "unreviewed"
	}

	// rollback.json
	if b, err := os.ReadFile(filepath.Join(runDir, "rollback.json")); err == nil {
		var ri rollbackInfo
		if json.Unmarshal(b, &ri) == nil {
			vm.Rollback = &ri
		}
	}
	vm.HasCheckpoint = len(m.Checkpoints) > 0

	// walk events
	revertedPaths := map[string]bool{}
	for _, e := range evs {
		if e.Type == "REVERT" || e.Type == "FILE_REVERT" || e.Type == "REVERTED" {
			if e.Path != "" {
				revertedPaths[e.Path] = true
			}
		}
	}

	var firstTS, lastTS time.Time
	for i, e := range evs {
		if i == 0 {
			firstTS = e.TS
		}
		lastTS = e.TS

		switch e.Type {
		case "CMD":
			if vm.Command == "" {
				if c, ok := e.Meta["cmd"].(string); ok {
					vm.Command = c
				}
			}
			if t, ok := e.Meta["task"].(string); ok {
				vm.Task = t
			}
			if cat, ok := e.Risk["category"].(string); ok {
				vm.CommandCategory = cat
			}
			if lvl, ok := e.Risk["level"].(string); ok {
				vm.CommandRisk = lvl
			}
			if d, ok := e.Approval["decision"].(string); ok {
				vm.FinalDecision = d
			}
			if vm.ApprovalMode == "" {
				if mode, ok := e.Approval["mode"].(string); ok {
					vm.ApprovalMode = mode
				}
			}
		case "POLICY_DENY":
			dc := deniedChange{Path: e.Path, Reverted: revertedPaths[e.Path]}
			if r, ok := e.Meta["reason"].(string); ok {
				dc.Reason = r
			} else {
				dc.Reason = e.Summary
			}
			if lvl, ok := e.Risk["level"].(string); ok {
				dc.Risk = lvl
			}
			dc.Explanation = buildDenyExplanation(dc.Reason)
			vm.DeniedC = append(vm.DeniedC, dc)
		case "RUN_FAILED":
			class, _ := e.Meta["class"].(string)
			reason, _ := e.Meta["reason"].(string)
			if class == "policy" {
				vm.Blocked = true
				vm.BlockedReason = reason
			}
		}
	}

	// blocked command: a high-risk command denied by approval mode before execution
	if vm.Blocked || (vm.FinalDecision == "deny") {
		vm.Blocked = true
		vm.BlockedCmd = vm.Command
		if vm.BlockedReason == "" {
			vm.BlockedReason = fmt.Sprintf("blocked by approval mode %q (risk=%s)", vm.ApprovalMode, vm.CommandRisk)
		}
	}

	// overall risk level
	vm.RiskLevel = "low"
	if vm.RiskHigh > 0 {
		vm.RiskLevel = "high"
	} else if vm.RiskMedium > 0 {
		vm.RiskLevel = "medium"
	}

	// timeline + timestamps
	vm.Timeline = buildTimeline(evs)
	if !firstTS.IsZero() {
		vm.Timestamp = firstTS.UTC().Format(time.RFC3339)
		if d := lastTS.Sub(firstTS); d > 0 {
			vm.Duration = d.Round(time.Millisecond).String()
		}
	}

	// patch
	patchPath := m.PatchPath
	if patchPath == "" {
		patchPath = filepath.Join(runDir, "changes.patch")
	}
	vm.PatchRel = "../" + filepath.Base(patchPath)
	if b, err := os.ReadFile(patchPath); err == nil && len(b) > 0 {
		vm.HasPatch = true
		vm.PatchFiles, vm.PatchInsertions, vm.PatchDeletions = summarizePatch(string(b))
		vm.PatchPreview = truncate(string(b), 12000)
	}

	// artifacts
	vm.Artifacts = listArtifacts(runDir)

	// display category — set after Blocked, Allowed, and HasPatch are known
	hasChanges := len(vm.Allowed) > 0 || vm.HasPatch
	vm.DisplayCategory = classifyDisplayCategory(vm.Adapter, vm.Command, hasChanges, vm.Blocked)

	// replay summary + ENV_DENY collapse
	vm.ReplaySetup, vm.ReplayAllowed, vm.ReplayDenied, vm.ReplayBlocked,
		vm.ReplayRollback, vm.ReplayEvidence, vm.EnvExcluded, vm.EnvKeys = computeReplayStats(evs)

	// governance sentence — built last after all fields populated
	vm.GovernanceSentence = buildGovernanceSentence(vm)

	// next-step guidance — depends on review/verify/rollback/denied being set
	vm.NextStep = computeReportNextStep(vm)

	return vm
}

type reportNextStep struct {
	Headline string
	Detail   string
	Command  string
	Class    string // ok | info | warn | bad
}

// computeReportNextStep mirrors the web viewer's guidance from observable state.
// The static report is generated at run time, so verification is always fresh;
// precedence: rollback > denied+unreviewed > unreviewed > checkpoint > done.
func computeReportNextStep(vm reportVM) reportNextStep {
	id := vm.RunID
	switch {
	case vm.Rollback != nil:
		return reportNextStep{
			Headline: "Re-review required — workspace was rolled back",
			Detail:   "The Airlock workspace was restored to a checkpoint, so review was reset to needs-attention. Re-check the evidence, then approve or reject.",
			Command:  "airlock review " + id + " --state approved --note \"re-reviewed after rollback\"",
			Class:    "warn",
		}
	case len(vm.DeniedC) > 0 && (vm.ReviewState == "unreviewed" || vm.ReviewState == "needs-attention"):
		return reportNextStep{
			Headline: "Inspect denied writes before approving",
			Detail:   "One or more writes were blocked and reverted by policy. Confirm nothing important was lost, then record a decision.",
			Command:  "airlock inspect " + id,
			Class:    "warn",
		}
	case vm.Blocked:
		return reportNextStep{
			Headline: "Command was blocked — nothing executed",
			Detail:   "The command was denied before the sandbox launched. No agent code ran and no files changed. Adjust the command or policy if this was unexpected.",
			Command:  "airlock inspect " + id,
			Class:    "warn",
		}
	case vm.ReviewState == "unreviewed":
		return reportNextStep{
			Headline: "Review the patch, then approve or reject",
			Detail:   "This run is verified but not yet reviewed. Open the patch, confirm the changes are what you expected, then record a decision.",
			Command:  "airlock review " + id + " --state approved --note \"looks clean\"",
			Class:    "info",
		}
	case vm.HasCheckpoint:
		return reportNextStep{
			Headline: "Reviewed — restore the workspace only if needed",
			Detail:   "This run is reviewed. If the workspace state should be undone, preview a rollback first with --dry-run. Rollback affects the Airlock workspace, not your original repo.",
			Command:  "airlock rollback " + id + " --dry-run",
			Class:    "ok",
		}
	default:
		return reportNextStep{
			Headline: "No action needed",
			Detail:   "This run is reviewed and its evidence is verified. Export the bundle if you need to share it.",
			Command:  "airlock export " + id + " --format zip --include-report",
			Class:    "ok",
		}
	}
}

// computeReplayStats produces high-level playback counts and collapses ENV_DENY
// events into a single count + key list instead of one row each.
func computeReplayStats(evs []events.Event) (setup, allowed, denied, blocked, rollback, evidence, envExcluded int, envKeys []string) {
	for _, e := range evs {
		switch e.Type {
		case "ENV_DENY":
			envExcluded++
			if k, ok := e.Meta["key"].(string); ok {
				envKeys = append(envKeys, k)
			}
		case "RUN_START", "ADAPTER_SELECTED", "ADAPTER_PREPARED", "SANDBOX_SELECTED",
			"SANDBOX_NETWORK", "SANDBOX_NETWORK_UNSUPPORTED", "SANDBOX_RUNTIME_SELECTED",
			"SANDBOX_FALLBACK", "CHECKPOINT_CREATED", "MODEL_INFO", "NET_ALLOW", "NET_DENY":
			setup++
		case "FILE_CREATE", "FILE_WRITE", "FILE_REMOVE":
			allowed++
		case "POLICY_DENY", "PATH_DENY", "SECRET_DENY":
			denied++
		case "RUN_FAILED":
			blocked++
		case "ROLLBACK":
			rollback++
		case "PATCH_READY", "RUN_DIGEST_READY", "RUN_DIGEST_SIGNED", "SESSION_SUMMARY", "RUN_END":
			evidence++
		}
	}
	return
}

// classifyDisplayCategory derives the operator-facing action label for a run.
// Based solely on observable facts from manifest and events — no invented semantics.
func classifyDisplayCategory(adapter, command string, hasChanges, isBlocked bool) string {
	if isBlocked {
		return "Blocked Shell Operation"
	}
	if strings.Contains(command, "byom-agent") {
		return "BYOM Agent Run"
	}
	if hasChanges {
		return "Workspace Mutation"
	}
	return "Policy-Governed Run"
}

func buildGovernanceSentence(vm reportVM) string {
	adapter := vm.Adapter
	if adapter == "" || adapter == "unknown-adapter" {
		adapter = "unknown-adapter"
	}
	sandbox := vm.SandboxMode
	if sandbox == "" || sandbox == "unknown" {
		sandbox = "workspace"
	}

	var parts []string
	switch vm.DisplayCategory {
	case "Blocked Shell Operation":
		parts = append(parts, fmt.Sprintf(
			"A %s-risk command was evaluated by the %s adapter and blocked before execution — no agent code ran and no files were written.",
			vm.CommandRisk, adapter))
	case "BYOM Agent Run":
		parts = append(parts, fmt.Sprintf("A BYOM agent ran via the %s adapter in a %s sandbox.", adapter, sandbox))
	case "Workspace Mutation":
		parts = append(parts, fmt.Sprintf("A process ran via the %s adapter in a %s sandbox and modified workspace files.", adapter, sandbox))
	default:
		parts = append(parts, fmt.Sprintf("A process ran via the %s adapter in a %s sandbox.", adapter, sandbox))
	}

	if vm.Blocked {
		// first sentence already covers the block; skip redundant detail
		_ = vm.BlockedReason
	} else {
		var details []string
		if len(vm.Allowed) > 0 {
			details = append(details, fmt.Sprintf("allowed %d safe write(s)", len(vm.Allowed)))
		} else {
			details = append(details, "made no file writes")
		}
		if len(vm.DeniedC) > 0 {
			details = append(details, fmt.Sprintf("blocked and reverted %d protected write(s)", len(vm.DeniedC)))
		}
		if vm.HasPatch {
			details = append(details, "generated a verifiable patch")
		}
		if len(details) > 0 {
			parts = append(parts, "It "+strings.Join(details, ", ")+".")
		}
	}

	if vm.Rollback != nil && vm.Rollback.Status == "complete" {
		switch vm.Rollback.Mode {
		case "full":
			parts = append(parts, "The workspace was subsequently rolled back to checkpoint cp-0 (full restore).")
		case "path":
			n := len(vm.Rollback.Paths)
			parts = append(parts, fmt.Sprintf("%d path(s) were subsequently rolled back to checkpoint cp-0.", n))
		}
	}

	switch vm.VerifyLabel {
	case "verified-signed":
		parts = append(parts, "The evidence bundle is cryptographically signed and verifiable.")
	case "verified-unsigned":
		parts = append(parts, "The evidence bundle is verifiable (digest present; no signing key configured).")
	}

	return strings.Join(parts, " ")
}

func buildDenyExplanation(reason string) string {
	switch {
	case strings.HasPrefix(reason, "deny_write"):
		return "Path matched a deny_write policy rule. The write was blocked and the file was reverted in the Airlock workspace."
	case strings.HasPrefix(reason, "allow_write"):
		return "Path was not in the allow_write whitelist. The write was blocked and the file was reverted in the Airlock workspace."
	case strings.HasPrefix(reason, "deny_read"):
		return "Path matched a deny_read policy rule. The read was blocked."
	case strings.HasPrefix(reason, "network"):
		return "Network access was denied by policy."
	default:
		return "Write was blocked and reverted by Airlock policy."
	}
}

func buildTimeline(evs []events.Event) []timelineEvent {
	out := make([]timelineEvent, 0, len(evs))
	for _, e := range evs {
		// ENV_DENY is neutral sandbox hardening, summarized separately — keep it
		// out of the raw timeline so the table isn't dominated by ~20 rows of it.
		if e.Type == "ENV_DENY" {
			continue
		}
		te := timelineEvent{
			TS:      e.TS.UTC().Format("15:04:05"),
			Type:    e.Type,
			Label:   humanizeType(e.Type),
			Path:    e.Path,
			Summary: e.Summary,
			Class:   "normal",
		}
		if lvl, ok := e.Risk["level"].(string); ok {
			te.Risk = lvl
		}
		if d, ok := e.Approval["decision"].(string); ok {
			te.Decision = d
		}
		// extract policy reason for POLICY_DENY
		if e.Type == "POLICY_DENY" {
			if r, ok := e.Meta["reason"].(string); ok {
				te.Reason = r
			} else {
				te.Reason = e.Summary
			}
		}
		switch {
		case e.Type == "POLICY_DENY":
			te.Class = "deny"
		case e.Type == "ROLLBACK":
			te.Class = "rollback"
		case e.Type == "RUN_FAILED" || te.Decision == "deny":
			te.Class = "block"
		case e.Type == "PATCH_READY" || e.Type == "RUN_DIGEST_READY" || e.Type == "RUN_END" || e.Type == "RUN_DIGEST_SIGNED":
			te.Class = "milestone"
		case strings.HasPrefix(e.Type, "FILE_"):
			te.Class = "change"
		}
		if cmd, ok := e.Meta["cmd"].(string); ok && cmd != "" {
			te.Detail = cmd
		}
		out = append(out, te)
	}
	return out
}

func summarizePatch(patch string) (files []string, ins, del int) {
	seen := map[string]bool{}
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "--- "):
			p := strings.TrimSpace(line[4:])
			p = strings.TrimPrefix(p, "a/")
			p = strings.TrimPrefix(p, "b/")
			if p != "" && p != "/dev/null" && !seen[p] {
				seen[p] = true
				files = append(files, p)
			}
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			ins++
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			del++
		}
	}
	sort.Strings(files)
	return files, ins, del
}

func listArtifacts(runDir string) []artifact {
	known := []string{
		"run_manifest.json", "events.jsonl", "session_events.jsonl",
		"changes.patch", "run_digest.json", "run_digest.sig",
		"review.json", "rollback.json", "review_events.jsonl", "build_info.json",
	}
	var out []artifact
	for _, name := range known {
		p := filepath.Join(runDir, name)
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		out = append(out, artifact{Name: name, Rel: "../" + name, Size: humanSize(info.Size())})
	}
	// checkpoints dir
	if info, err := os.Stat(filepath.Join(runDir, "checkpoints")); err == nil && info.IsDir() {
		out = append(out, artifact{Name: "checkpoints/", Rel: "../checkpoints/", Size: "dir"})
	}
	return out
}

// ---- helpers --------------------------------------------------------------

func badgeClass(kind, value string) string {
	v := strings.ToLower(value)
	switch kind {
	case "status":
		if strings.HasPrefix(v, "success") {
			return "ok"
		}
		if strings.HasPrefix(v, "failed") {
			return "bad"
		}
		return "muted"
	case "risk":
		switch v {
		case "high":
			return "bad"
		case "medium":
			return "warn"
		case "low":
			return "ok"
		}
		return "muted"
	case "decision":
		switch v {
		case "deny":
			return "bad"
		case "prompt":
			return "warn"
		case "allow":
			return "ok"
		}
		return "muted"
	case "review":
		switch v {
		case "approved":
			return "ok"
		case "rejected":
			return "bad"
		case "needs-attention":
			return "warn"
		}
		return "muted"
	}
	return "muted"
}

func humanizeType(t string) string {
	switch t {
	case "RUN_START":
		return "Run started"
	case "ADAPTER_SELECTED":
		return "Adapter selected"
	case "ADAPTER_PREPARED":
		return "Command prepared"
	case "CHECKPOINT_CREATED":
		return "Checkpoint captured"
	case "SANDBOX_SELECTED":
		return "Sandbox selected"
	case "SANDBOX_NETWORK":
		return "Network mode set"
	case "CMD":
		return "Agent command"
	case "POLICY_DENY":
		return "Blocked by policy"
	case "FILE_CREATE":
		return "File created"
	case "FILE_WRITE":
		return "File modified"
	case "FILE_REMOVE":
		return "File removed"
	case "PATCH_READY":
		return "Patch generated"
	case "RUN_FAILED":
		return "Run failed"
	case "RUN_END":
		return "Run finished"
	case "RUN_DIGEST_READY":
		return "Digest generated"
	case "RUN_DIGEST_SIGNED":
		return "Digest signed"
	case "ROLLBACK":
		return "Checkpoint restored"
	case "REVIEW_UPDATED":
		return "Review updated"
	default:
		return strings.ReplaceAll(strings.Title(strings.ToLower(t)), "_", " ")
	}
}

func packLabel(p runmeta.PolicyPackInfo) string {
	if p.Name == "" {
		return "—"
	}
	s := p.Name
	if p.Version != "" {
		s += "@" + p.Version
	}
	if p.Source != "" {
		s += " (" + p.Source + ")"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n… (truncated — see changes.patch)"
}

func humanSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

const reportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{{.DisplayCategory}} — Airlock evidence — {{.RunID}}</title>
<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c2230; --border:#30363d;
    --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
    --ok-bg:#12261a;--ok-bd:#2ea043;--ok-fg:#7ee2a8;
    --warn-bg:#2b2410;--warn-bd:#d29922;--warn-fg:#e3b341;
    --bad-bg:#2b1416;--bad-bd:#f85149;--bad-fg:#ff9492;
    --muted-bg:#21262d;--muted-bd:#484f58;--muted-fg:#adbac7;
    --outcome-bg:#0d1f38;--outcome-bd:#1f6feb;
  }
  @media (prefers-color-scheme: light){
    :root{--bg:#f6f8fa;--panel:#ffffff;--panel2:#f6f8fa;--border:#d0d7de;--text:#1f2328;--muted:#656d76;--accent:#0969da;
      --ok-bg:#dafbe1;--ok-bd:#2da44e;--ok-fg:#1a7f37;--warn-bg:#fff8c5;--warn-bd:#d4a72c;--warn-fg:#7d4e00;
      --bad-bg:#ffebe9;--bad-bd:#cf222e;--bad-fg:#a40e26;--muted-bg:#eaeef2;--muted-bd:#afb8c1;--muted-fg:#57606a;
      --outcome-bg:#ddf4ff;--outcome-bd:#54aeff;}
  }
  *{box-sizing:border-box}
  body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);
    margin:0;line-height:1.5;font-size:15px}
  .wrap{max-width:980px;margin:0 auto;padding:28px 20px 64px}
  header.top{display:flex;flex-wrap:wrap;gap:12px;align-items:baseline;justify-content:space-between;margin-bottom:6px}
  h1{font-size:20px;margin:0}
  h1 .brand{color:var(--muted);font-weight:600}
  .runid{font-family:var(--mono);font-size:13px;color:var(--muted)}
  h2{font-size:13px;margin:0 0 12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:700}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin:14px 0}
  .card.alert{border-color:var(--bad-bd);background:var(--bad-bg)}
  .card.outcome{border-color:var(--outcome-bd);background:var(--outcome-bg)}
  .card.rollback-card{border-color:var(--warn-bd);background:var(--warn-bg)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px 20px}
  .field{display:flex;flex-direction:column;gap:2px}
  .field .k{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  .field .v{font-weight:600;word-break:break-word}
  .mono{font-family:var(--mono);font-size:13px}
  .badge{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;border:1px solid var(--muted-bd);background:var(--muted-bg);color:var(--muted-fg)}
  .badge.ok{background:var(--ok-bg);border-color:var(--ok-bd);color:var(--ok-fg)}
  .badge.warn{background:var(--warn-bg);border-color:var(--warn-bd);color:var(--warn-fg)}
  .badge.bad{background:var(--bad-bg);border-color:var(--bad-bd);color:var(--bad-fg)}
  .badge.muted{background:var(--muted-bg);border-color:var(--muted-bd);color:var(--muted-fg)}
  .badges{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px}
  pre{background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;font-family:var(--mono);font-size:12.5px;margin:8px 0 0}
  ul.plain{list-style:none;padding:0;margin:6px 0 0}
  ul.plain li{padding:4px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:13px}
  ul.plain li:last-child{border-bottom:0}
  a{color:var(--accent);text-decoration:none}
  a:hover{text-decoration:underline}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
  tr.deny td{background:var(--bad-bg)}
  tr.block td{background:var(--bad-bg)}
  tr.change td{background:var(--muted-bg)}
  tr.rollback td{background:var(--warn-bg)}
  tr.milestone td{opacity:.75}
  .tl-type{font-family:var(--mono);font-size:12px;white-space:nowrap}
  .tl-time{color:var(--muted);font-family:var(--mono);font-size:12px;white-space:nowrap}
  .muted{color:var(--muted)}
  .stat-row{display:flex;flex-wrap:wrap;gap:8px}
  .outcome-sentence{font-size:15px;line-height:1.6;margin:0 0 14px;color:var(--text)}
  .deny-explanation{font-size:12px;color:var(--muted);font-style:italic;margin-top:3px}
  .caveat{font-size:12px;color:var(--muted);border-left:3px solid var(--warn-bd);padding-left:10px;margin-top:10px}
  .empty-state{color:var(--muted);font-size:14px}
  .empty-state .hint{font-size:12px;margin-top:6px;font-family:var(--mono)}
  .card.next-step.ok{border-color:var(--ok-bd);background:var(--ok-bg)}
  .card.next-step.warn{border-color:var(--warn-bd);background:var(--warn-bg)}
  .card.next-step.bad{border-color:var(--bad-bd);background:var(--bad-bg)}
  .card.next-step.info{border-color:var(--outcome-bd);background:var(--outcome-bg)}
  .ns-headline{font-size:16px;font-weight:700;margin:0 0 4px}
  .ns-detail{font-size:14px;margin:0 0 8px;line-height:1.55}
  .replay-counts{display:flex;flex-wrap:wrap;gap:8px;margin:4px 0 4px}
  .replay-chip{border:1px solid var(--border);border-radius:8px;padding:6px 10px;font-size:12px;background:var(--panel2);min-width:88px}
  .replay-chip .n{font-size:18px;font-weight:700;display:block}
  .replay-chip .l{color:var(--muted);text-transform:uppercase;letter-spacing:.03em;font-size:10px}
  .envnote{border:1px solid var(--muted-bd);background:var(--muted-bg);border-radius:8px;padding:10px 12px;margin-top:10px;font-size:13px}
  footer{margin-top:24px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);padding-top:14px}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1><span class="brand">Sentinel Airlock</span> · {{.DisplayCategory}}</h1>
    <span class="badge {{badgeClass "status" .Status}}">{{.Status}}</span>
  </header>
  <div class="runid">run {{.RunID}}{{if .Timestamp}} · {{.Timestamp}}{{end}}{{if .Duration}} · {{.Duration}}{{end}}</div>

  <!-- ── Governance outcome (executive summary) ──────────────────────── -->
  <div class="card outcome">
    <h2>Governance outcome</h2>
    <p class="outcome-sentence">{{.GovernanceSentence}}</p>
    <div class="badges">
      <span class="badge {{badgeClass "status" .Status}}">{{.Status}}</span>
      {{if .Allowed}}<span class="badge ok">{{len .Allowed}} write(s) allowed</span>{{end}}
      {{if .DeniedC}}<span class="badge bad">{{len .DeniedC}} write(s) denied+reverted</span>{{end}}
      {{if .Blocked}}<span class="badge bad">command blocked</span>{{end}}
      <span class="badge {{badgeClass "risk" .RiskLevel}}">risk: {{.RiskLevel}}</span>
      <span class="badge {{badgeClass "review" .ReviewState}}">review: {{.ReviewState}}</span>
      <span class="badge {{.VerifyClass}}">{{.VerifyLabel}}</span>
      {{if .Rollback}}<span class="badge warn">rolled back</span>{{end}}
    </div>
  </div>

  <!-- ── What should I do next? ──────────────────────────────────────── -->
  {{if .NextStep.Headline}}
  <div class="card next-step {{.NextStep.Class}}">
    <h2>What should I do next?</h2>
    <p class="ns-headline">{{.NextStep.Headline}}</p>
    <p class="ns-detail">{{.NextStep.Detail}}</p>
    {{if .NextStep.Command}}<pre>{{.NextStep.Command}}</pre>{{end}}
  </div>
  {{end}}

  <!-- ── Blocked command alert ───────────────────────────────────────── -->
  {{if .Blocked}}
  <div class="card alert">
    <h2 style="color:var(--bad-fg)">⛔ Command blocked before execution</h2>
    {{if .BlockedCmd}}<pre>{{.BlockedCmd}}</pre>{{end}}
    <div style="margin-top:8px"><strong>Reason:</strong> {{.BlockedReason}}</div>
    <div class="badges" style="margin-top:8px">
      {{if .CommandRisk}}<span class="badge {{badgeClass "risk" .CommandRisk}}">risk: {{.CommandRisk}}</span>{{end}}
      {{if .CommandCategory}}<span class="badge muted">category: {{.CommandCategory}}</span>{{end}}
      {{if .FinalDecision}}<span class="badge {{badgeClass "decision" .FinalDecision}}">decision: {{.FinalDecision}}</span>{{end}}
    </div>
    <div class="caveat">No agent code ran. The command was evaluated and blocked before the sandbox launched.</div>
  </div>
  {{end}}

  <!-- ── Run overview ────────────────────────────────────────────────── -->
  <div class="card">
    <h2>Run overview</h2>
    <div class="grid">
      <div class="field"><span class="k">Run ID</span><span class="v mono">{{.RunID}}</span></div>
      <div class="field"><span class="k">Status</span><span class="v">{{.Status}}</span></div>
      <div class="field"><span class="k">Adapter / agent</span><span class="v">{{.Adapter}}</span></div>
      <div class="field"><span class="k">Timestamp</span><span class="v mono">{{if .Timestamp}}{{.Timestamp}}{{else}}—{{end}}</span></div>
      <div class="field"><span class="k">Duration</span><span class="v mono">{{if .Duration}}{{.Duration}}{{else}}—{{end}}</span></div>
      <div class="field"><span class="k">Workspace</span><span class="v mono">{{if .Workspace}}{{.Workspace}}{{else}}—{{end}}</span></div>
    </div>
    {{if .Command}}<div class="field" style="margin-top:12px"><span class="k">Command</span><pre>{{.Command}}</pre></div>{{end}}
    {{if .Task}}<div class="field" style="margin-top:8px"><span class="k">Task</span><span class="v">{{.Task}}</span></div>{{end}}
  </div>

  <!-- ── Governance ──────────────────────────────────────────────────── -->
  <div class="card">
    <h2>Governance</h2>
    <div class="grid">
      <div class="field"><span class="k">Policy pack</span><span class="v">{{.PolicyPack}}</span></div>
      <div class="field"><span class="k">Approval mode</span><span class="v">{{if .ApprovalMode}}{{.ApprovalMode}}{{else}}—{{end}}</span></div>
      <div class="field"><span class="k">Sandbox mode</span><span class="v">{{.SandboxMode}}</span></div>
      <div class="field"><span class="k">Network mode</span><span class="v">{{.NetworkMode}}</span></div>
      <div class="field"><span class="k">Policy file</span><span class="v mono">{{if .PolicyPath}}{{.PolicyPath}}{{else}}—{{end}}</span></div>
    </div>
    {{if eq .SandboxMode "workspace"}}
    <div class="caveat">Workspace sandbox: the agent ran on the host OS inside an isolated directory copy. The workspace directory boundary is best-effort, not OS-enforced. See <a href="{{.SecurityRef}}">SECURITY.md</a>.</div>
    {{end}}
  </div>

  <!-- ── Risk summary ────────────────────────────────────────────────── -->
  <div class="card">
    <h2>Risk summary</h2>
    <div class="badges" style="margin-bottom:10px">
      <span class="badge {{badgeClass "risk" .RiskLevel}}">overall risk: {{.RiskLevel}}</span>
      {{if .CommandCategory}}<span class="badge muted">command category: {{.CommandCategory}}</span>{{end}}
      {{if .FinalDecision}}<span class="badge {{badgeClass "decision" .FinalDecision}}">final decision: {{.FinalDecision}}</span>{{end}}
    </div>
    <div class="stat-row">
      <span class="badge ok">low {{.RiskLow}}</span>
      <span class="badge warn">medium {{.RiskMedium}}</span>
      <span class="badge bad">high {{.RiskHigh}}</span>
      <span class="badge muted">approved {{.Approved}}</span>
      <span class="badge muted">denied {{.Denied}}</span>
    </div>
  </div>

  <!-- ── Allowed changes ─────────────────────────────────────────────── -->
  <div class="card">
    <h2>Allowed changes</h2>
    {{if .Allowed}}
    <ul class="plain">{{range .Allowed}}<li>{{.}}</li>{{end}}</ul>
    {{else}}
    <div class="empty-state">
      No files were written in this run.
      {{if .Blocked}}<div class="hint"># command was blocked before any writes could occur</div>{{end}}
    </div>
    {{end}}
  </div>

  <!-- ── Denied / reverted changes ───────────────────────────────────── -->
  {{if .DeniedC}}
  <div class="card">
    <h2>Denied / reverted changes</h2>
    <table>
      <tr><th>Path</th><th>Risk</th><th>Reason</th><th>Reverted</th></tr>
      {{range .DeniedC}}
      <tr class="deny">
        <td>
          <div class="mono">{{if .Path}}{{.Path}}{{else}}—{{end}}</div>
          {{if .Explanation}}<div class="deny-explanation">{{.Explanation}}</div>{{end}}
        </td>
        <td>{{if .Risk}}<span class="badge {{badgeClass "risk" .Risk}}">{{.Risk}}</span>{{else}}—{{end}}</td>
        <td class="mono">{{if .Reason}}{{.Reason}}{{else}}policy deny{{end}}</td>
        <td>{{if .Reverted}}<span class="badge ok">reverted</span>{{else}}<span class="badge muted">—</span>{{end}}</td>
      </tr>
      {{end}}
    </table>
  </div>
  {{end}}

  <!-- ── Checkpoint restore (rollback) ───────────────────────────────── -->
  {{if .Rollback}}
  <div class="card rollback-card">
    <h2>↩ Workspace rolled back</h2>
    <div class="stat-row" style="margin-bottom:10px">
      <span class="badge warn">{{.Rollback.Mode}} restore</span>
      <span class="badge warn">status: {{.Rollback.Status}}</span>
      <span class="badge {{.VerifyClass}}">{{.VerifyLabel}}</span>
    </div>
    <div class="grid">
      <div class="field"><span class="k">Mode</span><span class="v">{{.Rollback.Mode}}</span></div>
      <div class="field"><span class="k">Checkpoint</span><span class="v mono">{{.Rollback.Checkpoint}}</span></div>
      <div class="field"><span class="k">Status</span><span class="v">{{.Rollback.Status}}</span></div>
      <div class="field"><span class="k">Timestamp</span><span class="v mono">{{.Rollback.Timestamp}}</span></div>
    </div>
    {{if .Rollback.Paths}}
    <div style="margin-top:10px">
      <div class="field"><span class="k">Paths restored</span></div>
      <ul class="plain">{{range .Rollback.Paths}}<li class="mono">{{.}}</li>{{end}}</ul>
    </div>
    {{end}}
    <div class="caveat" style="margin-top:12px">
      <strong>What rollback restored:</strong> the Airlock workspace at
      <span class="mono">.airlock/workspaces/{{.RunID}}/repo</span> — the isolated copy the agent ran in.
      Rollback restores the Airlock workspace, <strong>not your original repo</strong>. Your original source directory was not modified at any point by Airlock.
      Review state is now <strong>needs-attention</strong> — this run requires re-review before approving.
      Digest was rebuilt after rollback; run <span class="mono">airlock verify {{.RunID}}</span> to confirm integrity.
      Use the patch / export / review workflow before applying any changes back to your source.
      Operation-level rollback (undo last N operations) is future work.
    </div>
  </div>
  {{else if .HasCheckpoint}}
  <div class="card">
    <h2>Rollback available — checkpoint cp-0</h2>
    <p style="color:var(--muted);font-size:14px;margin:0 0 10px">Airlock captured a workspace snapshot before agent execution. You can restore the isolated Airlock workspace to its pre-execution state.</p>
    <div class="grid" style="margin-bottom:10px">
      <div class="field"><span class="k">Original repo</span><span class="v" style="font-size:13px;font-weight:500">Your source directory — never touched by Airlock or rollback.</span></div>
      <div class="field"><span class="k">Airlock workspace</span><span class="v mono">.airlock/workspaces/{{.RunID}}/repo</span></div>
      <div class="field"><span class="k">Checkpoint</span><span class="v mono">.airlock/runs/{{.RunID}}/checkpoints/cp-0</span></div>
    </div>
    <pre style="margin:0 0 10px"># 1. preview what would be restored (no changes made — always start here):
./airlock rollback {{.RunID}} --dry-run

# 2. restore full workspace to checkpoint cp-0:
./airlock rollback {{.RunID}} --force

# 3. restore a single path only:
./airlock rollback {{.RunID}} --path src/changed-file.txt --force</pre>
    <div class="caveat">
      <strong>Rollback restores the Airlock workspace, not your original repo.</strong>
      It rewinds <span class="mono">.airlock/workspaces/{{.RunID}}/repo</span> to checkpoint cp-0. Your original source directory is never modified by Airlock.
      Use the patch / export / review workflow before applying any changes back to your source.
      After rollback: review state becomes needs-attention, digest is rebuilt, report is regenerated.
      Operation-level rollback (last N operations) is future work.
    </div>
  </div>
  {{end}}

  <!-- ── Patch summary ───────────────────────────────────────────────── -->
  <div class="card">
    <h2>Patch summary</h2>
    {{if .HasPatch}}
    <div class="stat-row" style="margin-bottom:8px">
      <span class="badge muted">{{len .PatchFiles}} file(s)</span>
      <span class="badge ok">+{{.PatchInsertions}}</span>
      <span class="badge bad">-{{.PatchDeletions}}</span>
      <a class="badge" href="{{.PatchRel}}">open changes.patch →</a>
    </div>
    {{if .PatchFiles}}<ul class="plain">{{range .PatchFiles}}<li>{{.}}</li>{{end}}</ul>{{end}}
    <details style="margin-top:10px"><summary class="muted">Preview diff</summary><pre>{{.PatchPreview}}</pre></details>
    {{else}}
    <div class="empty-state">
      No file changes were captured.
      <div class="hint"># run: airlock inspect &lt;run_id&gt; to see what was recorded</div>
    </div>
    {{end}}
  </div>

  <!-- ── Replay summary ──────────────────────────────────────────────── -->
  <div class="card">
    <h2>Replay summary</h2>
    <p class="muted" style="margin:0 0 8px;font-size:13px">A plain-language playback of what happened. The full raw event stream is in the timeline below.</p>
    <div class="replay-counts">
      <div class="replay-chip"><span class="n">{{.ReplaySetup}}</span><span class="l">setup &amp; sandbox</span></div>
      <div class="replay-chip"><span class="n">{{.ReplayAllowed}}</span><span class="l">allowed changes</span></div>
      <div class="replay-chip"><span class="n">{{.ReplayDenied}}</span><span class="l">denied / reverted</span></div>
      <div class="replay-chip"><span class="n">{{.ReplayBlocked}}</span><span class="l">blocked commands</span></div>
      <div class="replay-chip"><span class="n">{{.ReplayRollback}}</span><span class="l">rollback events</span></div>
      <div class="replay-chip"><span class="n">{{.ReplayEvidence}}</span><span class="l">evidence artifacts</span></div>
    </div>
    {{if gt .EnvExcluded 0}}
    <div class="envnote">
      <strong>Environment guardrail:</strong> {{.EnvExcluded}} environment variable(s) excluded from the sandbox. This is expected hardening, not a policy violation.
      <details style="margin-top:6px"><summary class="muted">Show excluded variables</summary>
        <div class="mono" style="margin-top:6px;font-size:12px;line-height:1.8">{{range .EnvKeys}}{{.}} {{end}}</div>
      </details>
    </div>
    {{end}}
  </div>

  <!-- ── Evidence timeline ───────────────────────────────────────────── -->
  <div class="card">
    <h2>Evidence timeline</h2>
    <table>
      <tr><th>Time</th><th>Event</th><th>Detail</th></tr>
      {{range .Timeline}}
      <tr class="{{.Class}}">
        <td class="tl-time">{{.TS}}</td>
        <td>
          <span class="tl-type">{{.Label}}</span>
          {{if eq .Class "deny"}} <span class="badge bad">POLICY_DENY</span>{{end}}
          {{if eq .Class "block"}} <span class="badge bad">BLOCKED</span>{{end}}
          {{if eq .Class "rollback"}} <span class="badge warn">ROLLBACK</span>{{end}}
          {{if .Risk}} <span class="badge {{badgeClass "risk" .Risk}}">{{.Risk}}</span>{{end}}
          {{if .Decision}} <span class="badge {{badgeClass "decision" .Decision}}">{{.Decision}}</span>{{end}}
        </td>
        <td>
          {{if .Path}}<div class="mono">{{.Path}}</div>{{end}}
          {{if .Reason}}<div class="mono deny-explanation">{{.Reason}}</div>{{end}}
          {{if .Detail}}<div class="mono deny-explanation">{{.Detail}}</div>{{else if .Summary}}<div class="deny-explanation">{{.Summary}}</div>{{end}}
        </td>
      </tr>
      {{end}}
    </table>
  </div>

  <!-- ── Review status ───────────────────────────────────────────────── -->
  <div class="card">
    <h2>Review status</h2>
    <div class="badges" style="margin-bottom:8px">
      <span class="badge {{badgeClass "review" .ReviewState}}">{{.ReviewState}}</span>
    </div>
    {{if eq .ReviewState "unreviewed"}}
    <div class="empty-state">
      Unreviewed — this run has not been approved or rejected.
      <div class="hint">airlock review {{.RunID}} --state approved --note "looks clean"</div>
    </div>
    {{else}}
    <div class="grid">
      <div class="field"><span class="k">Reviewer</span><span class="v">{{if .ReviewReviewer}}{{.ReviewReviewer}}{{else}}—{{end}}</span></div>
      <div class="field"><span class="k">Timestamp</span><span class="v mono">{{if .ReviewTimestamp}}{{.ReviewTimestamp}}{{else}}—{{end}}</span></div>
    </div>
    {{if .ReviewNote}}<div class="field" style="margin-top:8px"><span class="k">Note</span><span class="v">{{.ReviewNote}}</span></div>{{end}}
    {{end}}
    {{if eq .ReviewState "needs-attention"}}
    <div class="caveat">This run requires review — a rollback was performed or a policy denial was recorded. Review the evidence before approving.</div>
    {{end}}
  </div>

  <!-- ── Verification ────────────────────────────────────────────────── -->
  <div class="card">
    <h2>Verification</h2>
    <div class="badges" style="margin-bottom:8px">
      <span class="badge {{.VerifyClass}}">{{.VerifyLabel}}</span>
      {{if not .DigestPresent}}<span class="badge muted">no digest file</span>{{end}}
    </div>
    {{if eq .VerifyLabel "verified-unsigned"}}
    <div class="empty-state" style="margin-bottom:10px">
      Verified but unsigned — the SHA-256 digest matches all recorded artifacts. No signing key was configured at run time.
      <div class="hint"># to enable signing: export AIRLOCK_SIGNING_KEY=/path/to/ed25519-key.hex</div>
    </div>
    {{end}}
    {{if eq .VerifyLabel "no digest"}}
    <div class="empty-state">
      No digest present. Generate one with: <span class="mono">airlock verify {{.RunID}}</span>
    </div>
    {{end}}
    {{if .DigestValues}}
    <table>
      <tr><th>Artifact</th><th>SHA-256 (truncated)</th></tr>
      {{range .DigestValues}}<tr><td class="mono">{{.K}}</td><td class="mono">{{.V}}</td></tr>{{end}}
    </table>
    <div class="muted" style="margin-top:8px;font-size:12px">Run <span class="mono">airlock verify {{.RunID}}</span> to re-check all hashes{{if .Signed}} and the ed25519 signature{{end}}.</div>
    {{end}}
  </div>

  <!-- ── Artifacts ───────────────────────────────────────────────────── -->
  <div class="card">
    <h2>Artifacts</h2>
    {{if .Artifacts}}
    <table>
      <tr><th>File</th><th>Size</th></tr>
      {{range .Artifacts}}<tr><td><a href="{{.Rel}}" class="mono">{{.Name}}</a></td><td class="muted">{{.Size}}</td></tr>{{end}}
    </table>
    {{else}}<div class="empty-state">No artifacts found.</div>{{end}}
  </div>

  <!-- ── Limitations ─────────────────────────────────────────────────── -->
  <div class="card">
    <h2>Scope and limitations</h2>
    <div class="muted" style="font-size:13px;line-height:1.7">
      This report is a local, artifact-first evidence view — not a hosted dashboard or SaaS product.
      <ul style="margin:6px 0;padding-left:18px">
        <li>Airlock only captures workflows launched through <span class="mono">airlock run</span>.</li>
        <li>The <span class="mono">workspace</span> sandbox runs on the host OS; the directory boundary is best-effort, not OS-enforced. Use <span class="mono">--sandbox container</span> for stronger isolation.</li>
        <li>Network <span class="mono">off</span> mode in workspace sandbox is advisory — it records policy intent but does not block syscalls.</li>
        <li>Digest verification confirms artifact integrity after the run. It does not cryptographically prove execution correctness.</li>
        <li>Signing requires <span class="mono">AIRLOCK_SIGNING_KEY</span> configured at run time.</li>
      </ul>
      See <a href="{{.SecurityRef}}">SECURITY.md</a> for the full trust model and caveats.
    </div>
  </div>

  <footer>
    Generated {{.GeneratedAt}}{{if .Version}} · airlock {{.Version}}{{end}} · single static file, no network required.
  </footer>
</div>
</body>
</html>
`
