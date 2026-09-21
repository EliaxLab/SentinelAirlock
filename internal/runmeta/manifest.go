package runmeta

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/EliaxLab/SentinelAirlock/internal/policy"
)

type Checkpoint struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

type PolicySummary struct {
	PolicyPath string   `json:"policy_path"`
	Network    string   `json:"network,omitempty"`
	AllowWrite []string `json:"allow_write,omitempty"`
	DenyWrite  []string `json:"deny_write,omitempty"`
	DenyRead   []string `json:"deny_read,omitempty"`
}

type RunManifest struct {
	RunID           string            `json:"run_id"`
	WorkspacePath   string            `json:"workspace_path"`
	PolicySummary   PolicySummary     `json:"policy_summary"`
	PolicyPack      PolicyPackInfo    `json:"policy_pack"`
	ExecutionMode   string            `json:"execution_mode,omitempty"`
	Execution       ExecutionInfo     `json:"execution,omitempty"`
	Team            TeamInfo          `json:"team,omitempty"`
	TouchedPaths    []string          `json:"touched_paths"`
	DeniedPaths     []string          `json:"denied_paths"`
	PatchPath       string            `json:"patch_path,omitempty"`
	Checkpoints     []Checkpoint      `json:"checkpoints"`
	RiskSummary     RiskSummary       `json:"risk_summary"`
	ApprovalSummary ApprovalSummary   `json:"approval_summary"`
	Adapter         AdapterSummary    `json:"adapter"`
	Invocation      InvocationSummary `json:"invocation"`
	Sandbox         SandboxInfo       `json:"sandbox"`
	Network         NetworkInfo       `json:"network"`
	Env             EnvInfo           `json:"env"`
	SandboxSummary  SandboxSummary    `json:"sandbox_summary"`
	Digest          DigestInfo        `json:"digest"`
	Export          ExportInfo        `json:"export,omitempty"`
	Status          RunStatus         `json:"status,omitempty"`
	EffectiveConfig map[string]any    `json:"effective_config,omitempty"`
	Product         ProductInfo       `json:"product,omitempty"`
}

type ExecutionInfo struct {
	Target        string `json:"target,omitempty"`
	WorkerName    string `json:"worker_name,omitempty"`
	WorkerID      string `json:"worker_id,omitempty"`
	SubmittedBy   string `json:"submitted_by,omitempty"`
	SourceMachine string `json:"source_machine,omitempty"`
}

type TeamInfo struct {
	Name string `json:"name,omitempty"`
}

type PolicyPackInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
}

type RiskSummary struct {
	LowCount    int `json:"low_count"`
	MediumCount int `json:"medium_count"`
	HighCount   int `json:"high_count"`
}

type ApprovalSummary struct {
	ApprovedCount int `json:"approved_count"`
	PromptedCount int `json:"prompted_count"`
	DeniedCount   int `json:"denied_count"`
}

type AdapterSummary struct {
	Name         string         `json:"name"`
	Readiness    string         `json:"readiness,omitempty"`
	Version      string         `json:"version,omitempty"`
	Capabilities map[string]any `json:"capabilities"`
}

type RunStatus struct {
	Terminal      string `json:"terminal,omitempty"`
	FailureClass  string `json:"failure_class,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
	TimeoutSec    int    `json:"timeout_sec,omitempty"`
}

type ProductInfo struct {
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
}

type InvocationSummary struct {
	DisplayCommand string `json:"display_command,omitempty"`
}

type SandboxInfo struct {
	Mode         string `json:"mode"`
	Image        string `json:"image,omitempty"`
	Runtime      string `json:"runtime,omitempty"`
	FallbackUsed bool   `json:"fallback_used,omitempty"`
}

type NetworkInfo struct {
	Mode       string   `json:"mode"`
	Allowlist  []string `json:"allowlist,omitempty"`
	DenyCount  int      `json:"deny_count"`
	AllowCount int      `json:"allow_count"`
}

type EnvInfo struct {
	Allowed []string `json:"allowed,omitempty"`
	Denied  []string `json:"denied,omitempty"`
}

type SandboxSummary struct {
	HostModeRuns      int `json:"host_mode_runs"`
	WorkspaceModeRuns int `json:"workspace_mode_runs"`
	ContainerModeRuns int `json:"container_mode_runs"`
	SecretDenials     int `json:"secret_denials"`
	PathDenials       int `json:"path_denials"`
	EnvDenials        int `json:"env_denials"`
}

type DigestInfo struct {
	Path          string            `json:"path,omitempty"`
	Values        map[string]string `json:"values,omitempty"`
	Signed        bool              `json:"signed,omitempty"`
	SignaturePath string            `json:"signature_path,omitempty"`
	SigningKeyID  string            `json:"signing_key_id,omitempty"`
}

type ExportInfo struct {
	Path   string `json:"path,omitempty"`
	Format string `json:"format,omitempty"`
}

func BuildPolicySummary(policyPath string, cfg *policy.Config) PolicySummary {
	ps := PolicySummary{PolicyPath: policyPath}
	if cfg == nil {
		return ps
	}
	ps.Network = cfg.Network.Mode
	ps.AllowWrite = append([]string(nil), cfg.Policy.AllowWrite...)
	ps.DenyWrite = append([]string(nil), cfg.Policy.DenyWrite...)
	ps.DenyRead = append([]string(nil), cfg.Policy.DenyRead...)
	return ps
}

func Save(path string, m RunManifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func Load(path string) (RunManifest, error) {
	var m RunManifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	return m, nil
}
