package remote

import "github.com/EliaxLab/SentinelAirlock/internal/runmeta"

type SandboxSettings struct {
	Mode            string   `json:"mode"`
	Image           string   `json:"image,omitempty"`
	Network         string   `json:"network"`
	AllowEnv        []string `json:"allow_env,omitempty"`
	AllowDomains    []string `json:"allow_domains,omitempty"`
	ContainerRunner string   `json:"container_runtime,omitempty"`
}

type RunRequest struct {
	RunID         string          `json:"run_id"`
	Adapter       string          `json:"adapter"`
	Cmd           string          `json:"cmd,omitempty"`
	Task          string          `json:"task,omitempty"`
	RepoSubPath   string          `json:"repo_sub_path,omitempty"`
	PolicyPath    string          `json:"policy_path,omitempty"`
	PolicyPack    string          `json:"policy_pack,omitempty"`
	Approval      string          `json:"approval,omitempty"`
	Mode          string          `json:"mode,omitempty"`
	Sandbox       SandboxSettings `json:"sandbox"`
	EnvAllowlist  []string        `json:"env_allowlist,omitempty"`
	Effective     map[string]any  `json:"effective_config,omitempty"`
	SubmittedBy   string          `json:"submitted_by,omitempty"`
	SourceMachine string          `json:"source_machine,omitempty"`
	TeamName      string          `json:"team_name,omitempty"`
}

type RunResponse struct {
	RunID      string               `json:"run_id"`
	Status     string               `json:"status"`
	Message    string               `json:"message,omitempty"`
	WorkerName string               `json:"worker_name,omitempty"`
	WorkerID   string               `json:"worker_id,omitempty"`
	Manifest   *runmeta.RunManifest `json:"manifest,omitempty"`
	Artifacts  map[string]string    `json:"artifacts,omitempty"`
}
