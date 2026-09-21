package adapters

import (
	"bytes"
	"os"
	"os/exec"

	"github.com/EliaxLab/SentinelAirlock/internal/session"
)

type CapabilitySet struct {
	SupportsTaskArg           bool `json:"supports_task_arg"`
	SupportsEnvTask           bool `json:"supports_env_task"`
	SupportsStreamingOutput   bool `json:"supports_streaming_output"`
	SupportsNativeEvents      bool `json:"supports_native_events"`
	SupportsNativeCheckpoints bool `json:"supports_native_checkpoints"`
	SupportsNativeDiff        bool `json:"supports_native_diff"`
	SupportsNativeApproval    bool `json:"supports_native_approval"`
}

type RunContext struct {
	RunID         string
	WorkspacePath string
	RepoPath      string
	Task          string
	ApprovalMode  string
	Environment   []string
	AdapterName   string
	Command       string
	SessionSink   *session.Sink
}

type Invocation struct {
	Executable     string
	Args           []string
	EnvOverrides   []string
	WorkingDir     string
	DisplayCommand string
}

type ExecutionResult struct {
	ExitCode int
	Output   string
	Meta     map[string]any
}

type Adapter interface {
	Name() string
	Capabilities() CapabilitySet
	Prepare(RunContext) (Invocation, error)
	Execute(RunContext, Invocation) (ExecutionResult, error)
}

func ExecuteInvocation(ctx RunContext, inv Invocation) (ExecutionResult, error) {
	cmd := exec.Command(inv.Executable, inv.Args...)
	cmd.Dir = inv.WorkingDir
	cmd.Env = append(append([]string{}, ctx.Environment...), inv.EnvOverrides...)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()
	out := buf.String()
	if runErr == nil {
		return ExecutionResult{ExitCode: 0, Output: out}, nil
	}
	if ee, ok := runErr.(*exec.ExitError); ok {
		return ExecutionResult{ExitCode: ee.ExitCode(), Output: out}, runErr
	}
	return ExecutionResult{ExitCode: 1, Output: out}, runErr
}

func BaseEnv(task string) []string {
	return append(os.Environ(), "AIRLOCK_TASK="+task)
}
