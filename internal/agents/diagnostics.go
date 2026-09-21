package agents

import (
	"os/exec"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/adapters"
)

type Status string

const (
	Ready       Status = "ready"
	Degraded    Status = "degraded"
	Unavailable Status = "unavailable"
)

type Info struct {
	Name         string         `json:"name"`
	Installed    bool           `json:"installed"`
	Binary       string         `json:"binary,omitempty"`
	Path         string         `json:"path,omitempty"`
	Version      string         `json:"version,omitempty"`
	Status       Status         `json:"status"`
	Hint         string         `json:"hint,omitempty"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
}

func Known() []string {
	return []string{"generic-shell", "codex", "claude-code", "openclaw", "ollama"}
}

func Diagnose(name string) Info {
	name = strings.TrimSpace(strings.ToLower(name))
	info := Info{Name: name, Status: Unavailable, Binary: binaryFor(name)}
	if name == "generic-shell" {
		info.Installed = true
		info.Status = Ready
		info.Hint = "uses local shell"
		info.Capabilities = map[string]any{"supports_task_arg": false}
		return info
	}
	if info.Binary == "" {
		info.Hint = "unknown adapter"
		return info
	}
	p, err := exec.LookPath(info.Binary)
	if err != nil {
		info.Hint = "binary not found in PATH"
		return info
	}
	info.Path = p
	info.Installed = true
	info.Status = Ready
	if v := versionOf(info.Binary); v != "" {
		info.Version = v
	}
	reg := adapters.NewRegistry()
	if a, err := reg.Resolve(name); err == nil {
		info.Capabilities = map[string]any{
			"supports_task_arg":           a.Capabilities().SupportsTaskArg,
			"supports_env_task":           a.Capabilities().SupportsEnvTask,
			"supports_streaming_output":   a.Capabilities().SupportsStreamingOutput,
			"supports_native_events":      a.Capabilities().SupportsNativeEvents,
			"supports_native_checkpoints": a.Capabilities().SupportsNativeCheckpoints,
			"supports_native_diff":        a.Capabilities().SupportsNativeDiff,
			"supports_native_approval":    a.Capabilities().SupportsNativeApproval,
		}
	} else {
		info.Status = Degraded
		info.Hint = "binary installed but adapter not wired"
	}
	return info
}

func binaryFor(name string) string {
	switch name {
	case "codex":
		return "codex"
	case "claude-code":
		return "claude-code"
	case "openclaw":
		return "openclaw"
	case "ollama":
		return "ollama"
	default:
		return ""
	}
}

func versionOf(bin string) string {
	for _, args := range [][]string{{"--version"}, {"version"}, {"-v"}} {
		cmd := exec.Command(bin, args...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			s := strings.TrimSpace(string(out))
			if s != "" {
				if i := strings.IndexByte(s, '\n'); i > 0 {
					s = s[:i]
				}
				return s
			}
		}
	}
	return ""
}
