package adapters

import (
	"fmt"
	"runtime"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/session"
)

type GenericShellAdapter struct{}

func NewGenericShellAdapter() Adapter { return GenericShellAdapter{} }

func (GenericShellAdapter) Name() string { return "generic-shell" }

func (GenericShellAdapter) Capabilities() CapabilitySet {
	return CapabilitySet{
		SupportsTaskArg:         false,
		SupportsEnvTask:         true,
		SupportsStreamingOutput: false,
	}
}

func (GenericShellAdapter) Prepare(ctx RunContext) (Invocation, error) {
	if ctx.Command == "" {
		return Invocation{}, fmt.Errorf("generic-shell requires --cmd")
	}
	exe, args := shellInvocation(ctx.Command)
	return Invocation{
		Executable:     exe,
		Args:           args,
		WorkingDir:     ctx.WorkspacePath,
		DisplayCommand: ctx.Command,
	}, nil
}

// shellInvocation returns the shell executable and arguments for the current OS.
// Windows: powershell -NoProfile -NonInteractive -Command <cmd>
// Others:  bash -lc <cmd>
func shellInvocation(cmd string) (string, []string) {
	return shellInvocationForOS(runtime.GOOS, cmd)
}

func shellInvocationForOS(goos, cmd string) (string, []string) {
	if goos == "windows" {
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", cmd}
	}
	return "bash", []string{"-lc", cmd}
}

func (GenericShellAdapter) Execute(ctx RunContext, inv Invocation) (ExecutionResult, error) {
	if ctx.SessionSink != nil {
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MODEL_INFO", Meta: map[string]any{"provider": "generic-shell", "model": "shell"}})
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MSG_USER", Content: inv.DisplayCommand})
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "TOOL_CALL", Content: inv.DisplayCommand})
	}
	res, err := ExecuteInvocation(ctx, inv)
	if ctx.SessionSink != nil {
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "TOOL_RESULT", Content: res.Output, Meta: map[string]any{"exit_code": res.ExitCode}})
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "SESSION_SUMMARY", Content: "session complete", Meta: map[string]any{"exit_code": res.ExitCode}})
	}
	return res, err
}
