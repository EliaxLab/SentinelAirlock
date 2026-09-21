package adapters

import (
	"fmt"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/session"
)

type CodexAdapter struct{}

func NewCodexAdapter() Adapter { return CodexAdapter{} }

func (CodexAdapter) Name() string { return "codex" }

func (CodexAdapter) Capabilities() CapabilitySet {
	return CapabilitySet{
		SupportsTaskArg:         true,
		SupportsEnvTask:         true,
		SupportsStreamingOutput: true,
	}
}

func (CodexAdapter) Prepare(ctx RunContext) (Invocation, error) {
	if ctx.Task == "" {
		return Invocation{}, fmt.Errorf("codex adapter requires --task")
	}
	// V1.3 reference adapter: structured invocation with task argument.
	return Invocation{
		Executable:     "codex",
		Args:           []string{ctx.Task},
		WorkingDir:     ctx.WorkspacePath,
		DisplayCommand: "codex " + ctx.Task,
	}, nil
}

func (CodexAdapter) Execute(ctx RunContext, inv Invocation) (ExecutionResult, error) {
	if ctx.SessionSink != nil {
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MODEL_INFO", Meta: map[string]any{"provider": "codex", "model": "codex-cli"}})
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MSG_USER", Content: ctx.Task})
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "TOOL_CALL", Content: inv.DisplayCommand})
	}
	res, err := ExecuteInvocation(ctx, inv)
	if ctx.SessionSink != nil {
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "TOOL_RESULT", Content: res.Output, Meta: map[string]any{"exit_code": res.ExitCode}})
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "SESSION_SUMMARY", Content: "session complete", Meta: map[string]any{"exit_code": res.ExitCode}})
	}
	return res, err
}
