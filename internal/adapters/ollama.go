package adapters

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/providers"
	"github.com/EliaxLab/SentinelAirlock/internal/session"
)

type OllamaAdapter struct{}

func NewOllamaAdapter() Adapter { return OllamaAdapter{} }

func (OllamaAdapter) Name() string { return "ollama" }

func (OllamaAdapter) Capabilities() CapabilitySet {
	return CapabilitySet{
		SupportsTaskArg:         true,
		SupportsEnvTask:         true,
		SupportsStreamingOutput: false,
	}
}

func (OllamaAdapter) Prepare(ctx RunContext) (Invocation, error) {
	if strings.TrimSpace(ctx.Task) == "" {
		return Invocation{}, fmt.Errorf("ollama adapter requires --task")
	}
	return Invocation{Executable: "ollama", Args: []string{"run", "llama3", ctx.Task}, WorkingDir: ctx.WorkspacePath, DisplayCommand: "ollama run llama3 " + ctx.Task}, nil
}

func (OllamaAdapter) Execute(ctx RunContext, inv Invocation) (ExecutionResult, error) {
	if ctx.SessionSink != nil {
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MODEL_INFO", Meta: map[string]any{"provider": "ollama", "model": "llama3", "config": "default"}})
		ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MSG_USER", Content: ctx.Task})
	}

	pr := providers.NewRegistry()
	p, err := pr.Resolve("ollama")
	if err != nil {
		return ExecutionResult{}, err
	}
	resp, genErr := p.Generate(context.Background(), providers.GenerateRequest{Model: "llama3", Prompt: ctx.Task})
	if ctx.SessionSink != nil {
		if genErr != nil {
			ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "TOOL_CALL", Content: "ollama run", Meta: map[string]any{"status": "error", "error": genErr.Error()}})
			ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "SESSION_SUMMARY", Content: "session failed", Meta: map[string]any{"status": "error"}})
		} else {
			ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "TOOL_CALL", Content: "ollama run", Meta: map[string]any{"status": "ok"}})
			ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "MSG_ASSISTANT", Content: resp.Output})
			ctx.SessionSink.Add(session.Event{TS: time.Now().UTC(), Type: "SESSION_SUMMARY", Content: "session complete", Meta: map[string]any{"status": "ok"}})
		}
	}
	if genErr != nil {
		return ExecutionResult{ExitCode: 1, Output: genErr.Error()}, genErr
	}
	return ExecutionResult{ExitCode: 0, Output: resp.Output, Meta: resp.Meta}, nil
}
