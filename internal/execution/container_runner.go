package execution

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/adapters"
)

func runContainerWithRuntime(inv adapters.Invocation, baseEnv []string, opts Options, rt Runtime) (int, string, error) {
	image := strings.TrimSpace(opts.Image)
	if image == "" {
		image = "alpine:3.20"
	}

	workspaceHost := inv.WorkingDir
	workspaceCtr := "/workspace"

	dockerArgs := []string{"run", "--rm", "-w", workspaceCtr, "-v", workspaceHost + ":" + workspaceCtr}
	switch opts.Network {
	case NetworkOff:
		dockerArgs = append(dockerArgs, "--network", "none")
	case NetworkAllowlist:
		// Not truly enforced in v1.6; map to none for conservative behavior.
		dockerArgs = append(dockerArgs, "--network", "none")
	}
	for _, e := range filterEnv(baseEnv, opts.AllowEnvKeys) {
		dockerArgs = append(dockerArgs, "-e", e)
	}
	for _, e := range inv.EnvOverrides {
		dockerArgs = append(dockerArgs, "-e", e)
	}

	insideCmd := shellJoin(inv.Executable, inv.Args)
	dockerArgs = append(dockerArgs, image, "sh", "-lc", insideCmd)

	bin := runtimeBinary(rt)
	ctx := context.Background()
	if opts.TimeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(opts.TimeoutSec)*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, bin, dockerArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		return 0, out.String(), nil
	}
	if ctx.Err() != nil {
		return 124, out.String(), ctx.Err()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String(), fmt.Errorf("container run failed: %w", err)
	}
	return 1, out.String(), fmt.Errorf("container run failed: %w", err)
}

func runtimeBinary(rt Runtime) string {
	switch rt {
	case RuntimePodman:
		return "podman"
	default:
		// Docker Desktop and Colima both use docker CLI surface.
		return "docker"
	}
}

func filterEnv(base []string, allowKeys []string) []string {
	allow := map[string]struct{}{"AIRLOCK_TASK": {}}
	for _, k := range allowKeys {
		k = strings.TrimSpace(k)
		if k != "" {
			allow[k] = struct{}{}
		}
	}
	out := []string{}
	for _, kv := range base {
		i := strings.Index(kv, "=")
		if i <= 0 {
			continue
		}
		k := kv[:i]
		if _, ok := allow[k]; ok {
			out = append(out, kv)
		}
	}
	return out
}

func shellJoin(exe string, args []string) string {
	parts := []string{escapeShell(filepath.ToSlash(exe))}
	for _, a := range args {
		parts = append(parts, escapeShell(a))
	}
	return strings.Join(parts, " ")
}

func escapeShell(s string) string {
	if s == "" {
		return "''"
	}
	s = strings.ReplaceAll(s, "'", "'\\''")
	return "'" + s + "'"
}
