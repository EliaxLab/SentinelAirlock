package execution

import (
	"bytes"
	"context"
	"os/exec"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/adapters"
)

func runHost(inv adapters.Invocation, env []string, opts Options) (int, string, error) {
	ctx := context.Background()
	if opts.TimeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(opts.TimeoutSec)*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, inv.Executable, inv.Args...)
	cmd.Dir = inv.WorkingDir
	cmd.Env = append([]string{}, env...)
	cmd.Env = append(cmd.Env, inv.EnvOverrides...)

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
		return ee.ExitCode(), out.String(), err
	}
	return 1, out.String(), err
}
