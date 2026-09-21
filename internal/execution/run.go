package execution

import (
	"fmt"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/adapters"
)

func Run(inv adapters.Invocation, baseEnv []string, opts Options) (int, string, error) {
	mode := opts.Mode
	switch mode {
	case ModeContainer:
		info, err := DetectRuntime(opts.ContainerRuntime)
		if err != nil || !info.Available || !info.CanAccess {
			if opts.FallbackWorkspace {
				return runHost(inv, baseEnv, opts)
			}
			hint := ""
			if info.Hint != "" {
				hint = " " + info.Hint
			}
			return 1, "", fmt.Errorf("container runtime unavailable (%v).%s", err, hint)
		}
		return runContainerWithRuntime(inv, baseEnv, opts, info.Name)
	case ModeWorkspace, ModeOff:
		return runHost(inv, baseEnv, opts)
	default:
		return 1, "", fmt.Errorf("unknown sandbox mode: %s", strings.TrimSpace(string(mode)))
	}
}
