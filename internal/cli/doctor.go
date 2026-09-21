package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/execution"
	"github.com/spf13/cobra"
)

func doctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local environment and install readiness",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("airlock version: %s\n", VersionString())
			fmt.Printf("os: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			fmt.Printf("cwd: %s\n", must(os.Getwd()))
			checkCommand("git")
			checkCommand("docker")
			checkCommand("colima")
			checkCommand("podman")
			checkWritable(".airlock")
			checkWritable(filepath.Join(".airlock", "runs"))
			checkOpener()
			checkSandboxSupport()
			return nil
		},
	}
	return cmd
}

func checkCommand(name string) {
	if p, err := exec.LookPath(name); err == nil {
		fmt.Printf("[OK]      %-18s %s\n", name, p)
	} else {
		fmt.Printf("[WARN]    %-18s missing (install or choose an alternative backend)\n", name)
	}
}

func checkWritable(path string) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		fmt.Printf("[BLOCKER] writable %-10s failed (%v)\n", path, err)
		return
	}
	probe := filepath.Join(path, ".airlock_write_probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
		fmt.Printf("[BLOCKER] writable %-10s failed (%v)\n", path, err)
		return
	}
	_ = os.Remove(probe)
	fmt.Printf("[OK]      writable %-10s ok\n", path)
}

func checkOpener() {
	candidates := []string{}
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{"open"}
	case "windows":
		candidates = []string{"cmd"}
	default:
		candidates = []string{"xdg-open", "open"}
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			fmt.Printf("[OK]      opener             %s\n", p)
			return
		}
	}
	fmt.Printf("[WARN]    opener             missing (%s)\n", strings.Join(candidates, ", "))
}

func checkSandboxSupport() {
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/Applications/Docker.app"); err == nil {
			fmt.Println("[OK]      docker-desktop     detected (/Applications/Docker.app)")
		} else {
			fmt.Println("[WARN]    docker-desktop     not detected")
		}
	}
	for _, rt := range []execution.Runtime{execution.RuntimeDocker, execution.RuntimeColima, execution.RuntimePodman} {
		info, err := execution.DetectRuntime(rt)
		if err != nil {
			fmt.Printf("[WARN]    runtime %-10s unavailable (%v)\n", rt, err)
			if info.Hint != "" {
				fmt.Printf("  hint: %s\n", info.Hint)
			}
			continue
		}
		fmt.Printf("[OK]      runtime %-10s available=%v access=%v socket=%s\n", rt, info.Available, info.CanAccess, info.SocketPath)
		if info.Hint != "" {
			fmt.Printf("  hint: %s\n", info.Hint)
		}
	}
}

func must(v string, err error) string {
	if err != nil {
		return ""
	}
	return v
}
