package cli

import (
	"errors"
	"os"

	"github.com/spf13/cobra"
)

var Version = "dev"
var Commit = "none"
var BuildDate = "unknown"

var rootCmd = &cobra.Command{
	Use:   "airlock",
	Short: "Sentinel Airlock — universal wrapper + timeline recorder for coding agents",
}

func Execute() {
	rootCmd.Version = VersionString()
	if err := rootCmd.Execute(); err != nil {
		var ce *ciExitError
		if errors.As(err, &ce) {
			os.Exit(ce.code)
		}
		os.Exit(1)
	}
}

func VersionString() string {
	return Version + " (commit=" + Commit + ", built=" + BuildDate + ")"
}

func init() {
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(bootstrapCmd())
	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(sentinelCmd())
	rootCmd.AddCommand(fleetCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(agentsCmd())
	rootCmd.AddCommand(submitCmd())
	rootCmd.AddCommand(fetchCmd())
	rootCmd.AddCommand(workerCmd())
	rootCmd.AddCommand(rollbackCmd())
	rootCmd.AddCommand(inspectCmd())
	rootCmd.AddCommand(replayCmd())
	rootCmd.AddCommand(serveCmd())
	rootCmd.AddCommand(patchCmd())
	rootCmd.AddCommand(exportCmd())
	rootCmd.AddCommand(reviewCmd())
	rootCmd.AddCommand(compareCmd())
	rootCmd.AddCommand(runsCmd())
	rootCmd.AddCommand(doctorCmd())
	rootCmd.AddCommand(policyCmd())
	rootCmd.AddCommand(verifyCmd())
	rootCmd.AddCommand(indexCmd())
	rootCmd.AddCommand(whoamiCmd())
	rootCmd.AddCommand(cleanupCmd())
	rootCmd.AddCommand(ciCmd())
}
