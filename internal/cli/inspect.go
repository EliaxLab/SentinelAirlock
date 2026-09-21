package cli

import (
	"fmt"

	"github.com/EliaxLab/SentinelAirlock/internal/output"
	"github.com/EliaxLab/SentinelAirlock/internal/replay"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

func inspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <run_id>",
		Short: "Inspect a run from stored artifacts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]
			a, err := runmeta.LoadArtifacts(runID)
			if err != nil {
				return err
			}
			output.PrintInspectSummary(a)
			fmt.Println("Recent events:")
			replay.PrintTimeline(a.Events, 8)
			return nil
		},
	}
	return cmd
}
