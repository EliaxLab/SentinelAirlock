package cli

import (
	"fmt"

	"github.com/EliaxLab/SentinelAirlock/internal/review"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

func compareCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "compare <run_a> <run_b>",
		Short: "Compare two runs",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := runmeta.LoadArtifacts(args[0])
			if err != nil {
				return err
			}
			b, err := runmeta.LoadArtifacts(args[1])
			if err != nil {
				return err
			}
			ra, _ := review.Load(a.RunDir)
			rb, _ := review.Load(b.RunDir)
			fmt.Printf("Run A: %s\n", a.RunID)
			fmt.Printf("Run B: %s\n", b.RunID)
			fmt.Println("Diff summary:")
			fmt.Printf("- high risk: %d -> %d\n", a.Manifest.RiskSummary.HighCount, b.Manifest.RiskSummary.HighCount)
			fmt.Printf("- denied actions: %d -> %d\n", a.Manifest.ApprovalSummary.DeniedCount, b.Manifest.ApprovalSummary.DeniedCount)
			fmt.Printf("- touched paths: %d -> %d\n", len(a.Manifest.TouchedPaths), len(b.Manifest.TouchedPaths))
			fmt.Printf("- denied paths: %d -> %d\n", len(a.Manifest.DeniedPaths), len(b.Manifest.DeniedPaths))
			fmt.Printf("- patch present: %t -> %t\n", a.Manifest.PatchPath != "", b.Manifest.PatchPath != "")
			fmt.Printf("- signed: %t -> %t\n", a.Manifest.Digest.Signed, b.Manifest.Digest.Signed)
			fmt.Printf("- review state: %s -> %s\n", ra.State, rb.State)
			return nil
		},
	}
}
