package cli

import (
	"encoding/json"
	"fmt"

	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

func verifyCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify <run_id>",
		Short: "Verify run digest and signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := runmeta.LoadArtifacts(args[0])
			if err != nil {
				return err
			}
			runID := a.RunID
			res, err := runmeta.VerifyRun(runID, a.Manifest)
			if err != nil {
				return err
			}
			if asJSON {
				b, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(b))
				return nil
			}
			switch res.Status {
			case "verified-signed":
				fmt.Printf("status=verified-signed run=%s manifest=%s\n", runID, a.ManifestPath)
			case "verified-unsigned":
				fmt.Printf("status=verified-unsigned run=%s\n", runID)
			case "hash-mismatch":
				fmt.Printf("status=hash-mismatch run=%s\n", runID)
			case "signature-invalid":
				fmt.Printf("status=signature-invalid run=%s\n", runID)
			case "signature-present-key-unavailable":
				fmt.Printf("status=degraded signature-present-key-unavailable run=%s\n", runID)
			default:
				fmt.Printf("status=%s run=%s\n", res.Status, runID)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit structured JSON result")
	return cmd
}
