package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/index"
	"github.com/spf13/cobra"
)

func runsCmd() *cobra.Command {
	var (
		mode       string
		target     string
		worker     string
		signed     string
		review     string
		policyPack string
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "runs",
		Short: "List indexed runs",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := index.Load(index.DefaultPath())
			if err != nil {
				store, err = index.Rebuild(".airlock/runs")
				if err != nil {
					return err
				}
				_ = index.Save(index.DefaultPath(), store)
			}
			rows := make([]index.Entry, 0, len(store.Runs))
			for _, r := range store.Runs {
				if mode != "" && !strings.EqualFold(r.Mode, mode) {
					continue
				}
				if target != "" && !strings.EqualFold(r.Target, target) {
					continue
				}
				if worker != "" && !strings.EqualFold(r.Worker, worker) {
					continue
				}
				if signed == "signed" && !r.Signed {
					continue
				}
				if signed == "unsigned" && r.Signed {
					continue
				}
				if review != "" && !strings.EqualFold(r.ReviewState, review) {
					continue
				}
				if policyPack != "" && !strings.EqualFold(r.PolicyPack, policyPack) {
					continue
				}
				rows = append(rows, r)
			}
			if asJSON {
				b, _ := json.MarshalIndent(rows, "", "  ")
				fmt.Println(string(b))
				return nil
			}
			fmt.Printf("Runs: %d\n", len(rows))
			for _, r := range rows {
				fmt.Printf("%s ts=%s target=%s worker=%s mode=%s pack=%s sandbox=%s signed=%t verified=%t review=%s patch=%t export=%t high=%d denied=%d\n",
					r.RunID, r.Timestamp, r.Target, r.Worker, r.Mode, r.PolicyPack, r.Sandbox, r.Signed, r.Verified, r.ReviewState, r.Patch, r.Export, r.HighRiskCount, r.DeniedCount)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "", "Filter by execution mode")
	cmd.Flags().StringVar(&target, "target", "", "Filter by target (local|remote)")
	cmd.Flags().StringVar(&worker, "worker", "", "Filter by worker name")
	cmd.Flags().StringVar(&signed, "signed", "", "Filter by signature state: signed|unsigned")
	cmd.Flags().StringVar(&review, "review", "", "Filter by review state")
	cmd.Flags().StringVar(&policyPack, "policy-pack", "", "Filter by policy pack")
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return cmd
}
