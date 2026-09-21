package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/report"
	"github.com/EliaxLab/SentinelAirlock/internal/review"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

func reviewCmd() *cobra.Command {
	var state, note, reviewer string
	cmd := &cobra.Command{
		Use:   "review <run_id>",
		Short: "Set or inspect run review state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID, err := runmeta.ResolveRunID(args[0])
			if err != nil {
				return err
			}
			runDir := filepath.Join(".airlock", "runs", runID)
			if _, err := os.Stat(runDir); err != nil {
				return err
			}
			if strings.TrimSpace(state) == "" {
				r, err := review.Load(runDir)
				if err != nil {
					return err
				}
				fmt.Printf("run=%s state=%s reviewer=%s ts=%s note=%q\n", runID, r.State, r.Reviewer, r.Timestamp, r.Note)
				return nil
			}
			if reviewer == "" {
				reviewer = os.Getenv("USER")
			}
			prev, _ := review.Load(runDir)
			r := review.Record{State: review.State(state), PreviousState: prev.State, Note: note, Reviewer: reviewer}
			if err := review.Save(runDir, r); err != nil {
				return err
			}
			_ = events.AppendJSONLEvent(filepath.Join(runDir, "review_events.jsonl"), events.Event{
				TS:      time.Now().UTC(),
				Type:    "REVIEW_UPDATED",
				Summary: "review state updated",
				Meta: map[string]any{
					"state":          string(r.State),
					"previous_state": string(r.PreviousState),
					"reviewer":       reviewer,
					"note":           note,
				},
			})
			// Regenerate the static HTML report so the review status is reflected.
			if evs, err := events.ReadJSONL(filepath.Join(runDir, "events.jsonl")); err == nil {
				_ = report.Generate(runDir, evs)
			}
			refreshIndex()
			fmt.Printf("review updated run=%s state=%s reviewer=%s\n", runID, review.State(state), reviewer)
			return nil
		},
	}
	cmd.Flags().StringVar(&state, "state", "", "Review state: unreviewed|approved|rejected|needs-attention")
	cmd.Flags().StringVar(&note, "note", "", "Short reviewer note")
	cmd.Flags().StringVar(&reviewer, "reviewer", "", "Reviewer identity")
	return cmd
}
