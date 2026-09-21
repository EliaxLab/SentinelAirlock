package cli

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/replay"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/EliaxLab/SentinelAirlock/internal/session"
	"github.com/spf13/cobra"
)

type timelineRow struct {
	TS       time.Time      `json:"ts"`
	Stream   string         `json:"stream"`
	Type     string         `json:"type"`
	Path     string         `json:"path,omitempty"`
	Summary  string         `json:"summary,omitempty"`
	Risk     map[string]any `json:"risk,omitempty"`
	Approval map[string]any `json:"approval,omitempty"`
	Meta     map[string]any `json:"meta,omitempty"`
}

func replayCmd() *cobra.Command {
	var (
		open   bool
		asJSON bool
		tail   int
		stream string
	)
	cmd := &cobra.Command{
		Use:   "replay <run_id>",
		Short: "Replay a run in terminal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]
			a, err := runmeta.LoadArtifacts(runID)
			if err != nil {
				return err
			}
			rows := mergeRows(a.Events, a.SessionEvents, stream)
			if asJSON {
				payload := map[string]any{
					"run_id":              a.RunID,
					"report_path":         a.ReportPath,
					"events_path":         a.EventsPath,
					"session_events_path": a.SessionEventsPath,
					"event_count":         len(rows),
					"timeline":            rows,
				}
				b, err := json.MarshalIndent(payload, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(b))
			} else {
				fmt.Printf("Report: %s\n", a.ReportPath)
				if a.Manifest.ExecutionMode != "" {
					fmt.Printf("Mode: %s\n", a.Manifest.ExecutionMode)
				}
				if a.Manifest.PolicyPack.Name != "" {
					fmt.Printf("Policy pack: %s\n", a.Manifest.PolicyPack.Name)
				}
				replay.PrintTimeline(rowsToEvents(rows), tail)
			}
			if open {
				if err := openPath(a.ReportPath); err != nil {
					fmt.Printf("Open failed (%v). Report path: %s\n", err, a.ReportPath)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&open, "open", false, "Open HTML report in browser")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print timeline as JSON")
	cmd.Flags().IntVar(&tail, "tail", 10, "Number of timeline rows to show")
	cmd.Flags().StringVar(&stream, "stream", "both", "Timeline stream filter: system | session | both")
	return cmd
}

func mergeRows(sys []events.Event, sess []session.Event, stream string) []timelineRow {
	rows := []timelineRow{}
	if stream == "both" || stream == "system" {
		for _, e := range sys {
			rows = append(rows, timelineRow{TS: e.TS, Stream: "system", Type: e.Type, Path: e.Path, Summary: e.Summary, Risk: e.Risk, Approval: e.Approval, Meta: e.Meta})
		}
	}
	if stream == "both" || stream == "session" {
		for _, e := range sess {
			rows = append(rows, timelineRow{TS: e.TS, Stream: "session", Type: e.Type, Summary: e.Content, Meta: e.Meta})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TS.Before(rows[j].TS) })
	return rows
}

func rowsToEvents(rows []timelineRow) []events.Event {
	out := make([]events.Event, 0, len(rows))
	for _, r := range rows {
		s := r.Summary
		if r.Stream == "session" {
			s = "session: " + s
		}
		out = append(out, events.Event{TS: r.TS, Type: r.Type, Path: r.Path, Summary: s, Meta: r.Meta, Risk: r.Risk, Approval: r.Approval})
	}
	return out
}

func openPath(path string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", path).Run()
	case "windows":
		return exec.Command("cmd", "/C", "start", path).Run()
	default:
		return exec.Command("xdg-open", path).Run()
	}
}
