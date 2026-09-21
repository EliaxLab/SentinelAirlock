package replay

import (
	"fmt"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
)

func PrintTimeline(evs []events.Event, tail int) {
	if tail <= 0 || tail > len(evs) {
		tail = len(evs)
	}
	start := len(evs) - tail
	if start < 0 {
		start = 0
	}
	for _, e := range evs[start:] {
		fmt.Println(formatEvent(e))
	}
}

func formatEvent(e events.Event) string {
	ts := e.TS.UTC().Format(time.RFC3339)
	decision, _ := e.Approval["decision"].(string)

	// Flag policy denials and command blocks so they stand out in the tail.
	marker := "  "
	if e.Type == "POLICY_DENY" || e.Type == "RUN_FAILED" || decision == "deny" {
		marker = "⛔"
	} else if strings.HasPrefix(e.Type, "FILE_") {
		marker = "· "
	}

	line := fmt.Sprintf("%s [%s] %s", marker, ts, e.Type)
	if e.Path != "" {
		line += " path=" + e.Path
	}
	if lvl, ok := e.Risk["level"].(string); ok && lvl != "" {
		line += " risk=" + lvl
	}
	if decision != "" {
		line += " approval=" + decision
	}
	if e.Summary != "" {
		line += " " + e.Summary
	}
	if e.Type == "POLICY_DENY" || decision == "deny" || e.Type == "RUN_FAILED" {
		if reason, ok := e.Meta["reason"].(string); ok && reason != "" {
			line += " (" + reason + ")"
		}
	}
	return line
}
