package web

import (
	"fmt"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
)

// Outcome values for a decision explanation. They are deliberately distinct:
// a policy denial alone never implies the action was prevented or undone.
const (
	outcomeBlockedBeforeExec = "blocked-before-execution"
	outcomeReverted          = "detected-and-reverted"
	outcomeRevertFailed      = "revert-failed"
	outcomeUnconfirmed       = "unconfirmed"
)

// maxExplanations caps the cards rendered on the page; the Denied table below
// still lists every event.
const maxExplanations = 20

// decisionExplanation is a template-built, read-only explanation of one
// recorded policy decision. Every sentence is derived from fields present in
// events.jsonl; where a field is absent the text says so instead of guessing.
type decisionExplanation struct {
	Outcome     string
	Badge       string
	Class       string // ok | warn | bad (matches the viewer's badge classes)
	What        string
	Why         string
	Next        string
	NextCommand string
	Evidence    string
}

// explainDecisions builds explanations from recorded events only. It does not
// consult policy files, call a model, or change any state.
//
// Two evidence shapes exist today:
//   - CMD with a non-allow approval decision (+ RUN_FAILED class=policy):
//     the command was never launched.
//   - POLICY_DENY / APPROVAL_REQUIRED from the recorder: the write already
//     happened on disk, was detected, and Airlock tried to revert it.
func explainDecisions(runID string, evs []events.Event, hasCheckpoint, rollbackBlocked bool) (out []decisionExplanation, omitted int) {
	policyFailure := false
	for _, e := range evs {
		if e.Type == "RUN_FAILED" {
			if class, _ := e.Meta["class"].(string); class == "policy" {
				policyFailure = true
			}
		}
	}

	var all []decisionExplanation
	for _, e := range evs {
		switch e.Type {
		case "CMD":
			if x, ok := explainCommand(e, policyFailure); ok {
				all = append(all, x)
			}
		case "POLICY_DENY", "APPROVAL_REQUIRED":
			all = append(all, explainWrite(runID, e, hasCheckpoint, rollbackBlocked))
		}
	}
	if len(all) > maxExplanations {
		return all[:maxExplanations], len(all) - maxExplanations
	}
	return all, 0
}

func explainCommand(e events.Event, policyFailure bool) (decisionExplanation, bool) {
	decision, _ := e.Approval["decision"].(string)
	if decision == "" || decision == "allow" {
		return decisionExplanation{}, false
	}
	cmd, _ := e.Meta["cmd"].(string)
	mode, _ := e.Approval["mode"].(string)
	x := decisionExplanation{
		What:     "Airlock was asked to run " + quoteOr(cmd, "a command (not recorded)") + ".",
		Why:      riskWhy(e, mode),
		Evidence: evidenceRef(e),
	}
	if policyFailure {
		x.Outcome, x.Badge, x.Class = outcomeBlockedBeforeExec, "BLOCKED BEFORE EXECUTION", "bad"
		x.What += " It was blocked before it ran, so it made no changes."
		x.Next = "Check the command is what you intended. If it is safe, re-run it with a less restrictive approval mode."
		return x, true
	}
	// Denied on paper, but the run does not record a policy failure. Don't claim prevention.
	x.Outcome, x.Badge, x.Class = outcomeUnconfirmed, "DENIED — PREVENTION UNCONFIRMED", "warn"
	x.What += " Policy denied it, but this run does not record that the command was stopped."
	x.Next = "Inspect the run's events and patch to see what actually changed."
	return x, true
}

func explainWrite(runID string, e events.Event, hasCheckpoint, rollbackBlocked bool) decisionExplanation {
	mode, _ := e.Approval["mode"].(string)
	op, _ := e.Meta["op"].(string)
	verb := "change"
	if op != "" {
		verb = strings.ToLower(normalizeSentinelOperation(op))
	}
	target := quoteOr(e.Path, "a path (not recorded)")
	x := decisionExplanation{Why: riskWhy(e, mode), Evidence: evidenceRef(e)}
	if e.Type == "APPROVAL_REQUIRED" {
		x.What = "A " + verb + " to " + target + " needed approval."
	} else {
		x.What = "A " + verb + " to " + target + " was denied by policy."
	}

	reverted, hasReverted := e.Meta["reverted"].(bool)
	revertErr, _ := e.Meta["revert_error"].(string)
	switch {
	case revertErr != "" || (hasReverted && !reverted):
		x.Outcome, x.Badge, x.Class = outcomeRevertFailed, "REVERT FAILED", "bad"
		x.What += " Airlock detected it after it happened and tried to undo it, but the revert failed"
		if revertErr != "" {
			x.What += " (" + revertErr + ")"
		}
		x.What += ". The change may still be on disk."
		x.Next = "Inspect the file and restore it manually."
		if hasCheckpoint && !rollbackBlocked && e.Path != "" {
			x.NextCommand = fmt.Sprintf("airlock rollback %s --path %s --dry-run", runID, shellQuote(e.Path))
		}
	case hasReverted:
		x.Outcome, x.Badge, x.Class = outcomeReverted, "DETECTED AND REVERTED", "ok"
		x.What += " The write was not prevented: Airlock detected it after it happened and the recorded revert succeeded."
		x.Next = "Nothing to undo. If the agent should be allowed to do this, change the matching policy rule and re-run."
		if reason, _ := e.Risk["reason"].(string); strings.Contains(reason, "protected secret/auth path") {
			x.Next = "Nothing to undo. This is a built-in protected path, so policy cannot allow it; have the agent write elsewhere."
		}
	default:
		x.Outcome, x.Badge, x.Class = outcomeUnconfirmed, "REVERT UNCONFIRMED", "warn"
		x.What += " This run did not record whether the change was reverted, so it may still be on disk."
		x.Next = "Check the file's current contents before trusting it."
	}
	return x
}

// riskWhy states the recorded reason without inventing a specific rule: the
// event stores the classifier's reason, not which airlock.yaml pattern matched.
func riskWhy(e events.Event, mode string) string {
	reason, _ := e.Risk["reason"].(string)
	category, _ := e.Risk["category"].(string)
	level, _ := e.Risk["level"].(string)
	if reason == "" {
		return "No rule or reason was recorded for this decision."
	}
	s := "Rule applied: " + reason
	if category != "" || level != "" {
		s += " (" + strings.Trim(strings.Join([]string{category, level + " risk"}, ", "), ", ") + ")"
	}
	s += "."
	if mode != "" {
		s += " Approval mode: " + mode + "."
	}
	if strings.Contains(reason, "deny rule matched") {
		s += " The event does not record which pattern matched."
	}
	return s
}

func evidenceRef(e events.Event) string {
	ref := "events.jsonl · " + e.Type
	if !e.TS.IsZero() {
		ref += " · " + e.TS.UTC().Format("2006-01-02 15:04:05Z")
	}
	return ref
}

func quoteOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return "“" + s + "”"
}

func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t'\"$`\\!*?[](){};&|<>#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
