package web

import (
	"strings"
	"testing"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
)

var ts = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func writeDeny(meta map[string]any) events.Event {
	return events.Event{
		TS: ts, Type: "POLICY_DENY", Path: ".env", Summary: "write blocked and reverted",
		Meta:     meta,
		Risk:     map[string]any{"level": "high", "category": "secrets", "reason": "touches protected secret/auth path"},
		Approval: map[string]any{"mode": "deny-high-risk", "decision": "deny"},
	}
}

func cmdEvent(decision string) events.Event {
	return events.Event{
		TS: ts, Type: "CMD", Meta: map[string]any{"cmd": "rm -rf src/"},
		Risk:     map[string]any{"level": "high", "category": "destructive", "reason": "recursive delete"},
		Approval: map[string]any{"mode": "deny-high-risk", "decision": decision},
	}
}

func explainOne(t *testing.T, evs []events.Event) decisionExplanation {
	t.Helper()
	got, omitted := explainDecisions("run1", evs, true, false)
	if len(got) != 1 || omitted != 0 {
		t.Fatalf("want exactly 1 explanation, got %d (omitted %d)", len(got), omitted)
	}
	return got[0]
}

func TestExplainBlockedBeforeExecution(t *testing.T) {
	x := explainOne(t, []events.Event{
		cmdEvent("deny"),
		{Type: "RUN_FAILED", Meta: map[string]any{"class": "policy"}},
	})
	if x.Outcome != outcomeBlockedBeforeExec || x.Class != "bad" {
		t.Fatalf("outcome = %s/%s", x.Outcome, x.Class)
	}
	for _, want := range []string{"rm -rf src/", "before it ran"} {
		if !strings.Contains(x.What, want) {
			t.Errorf("What missing %q: %s", want, x.What)
		}
	}
	if !strings.Contains(x.Why, "recursive delete") || !strings.Contains(x.Why, "deny-high-risk") {
		t.Errorf("Why = %s", x.Why)
	}
}

func TestExplainCommandDenyWithoutPolicyFailureIsNotClaimedPrevented(t *testing.T) {
	x := explainOne(t, []events.Event{cmdEvent("deny")})
	if x.Outcome != outcomeUnconfirmed {
		t.Fatalf("outcome = %s", x.Outcome)
	}
	if strings.Contains(strings.ToLower(x.What), "before it ran") {
		t.Errorf("must not claim prevention: %s", x.What)
	}
}

func TestExplainAllowedCommandProducesNothing(t *testing.T) {
	if got, _ := explainDecisions("r", []events.Event{cmdEvent("allow")}, true, false); len(got) != 0 {
		t.Fatalf("allowed command explained: %+v", got)
	}
}

func TestExplainDetectedAndReverted(t *testing.T) {
	x := explainOne(t, []events.Event{writeDeny(map[string]any{"op": "WRITE", "reverted": true})})
	if x.Outcome != outcomeReverted || x.Class != "ok" {
		t.Fatalf("outcome = %s/%s", x.Outcome, x.Class)
	}
	if !strings.Contains(x.What, "not prevented") || !strings.Contains(x.What, ".env") {
		t.Errorf("What = %s", x.What)
	}
	if !strings.Contains(x.Next, "built-in protected path") {
		t.Errorf("protected path should say policy cannot allow it: %s", x.Next)
	}
	if !strings.Contains(x.Evidence, "POLICY_DENY") || !strings.Contains(x.Evidence, "2026-11-19") {
		t.Errorf("Evidence = %s", x.Evidence)
	}
}

func TestExplainRevertFailed(t *testing.T) {
	x := explainOne(t, []events.Event{writeDeny(map[string]any{"op": "CREATE", "reverted": false, "revert_error": "permission denied"})})
	if x.Outcome != outcomeRevertFailed || x.Class != "bad" {
		t.Fatalf("outcome = %s/%s", x.Outcome, x.Class)
	}
	if !strings.Contains(x.What, "permission denied") || !strings.Contains(x.What, "still be on disk") {
		t.Errorf("What = %s", x.What)
	}
	if x.NextCommand != "airlock rollback run1 --path .env --dry-run" {
		t.Errorf("NextCommand = %q", x.NextCommand)
	}
}

func TestExplainRevertFailedOmitsRollbackWhenUnavailable(t *testing.T) {
	ev := []events.Event{writeDeny(map[string]any{"reverted": false})}
	for name, args := range map[string][2]bool{"no checkpoint": {false, false}, "sentinel active": {true, true}} {
		got, _ := explainDecisions("run1", ev, args[0], args[1])
		if got[0].NextCommand != "" {
			t.Errorf("%s: offered rollback command %q", name, got[0].NextCommand)
		}
	}
}

func TestExplainRevertErrorAloneIsFailure(t *testing.T) {
	x := explainOne(t, []events.Event{writeDeny(map[string]any{"revert_error": "disk full"})})
	if x.Outcome != outcomeRevertFailed {
		t.Fatalf("outcome = %s", x.Outcome)
	}
}

func TestExplainOlderRunMissingEvidence(t *testing.T) {
	// No meta, risk, approval, or path at all: must not panic or claim a revert.
	x := explainOne(t, []events.Event{{Type: "POLICY_DENY"}})
	if x.Outcome != outcomeUnconfirmed {
		t.Fatalf("outcome = %s", x.Outcome)
	}
	for _, want := range []string{"not recorded", "No rule or reason was recorded"} {
		if !strings.Contains(x.What+x.Why, want) {
			t.Errorf("missing %q in %q / %q", want, x.What, x.Why)
		}
	}
	if strings.Contains(x.What, "reverted") && !strings.Contains(x.What, "not record whether") {
		t.Errorf("claimed a revert: %s", x.What)
	}
	if x.NextCommand != "" {
		t.Errorf("no path, no command: %q", x.NextCommand)
	}
}

func TestExplainApprovalRequiredAndUnspecificRule(t *testing.T) {
	e := events.Event{
		Type: "APPROVAL_REQUIRED", Path: "docs/a b.md", Meta: map[string]any{"op": "WRITE", "reverted": true},
		Risk: map[string]any{"reason": "outside allowlist or deny rule matched"},
	}
	x := explainOne(t, []events.Event{e})
	if !strings.Contains(x.What, "needed approval") {
		t.Errorf("What = %s", x.What)
	}
	if !strings.Contains(x.Why, "does not record which pattern") {
		t.Errorf("must not invent a specific rule: %s", x.Why)
	}
}

func TestExplainCapsAndCountsOmitted(t *testing.T) {
	var evs []events.Event
	for i := 0; i < maxExplanations+5; i++ {
		evs = append(evs, writeDeny(map[string]any{"reverted": true}))
	}
	got, omitted := explainDecisions("r", evs, true, false)
	if len(got) != maxExplanations || omitted != 5 {
		t.Fatalf("got %d, omitted %d", len(got), omitted)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a b/it's.md"); got != `'a b/it'\''s.md'` {
		t.Errorf("got %s", got)
	}
	if shellQuote("src/x.go") != "src/x.go" {
		t.Error("plain path should be unquoted")
	}
}
