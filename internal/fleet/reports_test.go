package fleet

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestOutbox(t *testing.T) (*Outbox, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet-outbox.json")
	o, err := OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	return o, path
}

func report(id string, at time.Time) Report {
	return Report{ID: id, SentinelID: "sen-1", Type: ReportDeny, At: at, Path: ".env"}
}

// --- 19: reports accumulate while offline -----------------------------------

func TestOutbox_AccumulatesAndSurvivesRestart(t *testing.T) {
	o, path := newTestOutbox(t)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		if err := o.Add(report(string(rune('a'+i)), now)); err != nil {
			t.Fatal(err)
		}
	}
	if o.Len() != 5 {
		t.Fatalf("expected 5 buffered reports, got %d", o.Len())
	}

	// A Sentinel restart during an outage must not lose what was observed.
	reopened, err := OpenOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Len() != 5 {
		t.Fatalf("buffered reports must be durable across a restart, got %d", reopened.Len())
	}
}

func TestOutbox_DeduplicatesByIDLocally(t *testing.T) {
	o, _ := newTestOutbox(t)
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		if err := o.Add(report("same", now)); err != nil {
			t.Fatal(err)
		}
	}
	if o.Len() != 1 {
		t.Fatalf("deterministic ids should keep re-buffering idempotent, got %d entries", o.Len())
	}
}

// --- 20: the buffer is bounded ----------------------------------------------

func TestOutbox_IsBoundedAndDropsOldestFirst(t *testing.T) {
	o, _ := newTestOutbox(t)
	now := time.Now().UTC()
	total := MaxBufferedReports + 50
	for i := 0; i < total; i++ {
		if err := o.Add(Report{ID: idFor(i), SentinelID: "sen-1", Type: ReportDeny, At: now}); err != nil {
			t.Fatal(err)
		}
	}
	if o.Len() != MaxBufferedReports {
		t.Fatalf("the outbox must stay bounded at %d, got %d", MaxBufferedReports, o.Len())
	}
	if o.DroppedCount() != 50 {
		t.Fatalf("dropped reports must be counted so a long outage's cost is visible, got %d", o.DroppedCount())
	}
	// The newest reports are the ones retained.
	pending := o.Batch()
	if pending[0].ID == idFor(0) {
		t.Fatal("the oldest reports should have been dropped, not the newest")
	}
}

func idFor(i int) string {
	return ReportID("sen-1", "sess-1", ReportDeny, time.Unix(int64(i), 0).UTC(), "path")
}

func TestOutbox_BatchIsBoundedPerFlush(t *testing.T) {
	o, _ := newTestOutbox(t)
	now := time.Now().UTC()
	for i := 0; i < MaxReportsPerFlush+25; i++ {
		if err := o.Add(Report{ID: idFor(i), SentinelID: "sen-1", Type: ReportDeny, At: now}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(o.Batch()); got != MaxReportsPerFlush {
		t.Fatalf("one flush must be bounded at %d reports, got %d", MaxReportsPerFlush, got)
	}
}

// --- 21: only acknowledged reports are cleared ------------------------------

func TestOutbox_AckClearsOnlyAcknowledgedReports(t *testing.T) {
	o, _ := newTestOutbox(t)
	now := time.Now().UTC()
	for _, id := range []string{"a", "b", "c"} {
		if err := o.Add(report(id, now)); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Ack([]string{"a", "c"}); err != nil {
		t.Fatal(err)
	}
	pending := o.Batch()
	if len(pending) != 1 || pending[0].ID != "b" {
		t.Fatalf("an unacknowledged report must stay buffered for the next flush, got %+v", pending)
	}
}

func TestReportID_IsDeterministicAndDistinguishing(t *testing.T) {
	at := time.Now().UTC()
	a := ReportID("sen-1", "sess-1", ReportDeny, at, ".env")
	if a != ReportID("sen-1", "sess-1", ReportDeny, at, ".env") {
		t.Fatal("the same event must always produce the same id -- that is what makes upload retries safe")
	}
	for _, other := range []string{
		ReportID("sen-2", "sess-1", ReportDeny, at, ".env"),
		ReportID("sen-1", "sess-2", ReportDeny, at, ".env"),
		ReportID("sen-1", "sess-1", ReportReverted, at, ".env"),
		ReportID("sen-1", "sess-1", ReportDeny, at.Add(time.Second), ".env"),
		ReportID("sen-1", "sess-1", ReportDeny, at, "secrets/key"),
	} {
		if other == a {
			t.Fatal("distinct events must not collide")
		}
	}
}

// --- alert store ------------------------------------------------------------

func TestAlertStore_IsBoundedAndDeduplicated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-alerts.json")
	store, err := OpenAlertStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := make([]Report, 0, 60)
	for i := 0; i < 60; i++ {
		batch = append(batch, Report{ID: idFor(i), Type: ReportDeny, At: now})
	}
	resp, err := store.Ingest("sen-1", batch)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted != 60 || resp.Duplicates != 0 {
		t.Fatalf("unexpected ingest result: %+v", resp)
	}
	resp, err = store.Ingest("sen-1", batch)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted != 0 || resp.Duplicates != 60 {
		t.Fatalf("re-ingesting the same batch must be entirely duplicate: %+v", resp)
	}
	if store.Len() != 60 {
		t.Fatalf("expected 60 retained alerts, got %d", store.Len())
	}

	// Overflow the retention window and confirm it stays bounded.
	big := make([]Report, 0, MaxStoredAlerts)
	for i := 0; i < MaxStoredAlerts; i++ {
		big = append(big, Report{ID: idFor(1000 + i), Type: ReportDeny, At: now})
	}
	if _, err := store.Ingest("sen-1", big); err != nil {
		t.Fatal(err)
	}
	if store.Len() != MaxStoredAlerts {
		t.Fatalf("the alert feed must stay bounded at %d, got %d", MaxStoredAlerts, store.Len())
	}

	reopened, err := OpenAlertStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Len() != MaxStoredAlerts {
		t.Fatalf("alerts must survive a control-plane restart, got %d", reopened.Len())
	}
}

func TestAlertStore_RecentIsNewestFirst(t *testing.T) {
	store, err := OpenAlertStore(filepath.Join(t.TempDir(), "fleet-alerts.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	if _, err := store.Ingest("sen-1", []Report{
		{ID: "old", Type: ReportDeny, At: base},
		{ID: "new", Type: ReportRevertFailed, At: base.Add(30 * time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	recent := store.Recent(10)
	if len(recent) != 2 || recent[0].ID != "new" {
		t.Fatalf("expected newest-first ordering, got %+v", recent)
	}
	if len(store.Recent(1)) != 1 {
		t.Fatal("Recent must honor its limit")
	}
}
