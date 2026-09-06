package fleet

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestSessionStore(t *testing.T) (*SessionStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet-sessions.json")
	s, err := OpenSessionStore(path, DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func upd(sessionID string, startedAt time.Time) SessionUpdate {
	return SessionUpdate{SessionID: sessionID, StartedAt: startedAt, RepoPath: "/repo/a", MachineID: "mach-1"}
}

// --- 1/2/3/4/5: identity across sessions ------------------------------------

func TestSessionStore_RestartCreatesSecondSessionUnderSameSentinel(t *testing.T) {
	s, _ := newTestSessionStore(t)
	now := time.Now().UTC()

	if _, err := s.Upsert("sen-1", upd("sess-A", now.Add(-time.Hour)), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upsert("sen-1", upd("sess-B", now), now); err != nil {
		t.Fatal(err)
	}

	sessions := s.ForSentinel("sen-1")
	if len(sessions) != 2 {
		t.Fatalf("a restart must add a session, not replace one: got %d", len(sessions))
	}
	if sessions[0].SessionID != "sess-B" {
		t.Fatalf("expected newest first, got %s", sessions[0].SessionID)
	}
	for _, sess := range sessions {
		if sess.SentinelID != "sen-1" {
			t.Fatalf("both sessions must belong to the same durable sentinel id, got %q", sess.SentinelID)
		}
	}
	if sessions[0].SessionID == sessions[1].SessionID {
		t.Fatal("session ids must differ across restarts")
	}
}

// --- 6/7/8/9/10/11: lifecycle states ----------------------------------------

func TestSessionStatus_ActiveOnlyForCurrentAndFresh(t *testing.T) {
	now := time.Now().UTC()
	fresh := FleetSession{SessionID: "sess-A", LastSeenAt: now}

	if got := SessionStatus(fresh, "sess-A", now); got != SessionActive {
		t.Fatalf("the current session with a fresh heartbeat should be ACTIVE, got %s", got)
	}
	// Same row, but the Sentinel has since reported a different current
	// session: it must not stay ACTIVE just because its last heartbeat said so.
	if got := SessionStatus(fresh, "sess-B", now); got != SessionInterrupted {
		t.Fatalf("a superseded session must not remain ACTIVE, got %s", got)
	}
	stale := FleetSession{SessionID: "sess-A", LastSeenAt: now.Add(-OfflineThreshold - time.Second)}
	if got := SessionStatus(stale, "sess-A", now); got != SessionInterrupted {
		t.Fatalf("a stale heartbeat must become INTERRUPTED, got %s", got)
	}
}

func TestSessionStore_GracefulStopRecordsStoppedAtAndSurvivesRestartOfSentinel(t *testing.T) {
	s, _ := newTestSessionStore(t)
	now := time.Now().UTC()
	if _, err := s.Upsert("sen-1", upd("sess-A", now.Add(-time.Hour)), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	stoppedAt := now.Add(-30 * time.Minute)
	if _, err := s.MarkStopped("sen-1", "sess-A", stoppedAt, now); err != nil {
		t.Fatal(err)
	}
	sess, _ := s.Get("sess-A")
	if sess.StoppedAt == nil || !sess.StoppedAt.Equal(stoppedAt) {
		t.Fatalf("a clean stop must record its own stopped_at, got %v", sess.StoppedAt)
	}
	if got := SessionStatus(sess, "sess-B", now); got != SessionStopped {
		t.Fatalf("expected STOPPED, got %s", got)
	}

	// A new session becomes current; the stopped one stays in history.
	if _, err := s.Upsert("sen-1", upd("sess-B", now), now); err != nil {
		t.Fatal(err)
	}
	b, _ := s.Get("sess-B")
	if got := SessionStatus(b, "sess-B", now); got != SessionActive {
		t.Fatalf("the new session should be ACTIVE, got %s", got)
	}
	if len(s.ForSentinel("sen-1")) != 2 {
		t.Fatal("stopping a session must not remove it from history")
	}
}

func TestSessionStore_InterruptedSessionNeverGetsAFabricatedStoppedAt(t *testing.T) {
	s, _ := newTestSessionStore(t)
	now := time.Now().UTC()
	// A session that was killed: it reported, then simply stopped reporting.
	if _, err := s.Upsert("sen-1", upd("sess-A", now.Add(-2*time.Hour)), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sess, _ := s.Get("sess-A")
	if got := SessionStatus(sess, "sess-A", now); got != SessionInterrupted {
		t.Fatalf("expected INTERRUPTED for an abandoned session, got %s", got)
	}
	if sess.StoppedAt != nil {
		t.Fatalf("a process that never reported stopping must not be given a stopped_at, got %v", sess.StoppedAt)
	}
}

func TestSessionStore_MarkStoppedIsFirstWriteWins(t *testing.T) {
	// A live final heartbeat and a buffered SESSION_STOPPED report can both
	// describe the same shutdown. They must converge on one timestamp.
	s, _ := newTestSessionStore(t)
	now := time.Now().UTC()
	if _, err := s.Upsert("sen-1", upd("sess-A", now.Add(-time.Hour)), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	first := now.Add(-10 * time.Minute)
	if _, err := s.MarkStopped("sen-1", "sess-A", first, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkStopped("sen-1", "sess-A", now, now); err != nil {
		t.Fatal(err)
	}
	sess, _ := s.Get("sess-A")
	if !sess.StoppedAt.Equal(first) {
		t.Fatalf("a duplicate stop must not rewrite stopped_at: got %v, want %v", sess.StoppedAt, first)
	}
}

func TestSessionStore_MarkStoppedForUnknownSessionDoesNotInventOne(t *testing.T) {
	s, _ := newTestSessionStore(t)
	if _, err := s.MarkStopped("sen-1", "never-recorded", time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("never-recorded"); ok {
		t.Fatal("a stop notice alone must not manufacture a session whose activity was never observed")
	}
}

// --- 12: historical policy state is immutable -------------------------------

func TestSessionStore_HistoricalPolicyIsNotRewrittenByLaterSessions(t *testing.T) {
	s, _ := newTestSessionStore(t)
	base := time.Now().UTC().Add(-3 * time.Hour)

	a := upd("sess-A", base)
	a.PolicyID, a.PolicyVersion, a.PolicyHash = "production", "10", "hash10"
	if _, err := s.Upsert("sen-1", a, base); err != nil {
		t.Fatal(err)
	}
	b := upd("sess-B", base.Add(time.Hour))
	b.PolicyID, b.PolicyVersion, b.PolicyHash = "production", "11", "hash11"
	if _, err := s.Upsert("sen-1", b, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c := upd("sess-C", base.Add(2*time.Hour))
	c.PolicyID, c.PolicyVersion, c.PolicyHash = "production", "12", "hash12"
	if _, err := s.Upsert("sen-1", c, base.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// The Sentinel moves on to v13 in its current session. History must not
	// follow it.
	c2 := upd("sess-C", base.Add(2*time.Hour))
	c2.PolicyID, c2.PolicyVersion, c2.PolicyHash = "production", "13", "hash13"
	if _, err := s.Upsert("sen-1", c2, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	for _, want := range []struct{ id, version, hash string }{
		{"sess-A", "10", "hash10"},
		{"sess-B", "11", "hash11"},
		{"sess-C", "13", "hash13"}, // its own current session legitimately advanced
	} {
		sess, ok := s.Get(want.id)
		if !ok {
			t.Fatalf("%s missing", want.id)
		}
		if sess.PolicyVersion != want.version || sess.PolicyHash != want.hash {
			t.Fatalf("%s must still report v%s/%s, got v%s/%s",
				want.id, want.version, want.hash, sess.PolicyVersion, sess.PolicyHash)
		}
	}
}

// --- 13/14: counter semantics -----------------------------------------------

func TestSessionStore_CountersAreSessionScopedAndTotalsAreDerived(t *testing.T) {
	s, _ := newTestSessionStore(t)
	base := time.Now().UTC().Add(-2 * time.Hour)

	a := upd("sess-A", base)
	a.AllowCount, a.DenyCount, a.RevertedCount = 100, 4, 4
	if _, err := s.Upsert("sen-1", a, base); err != nil {
		t.Fatal(err)
	}
	b := upd("sess-B", base.Add(time.Hour))
	b.AllowCount, b.DenyCount, b.RevertedCount, b.RevertFailedCount = 40, 2, 1, 1
	if _, err := s.Upsert("sen-1", b, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	sessA, _ := s.Get("sess-A")
	sessB, _ := s.Get("sess-B")
	if sessA.AllowCount != 100 || sessB.AllowCount != 40 {
		t.Fatalf("per-session counters must stay independent: A=%d B=%d", sessA.AllowCount, sessB.AllowCount)
	}

	totals := Totals(s.ForSentinel("sen-1"))
	if totals.SessionCount != 2 || totals.AllowCount != 140 || totals.DenyCount != 6 ||
		totals.RevertedCount != 5 || totals.RevertFailedCount != 1 {
		t.Fatalf("totals must equal the sum of their sessions, got %+v", totals)
	}
}

// --- 15/16: ownership and idempotency ---------------------------------------

func TestSessionStore_SentinelCannotMutateAnotherSentinelsSession(t *testing.T) {
	s, _ := newTestSessionStore(t)
	now := time.Now().UTC()
	if _, err := s.Upsert("sen-1", upd("sess-A", now), now); err != nil {
		t.Fatal(err)
	}

	hostile := upd("sess-A", now)
	hostile.AllowCount = 9999
	hostile.PolicyID = "attacker-policy"
	if _, err := s.Upsert("sen-2", hostile, now); !errors.Is(err, ErrSessionOwnedByAnotherSentinel) {
		t.Fatalf("sen-2 must not be able to write sen-1's session, got %v", err)
	}
	if _, err := s.MarkStopped("sen-2", "sess-A", now, now); !errors.Is(err, ErrSessionOwnedByAnotherSentinel) {
		t.Fatalf("sen-2 must not be able to stop sen-1's session, got %v", err)
	}

	sess, _ := s.Get("sess-A")
	if sess.SentinelID != "sen-1" || sess.AllowCount == 9999 || sess.PolicyID == "attacker-policy" {
		t.Fatalf("the victim session was mutated: %+v", sess)
	}
	if sess.StoppedAt != nil {
		t.Fatal("the victim session must not have been stopped")
	}
}

func TestSessionStore_RepeatedUpdatesAreIdempotent(t *testing.T) {
	s, _ := newTestSessionStore(t)
	started := time.Now().UTC().Add(-time.Hour)
	u := upd("sess-A", started)
	u.AllowCount = 7

	for i := 0; i < 5; i++ {
		if _, err := s.Upsert("sen-1", u, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.ForSentinel("sen-1")); n != 1 {
		t.Fatalf("replaying an update must not fork history, got %d sessions", n)
	}
	sess, _ := s.Get("sess-A")
	if !sess.StartedAt.Equal(started) {
		t.Fatalf("started_at must be sticky across replays, got %v", sess.StartedAt)
	}
	if sess.AllowCount != 7 {
		t.Fatalf("counters should settle at the reported value, got %d", sess.AllowCount)
	}

	// A later heartbeat that omits started_at must not blank it.
	noStart := upd("sess-A", time.Time{})
	noStart.AllowCount = 9
	if _, err := s.Upsert("sen-1", noStart, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	sess, _ = s.Get("sess-A")
	if !sess.StartedAt.Equal(started) {
		t.Fatalf("an omitted started_at must not overwrite the original, got %v", sess.StartedAt)
	}
}

// --- 17: control-plane restart preserves history ----------------------------

func TestSessionStore_HistorySurvivesControlPlaneRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-sessions.json")
	first, err := OpenSessionStore(path, DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := first.Upsert("sen-1", upd("sess-A", now.Add(-time.Hour)), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.MarkStopped("sen-1", "sess-A", now.Add(-30*time.Minute), now); err != nil {
		t.Fatal(err)
	}

	second, err := OpenSessionStore(path, DefaultRetention())
	if err != nil {
		t.Fatal(err)
	}
	sess, ok := second.Get("sess-A")
	if !ok {
		t.Fatal("session history must survive a control-plane restart")
	}
	if sess.StoppedAt == nil {
		t.Fatal("a recorded clean stop must survive a restart")
	}
}

// --- 29/30: retention -------------------------------------------------------

func TestSessionStore_RetentionKeepsNewestAndNeverRemovesTheActiveSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-sessions.json")
	s, err := OpenSessionStore(path, RetentionPolicy{Enabled: true, MaxSessionsPerSentinel: 3})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-10 * time.Hour)
	for i := 0; i < 6; i++ {
		id := "sess-" + string(rune('A'+i))
		if _, err := s.Upsert("sen-1", upd(id, base.Add(time.Duration(i)*time.Hour)), base.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	sessions := s.ForSentinel("sen-1")
	if len(sessions) != 3 {
		t.Fatalf("retention should keep 3 sessions, got %d", len(sessions))
	}
	if _, ok := s.Get("sess-F"); !ok {
		t.Fatal("the newest session must be retained")
	}
	if _, ok := s.Get("sess-A"); ok {
		t.Fatal("the oldest session should have aged out")
	}
}

func TestSessionStore_RetentionNeverRemovesProtectedActiveSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-sessions.json")
	// Populate under lenient retention first, so the rows survive to be
	// pruned deliberately below -- retention also runs on write, so an
	// aggressive policy here would leave nothing for Prune to act on and the
	// test would prove nothing.
	seed, err := OpenSessionStore(path, RetentionPolicy{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-100 * time.Hour)
	for _, id := range []string{"sess-A", "sess-B", "sess-CURRENT"} {
		if _, err := seed.Upsert("sen-1", upd(id, base), base); err != nil {
			t.Fatal(err)
		}
	}

	// Reopen with a policy under which every row is eligible for removal.
	// The active session must still survive it.
	s, err := OpenSessionStore(path, RetentionPolicy{Enabled: true, MaxAge: time.Nanosecond, MaxSessionsPerSentinel: 1})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := s.Prune(time.Now().UTC(), map[string]string{"sen-1": "sess-CURRENT"})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("expected the two eligible old sessions to be removed, got %d", removed)
	}
	if _, ok := s.Get("sess-CURRENT"); !ok {
		t.Fatal("retention must never remove the currently active session, however aggressive the policy")
	}
	if len(s.ForSentinel("sen-1")) != 1 {
		t.Fatalf("expected only the protected session to remain, got %d", len(s.ForSentinel("sen-1")))
	}
}

func TestSessionStore_RetentionDisabledKeepsEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-sessions.json")
	s, err := OpenSessionStore(path, RetentionPolicy{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-1000 * time.Hour)
	for i := 0; i < 12; i++ {
		id := "sess-" + string(rune('A'+i))
		if _, err := s.Upsert("sen-1", upd(id, base), base); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.ForSentinel("sen-1")); n != 12 {
		t.Fatalf("retention is disabled; expected all 12 sessions, got %d", n)
	}
}

func TestSessionStore_SessionsOfDifferentSentinelsDoNotInterfere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-sessions.json")
	s, err := OpenSessionStore(path, RetentionPolicy{Enabled: true, MaxSessionsPerSentinel: 2})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-5 * time.Hour)
	for i := 0; i < 4; i++ {
		if _, err := s.Upsert("sen-1", upd("a"+string(rune('0'+i)), base.Add(time.Duration(i)*time.Minute)), base); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Upsert("sen-2", upd("b"+string(rune('0'+i)), base.Add(time.Duration(i)*time.Minute)), base); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.ForSentinel("sen-1")); n != 2 {
		t.Fatalf("sen-1 should retain 2, got %d", n)
	}
	if n := len(s.ForSentinel("sen-2")); n != 2 {
		t.Fatalf("sen-2 should retain 2, got %d", n)
	}
}

// --- 28: the evidence reference is logical, never a path --------------------

func TestEvidenceRef_IsLogicalAndLocal(t *testing.T) {
	ref := LocalEvidenceRef("sess-A")
	if ref.Location != "LOCAL" || ref.SessionID != "sess-A" {
		t.Fatalf("unexpected evidence ref: %+v", ref)
	}
	// A path would imply the control plane could open it. It cannot.
	if filepath.IsAbs(ref.Kind) || filepath.IsAbs(ref.SessionID) || filepath.IsAbs(ref.Location) {
		t.Fatal("an evidence reference must never carry a filesystem path")
	}
}

// --- 41: paths with spaces --------------------------------------------------

func TestSessionStore_HandlesRepoPathsWithSpaces(t *testing.T) {
	s, _ := newTestSessionStore(t)
	now := time.Now().UTC()
	u := upd("sess-A", now)
	u.RepoPath = "/Users/alice/My Projects/payments api"
	if _, err := s.Upsert("sen-1", u, now); err != nil {
		t.Fatal(err)
	}
	sess, _ := s.Get("sess-A")
	if sess.RepoPath != "/Users/alice/My Projects/payments api" {
		t.Fatalf("repo paths with spaces must round-trip intact, got %q", sess.RepoPath)
	}
}
