package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirelahmed-commits/SentinelAirlock/internal/fleet"
)

// serveHandler starts an httptest server for h and registers its cleanup.
func serveHandler(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// historyFleet is a control plane with trust (14B) and session history (14C).
type historyFleet struct {
	*trustFleet
	sessions *fleet.SessionStore
}

func newHistoryFleet(t *testing.T, retention fleet.RetentionPolicy) *historyFleet {
	t.Helper()
	dir := t.TempDir()
	tf := buildTrustFleet(t, dir)
	sessions, err := fleet.OpenSessionStore(filepath.Join(dir, "fleet-sessions.json"), retention)
	if err != nil {
		t.Fatal(err)
	}
	hf := &historyFleet{trustFleet: tf, sessions: sessions}
	return hf
}

func (hf *historyFleet) handler() http.Handler {
	return fleet.NewServerWithOptions(hf.store, hf.policyStore, "", fleet.ServerOptions{
		AuthStore: hf.authStore, AlertStore: hf.alertStore, SessionStore: hf.sessions,
		SigningKey: hf.key, RequireEnrollment: true,
	}).Handler()
}

// assignOn posts a desired-policy assignment to an explicitly given base URL,
// since a historyFleet runs its own server rather than trustFleet's.
func (hf *historyFleet) assignOn(t *testing.T, baseURL, sentinelID, policyID string, version int, allowRollback bool) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"policy_id": policyID, "version": version, "allow_rollback": allowRollback})
	resp, err := http.Post(baseURL+"/api/fleet/sentinels/"+sentinelID+"/assign", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("assign failed: %s: %s", resp.Status, msg)
	}
}

func (hf *historyFleet) sessionsFor(t *testing.T, sentinelID string) []fleet.FleetSession {
	t.Helper()
	return hf.sessions.ForSentinel(sentinelID)
}

// waitForSessions polls until the Sentinel's history has at least n rows.
func (hf *historyFleet) waitForSessions(t *testing.T, sentinelID string, n int) []fleet.FleetSession {
	t.Helper()
	var got []fleet.FleetSession
	pollUntil(t, 4*time.Second, func() bool {
		got = hf.sessionsFor(t, sentinelID)
		return len(got) >= n
	})
	return got
}

// --- 1/2/3/4/5/6/7/8/9: the multi-session lifecycle end to end --------------

func TestSentinelHistory_RestartCreatesNewSessionAndKeepsTheOld(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	hf := newHistoryFleet(t, fleet.DefaultRetention())
	srv := serveHandler(t, hf.handler())
	sentinelID := sentinelIDFor(t, repoAbs)

	// Session A.
	first := startTrustSentinel(t, repoAbs, srv.URL, hf.enrollToken(t))
	if !pollUntil(t, 3*time.Second, func() bool { return first.getIdentityState() == "AUTHENTICATED" }) {
		t.Fatal("expected the sentinel to enroll")
	}
	sessionA := first.sessionID
	hf.waitForSessions(t, sentinelID, 1)

	// Graceful stop.
	first.shutdown()
	if !pollUntil(t, 3*time.Second, func() bool {
		s, ok := hf.sessions.Get(sessionA)
		return ok && s.StoppedAt != nil
	}) {
		t.Fatal("a graceful stop must be recorded as STOPPED with a stopped_at")
	}

	// Session B.
	second, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer second.shutdown()
	sessionB := second.sessionID

	if sessionA == sessionB {
		t.Fatal("a restart must mint a new session id")
	}
	sessions := hf.waitForSessions(t, sentinelID, 2)
	if len(sessions) != 2 {
		t.Fatalf("expected both sessions in history, got %d", len(sessions))
	}
	// The durable Sentinel identity is unchanged across the restart.
	for _, s := range sessions {
		if s.SentinelID != sentinelID {
			t.Fatalf("sentinel id must be stable across restarts, got %q", s.SentinelID)
		}
	}

	now := time.Now().UTC()
	a, _ := hf.sessions.Get(sessionA)
	if got := fleet.SessionStatus(a, sessionB, now); got != fleet.SessionStopped {
		t.Fatalf("session A should be STOPPED, got %s", got)
	}
	if !pollUntil(t, 3*time.Second, func() bool {
		b, ok := hf.sessions.Get(sessionB)
		return ok && fleet.SessionStatus(b, sessionB, time.Now().UTC()) == fleet.SessionActive
	}) {
		t.Fatal("session B should become CURRENT/ACTIVE")
	}
}

// --- 10/11: ungraceful disappearance -> INTERRUPTED, no fake stopped_at -----

func TestSentinelHistory_AbandonedSessionBecomesInterruptedWithoutFabricatedStop(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	hf := newHistoryFleet(t, fleet.DefaultRetention())
	srv := serveHandler(t, hf.handler())
	sentinelID := sentinelIDFor(t, repoAbs)

	sess := startTrustSentinel(t, repoAbs, srv.URL, hf.enrollToken(t))
	if !pollUntil(t, 3*time.Second, func() bool { return sess.getIdentityState() == "AUTHENTICATED" }) {
		t.Fatal("expected enrollment")
	}
	sessionA := sess.sessionID
	hf.waitForSessions(t, sentinelID, 1)

	// Simulate a kill: stop the fleet goroutine and the recorder WITHOUT the
	// graceful stop report, exactly as an unexpected process death would.
	close(sess.fleetStopCh)
	<-sess.fleetDone
	sess.fleetStopCh = nil // prevent the deferred shutdown from reporting a clean stop
	if sess.rec != nil {
		_ = sess.rec.Stop()
	}
	_ = sess.logger.Close()

	a, _ := hf.sessions.Get(sessionA)
	if a.StoppedAt != nil {
		t.Fatal("a killed session must never be given a stopped_at")
	}
	// Once the heartbeat ages past the offline threshold, it reads INTERRUPTED.
	stale := a
	stale.LastSeenAt = time.Now().UTC().Add(-fleet.OfflineThreshold - time.Second)
	if got := fleet.SessionStatus(stale, sessionA, time.Now().UTC()); got != fleet.SessionInterrupted {
		t.Fatalf("an abandoned session must become INTERRUPTED, got %s", got)
	}

	// A later session starts; the interrupted one stays in history.
	next, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer next.shutdown()
	sessions := hf.waitForSessions(t, sentinelID, 2)
	if len(sessions) != 2 {
		t.Fatalf("the interrupted session must remain in history, got %d", len(sessions))
	}
	a, _ = hf.sessions.Get(sessionA)
	if a.StoppedAt != nil {
		t.Fatal("starting a new session must not retroactively mark the old one cleanly stopped")
	}
}

// --- 12/13: per-session policy and counters stay independent ----------------

func TestSentinelHistory_SessionsRecordTheirOwnPolicyAndCounters(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	hf := newHistoryFleet(t, fleet.DefaultRetention())
	srv := serveHandler(t, hf.handler())
	sentinelID := sentinelIDFor(t, repoAbs)

	if _, err := hf.policyStore.Create("production", "v1", denySpecialYAML); err != nil {
		t.Fatal(err)
	}
	hf.assignOn(t, srv.URL, sentinelID, "production", 1, false)

	first := startTrustSentinel(t, repoAbs, srv.URL, hf.enrollToken(t))
	if !pollUntil(t, 4*time.Second, func() bool { return first.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected v1 to reconcile")
	}
	sessionA := first.sessionID
	// Generate one denial so this session has activity of its own.
	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 4*time.Second, func() bool {
		s, ok := hf.sessions.Get(sessionA)
		return ok && s.DenyCount > 0 && s.PolicyVersion == "1"
	}) {
		s, _ := hf.sessions.Get(sessionA)
		t.Fatalf("session A should record its own denial under v1, got %+v", s)
	}
	first.shutdown()

	// v2 arrives, and a new session picks it up.
	if _, err := hf.policyStore.AddVersion("production", "v2", allowAllYAML); err != nil {
		t.Fatal(err)
	}
	hf.assignOn(t, srv.URL, sentinelID, "production", 2, false)

	second, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer second.shutdown()
	if !pollUntil(t, 4*time.Second, func() bool { return second.getFleetPolicyRef().Version == 2 }) {
		t.Fatal("expected v2 to reconcile in the new session")
	}
	if !pollUntil(t, 4*time.Second, func() bool {
		s, ok := hf.sessions.Get(second.sessionID)
		return ok && s.PolicyVersion == "2"
	}) {
		t.Fatal("session B should record v2")
	}

	// The critical property: session A still says v1 after the fleet moved on.
	a, _ := hf.sessions.Get(sessionA)
	if a.PolicyVersion != "1" {
		t.Fatalf("history must not be rewritten by a later policy: session A now says v%s", a.PolicyVersion)
	}
	b, _ := hf.sessions.Get(second.sessionID)
	if a.DenyCount == 0 {
		t.Fatal("session A should have retained its own deny count")
	}
	if b.DenyCount != 0 {
		t.Fatalf("session B's counters must be its own, got deny=%d", b.DenyCount)
	}
}

// --- 19/20/21/22: control-plane outage, then reconnect ----------------------

func TestSentinelHistory_OutageKeepsGovernanceAndReconcilesStopOnReconnect(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	hf := newHistoryFleet(t, fleet.DefaultRetention())
	sentinelID := sentinelIDFor(t, repoAbs)

	addr := reserveTestAddr(t)
	fleetURL := "http://" + addr
	srv := startOn(t, addr, hf.handler())

	first := startTrustSentinel(t, repoAbs, fleetURL, hf.enrollToken(t))
	if !pollUntil(t, 3*time.Second, func() bool { return first.getIdentityState() == "AUTHENTICATED" }) {
		t.Fatal("expected enrollment")
	}
	sessionA := first.sessionID
	hf.waitForSessions(t, sentinelID, 1)

	// Fleet goes away, then the Sentinel is stopped gracefully. Local
	// shutdown must succeed regardless, and the stop must be buffered.
	srv.Close()
	first.shutdown()

	a, _ := hf.sessions.Get(sessionA)
	if a.StoppedAt != nil {
		t.Fatal("the control plane was down; it cannot have recorded a stop yet")
	}
	outbox, err := fleet.OpenOutbox(fleetOutboxPath(repoAbs))
	if err != nil {
		t.Fatal(err)
	}
	foundStop := false
	for _, r := range outbox.Batch() {
		if r.Type == fleet.ReportSessionStopped && r.SessionID == sessionA {
			foundStop = true
		}
	}
	if !foundStop {
		t.Fatal("a stop that could not be delivered must be buffered durably for a later session to flush")
	}

	// Local evidence is untouched by any of this.
	if _, err := os.Stat(filepath.Join(repoAbs, ".airlock", "runs", sessionA)); err != nil {
		t.Fatalf("local evidence for the stopped session must still exist: %v", err)
	}

	// Fleet returns; a new session flushes the buffered stop.
	restarted := startOn(t, addr, hf.handler())
	defer restarted.Close()
	second, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: fleetURL})
	if err != nil {
		t.Fatal(err)
	}
	defer second.shutdown()

	if !pollUntil(t, 6*time.Second, func() bool {
		s, ok := hf.sessions.Get(sessionA)
		return ok && s.StoppedAt != nil
	}) {
		t.Fatal("the buffered stop should reconcile session A to STOPPED after reconnect")
	}
	// 21: no duplicate rows appeared for either session.
	sessions := hf.sessionsFor(t, sentinelID)
	seen := map[string]int{}
	for _, s := range sessions {
		seen[s.SessionID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("session %s appears %d times; reconnect must not duplicate history", id, n)
		}
	}
	if len(sessions) != 2 {
		t.Fatalf("expected exactly 2 sessions, got %d", len(sessions))
	}
}

// --- 34/35: history sync off ------------------------------------------------

func TestSentinelHistory_SyncDisabledSuppressesHistoryButKeepsHealthAndEnforcement(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	hf := newHistoryFleet(t, fleet.DefaultRetention())
	srv := serveHandler(t, hf.handler())
	sentinelID := sentinelIDFor(t, repoAbs)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false,
		fleetOptions{URL: srv.URL, EnrollToken: hf.enrollToken(t), HistorySyncDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()

	// Health still works: the Sentinel is enrolled and reporting.
	if !pollUntil(t, 4*time.Second, func() bool {
		rec, ok := hf.store.Get(sentinelID)
		return ok && fleet.Health(rec, time.Now().UTC()) == "ACTIVE"
	}) {
		t.Fatal("health heartbeat must keep working when history sync is off")
	}
	// ...but no history is recorded.
	if n := len(hf.sessionsFor(t, sentinelID)); n != 0 {
		t.Fatalf("history sync is off; expected no session metadata, got %d rows", n)
	}
	// ...and local enforcement is entirely unaffected.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 3*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, ".env"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("local governance must be unaffected by the history-sync setting")
	}
}

// --- 31/32/33: retention touches Fleet metadata only ------------------------

func TestSentinelHistory_FleetRetentionNeverTouchesLocalState(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	// Retention that keeps only one session per Sentinel.
	hf := newHistoryFleet(t, fleet.RetentionPolicy{Enabled: true, MaxSessionsPerSentinel: 1})
	srv := serveHandler(t, hf.handler())
	sentinelID := sentinelIDFor(t, repoAbs)

	if _, err := hf.policyStore.Create("production", "v1", denySpecialYAML); err != nil {
		t.Fatal(err)
	}
	hf.assignOn(t, srv.URL, sentinelID, "production", 1, false)

	first := startTrustSentinel(t, repoAbs, srv.URL, hf.enrollToken(t))
	if !pollUntil(t, 4*time.Second, func() bool { return first.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected v1 to reconcile so an LKG exists")
	}
	sessionA := first.sessionID
	hf.waitForSessions(t, sentinelID, 1)
	first.shutdown()

	second, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer second.shutdown()
	if !pollUntil(t, 4*time.Second, func() bool {
		_, ok := hf.sessions.Get(second.sessionID)
		return ok
	}) {
		t.Fatal("the new session should be recorded")
	}

	// Fleet aged the old session's METADATA out...
	if !pollUntil(t, 3*time.Second, func() bool {
		_, ok := hf.sessions.Get(sessionA)
		return !ok
	}) {
		t.Fatal("retention should have removed the older session's fleet metadata")
	}

	// ...and touched nothing on the Sentinel's machine.
	if _, err := os.Stat(filepath.Join(repoAbs, ".airlock", "runs", sessionA)); err != nil {
		t.Fatalf("fleet retention must never delete local evidence: %v", err)
	}
	if _, err := os.Stat(fleetPolicyLKGPath(repoAbs)); err != nil {
		t.Fatalf("fleet retention must never delete the local last-known-good policy: %v", err)
	}
	if _, err := os.Stat(fleetCredentialPath(repoAbs)); err != nil {
		t.Fatalf("fleet retention must never delete the sentinel credential: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoAbs, ".airlock", "sentinel_id")); err != nil {
		t.Fatalf("fleet retention must never delete the durable sentinel identity: %v", err)
	}
}

// --- 26/27: nothing but metadata ever leaves the machine --------------------

func TestSentinelHistory_NoEvidenceOrContentsAreEverUploaded(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	hf := newHistoryFleet(t, fleet.DefaultRetention())

	// Record every request body the control plane receives.
	var mu sync.Mutex
	bodies := []string{}
	inner := hf.handler()
	recording := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, string(b))
			mu.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		inner.ServeHTTP(w, r)
	})
	srv := serveHandler(t, recording)

	sess := startTrustSentinel(t, repoAbs, srv.URL, hf.enrollToken(t))
	defer sess.shutdown()
	if !pollUntil(t, 3*time.Second, func() bool { return sess.getIdentityState() == "AUTHENTICATED" }) {
		t.Fatal("expected enrollment")
	}

	// Write a file with distinctive contents that is allowed, and one that is
	// denied. Neither file's CONTENTS may ever appear in a request body.
	secret := "SUPER-SECRET-CONTENT-9f3a2b"
	if err := os.WriteFile(filepath.Join(dir, "status.txt"), []byte(secret+"-allowed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(secret+"-denied\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 4*time.Second, func() bool {
		s, ok := hf.sessions.Get(sess.sessionID)
		return ok && s.AllowCount > 0
	}) {
		t.Fatal("expected the session to report governance activity")
	}
	// Give the outbox a chance to flush alerts too.
	pollUntil(t, 3*time.Second, func() bool { return sess.bufferedReportCount() == 0 })

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("expected to have captured request bodies")
	}
	for i, body := range bodies {
		if strings.Contains(body, secret) {
			t.Fatalf("request %d carried file contents to the control plane:\n%s", i, body)
		}
		for _, forbidden := range []string{"\"diff\"", "\"patch\"", "\"prompt\"", "events.jsonl"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("request %d carried %s:\n%s", i, forbidden, body)
			}
		}
	}
	// The path itself is legitimate metadata and is expected; contents are not.
	sessionRow, _ := hf.sessions.Get(sess.sessionID)
	if sessionRow.AllowCount == 0 {
		t.Fatal("test did not actually exercise the reporting path")
	}
}

// --- 44: the CLI reports accurate history without the browser UI ------------

func TestFleetSessionsCLI_ReportsAccurateHistory(t *testing.T) {
	hf := newHistoryFleet(t, fleet.DefaultRetention())
	srv := serveHandler(t, hf.handler())
	now := time.Now().UTC()

	// A stopped session and a current one, written directly so the CLI is
	// exercised against known values.
	if _, err := hf.sessions.Upsert("sen-1", fleet.SessionUpdate{
		SessionID: "sess-old", StartedAt: now.Add(-2 * time.Hour), RepoPath: "/repo/a",
		PolicyID: "production", PolicyVersion: "10", SignatureState: "VERIFIED",
		AllowCount: 100, DenyCount: 4, RevertedCount: 4,
	}, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := hf.sessions.MarkStopped("sen-1", "sess-old", now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := hf.sessions.Upsert("sen-1", fleet.SessionUpdate{
		SessionID: "sess-now", StartedAt: now, RepoPath: "/repo/a",
		PolicyID: "production", PolicyVersion: "12", SignatureState: "VERIFIED",
		AllowCount: 40, DenyCount: 2, RevertedCount: 1, RevertFailedCount: 1,
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := hf.store.UpsertHeartbeat("sen-1", func(r *fleet.Record) {
		r.SessionID = "sess-now"
		r.LastHeartbeat = now
	}); err != nil {
		t.Fatal(err)
	}

	var resp fleet.SessionListResponse
	if err := fleetGet(srv.URL, "", "/api/fleet/sessions?sentinel=sen-1", &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(resp.Sessions))
	}
	byID := map[string]fleet.SessionView{}
	for _, v := range resp.Sessions {
		byID[v.SessionID] = v
	}
	if got := sessionStateLabel(byID["sess-now"]); got != "CURRENT/ACTIVE" {
		t.Fatalf("the current session should render as CURRENT/ACTIVE, got %q", got)
	}
	if got := sessionStateLabel(byID["sess-old"]); got != "HIST/STOPPED" {
		t.Fatalf("the stopped session should render as HIST/STOPPED, got %q", got)
	}
	if got := sessionEndedLabel(byID["sess-now"]); got != "-" {
		t.Fatalf("a running session has no end, got %q", got)
	}
	if got := sessionEndedLabel(byID["sess-old"]); got == "no clean stop" || got == "-" {
		t.Fatalf("a cleanly stopped session should show when it ended, got %q", got)
	}
	// Historical policy is per session, and totals are the derived sum.
	if byID["sess-old"].PolicyVersion != "10" || byID["sess-now"].PolicyVersion != "12" {
		t.Fatalf("each session must report its own policy: old=%s now=%s",
			byID["sess-old"].PolicyVersion, byID["sess-now"].PolicyVersion)
	}
	if resp.Totals == nil || resp.Totals.AllowCount != 140 || resp.Totals.DenyCount != 6 ||
		resp.Totals.RevertedCount != 5 || resp.Totals.RevertFailedCount != 1 {
		t.Fatalf("totals should be the derived sum, got %+v", resp.Totals)
	}

	// An interrupted session renders honestly rather than as a clean stop.
	interrupted := fleet.SessionView{Status: fleet.SessionInterrupted}
	if got := sessionEndedLabel(interrupted); got != "no clean stop" {
		t.Fatalf("an interrupted session must not display an end time, got %q", got)
	}
}
