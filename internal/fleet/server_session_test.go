package fleet

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newHistoryServer builds a control plane with trust (14B) plus session
// history (14C) attached.
func newHistoryServer(t *testing.T, retention RetentionPolicy) (*Server, *Store, *AuthStore, *AlertStore, *SessionStore) {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	policyStore, err := OpenPolicyStore(filepath.Join(dir, "fleet-policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	authStore, err := OpenAuthStore(filepath.Join(dir, "fleet-auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	alertStore, err := OpenAlertStore(filepath.Join(dir, "fleet-alerts.json"))
	if err != nil {
		t.Fatal(err)
	}
	sessionStore, err := OpenSessionStore(filepath.Join(dir, "fleet-sessions.json"), retention)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := LoadOrCreateSigningKey(filepath.Join(dir, "signing-key"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServerWithOptions(store, policyStore, "", ServerOptions{
		AuthStore: authStore, AlertStore: alertStore, SessionStore: sessionStore,
		SigningKey: key, RequireEnrollment: true,
	})
	return srv, store, authStore, alertStore, sessionStore
}

func heartbeatAs(t *testing.T, srv *Server, cred string, req HeartbeatRequest) *httpRecorder {
	t.Helper()
	rr := doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", req, cred)
	return &httpRecorder{Code: rr.Code, Body: rr.Body.String()}
}

type httpRecorder struct {
	Code int
	Body string
}

func listSessions(t *testing.T, srv *Server, query string) SessionListResponse {
	t.Helper()
	rr := doJSON(t, srv, http.MethodGet, "/api/fleet/sessions"+query, nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("sessions list status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp SessionListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// --- 1/2/8/9: a heartbeat creates history; a new session supersedes ---------

func TestServerHistory_HeartbeatRecordsSessionAndRestartAddsAnother(t *testing.T) {
	srv, _, auth, _, _ := newHistoryServer(t, DefaultRetention())
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")
	started := time.Now().UTC().Add(-time.Hour)

	if rr := heartbeatAs(t, srv, cred, HeartbeatRequest{
		SentinelID: "sen-1", SessionID: "sess-A", SessionStartedAt: started,
		Status: "running", PolicyID: "production", PolicyVersion: "10", AllowCount: 5,
	}); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat failed: %d %s", rr.Code, rr.Body)
	}
	resp := listSessions(t, srv, "?sentinel=sen-1")
	if len(resp.Sessions) != 1 || !resp.Sessions[0].Current {
		t.Fatalf("expected one CURRENT session, got %+v", resp.Sessions)
	}

	// The Sentinel restarts: new session id, same sentinel id.
	if rr := heartbeatAs(t, srv, cred, HeartbeatRequest{
		SentinelID: "sen-1", SessionID: "sess-B", SessionStartedAt: time.Now().UTC(),
		Status: "running", PolicyID: "production", PolicyVersion: "11",
	}); rr.Code != http.StatusOK {
		t.Fatalf("second heartbeat failed: %d %s", rr.Code, rr.Body)
	}

	resp = listSessions(t, srv, "?sentinel=sen-1")
	if len(resp.Sessions) != 2 {
		t.Fatalf("a restart must add history, got %d sessions", len(resp.Sessions))
	}
	byID := map[string]SessionView{}
	for _, v := range resp.Sessions {
		byID[v.SessionID] = v
	}
	if !byID["sess-B"].Current || byID["sess-B"].Status != SessionActive {
		t.Fatalf("the new session must be CURRENT/ACTIVE, got %+v", byID["sess-B"])
	}
	if byID["sess-A"].Current {
		t.Fatal("the superseded session must no longer be CURRENT")
	}
	if byID["sess-A"].Status != SessionInterrupted {
		t.Fatalf("a superseded session with no clean stop is INTERRUPTED, got %s", byID["sess-A"].Status)
	}
	if byID["sess-A"].StoppedAt != nil {
		t.Fatal("no clean stop was reported, so no stopped_at may be recorded")
	}
	// 12: history keeps its own policy.
	if byID["sess-A"].PolicyVersion != "10" {
		t.Fatalf("session A must still report v10, got %s", byID["sess-A"].PolicyVersion)
	}
}

// --- 6/7: graceful stop over the wire ---------------------------------------

func TestServerHistory_FinalHeartbeatMarksSessionStopped(t *testing.T) {
	srv, _, auth, _, _ := newHistoryServer(t, DefaultRetention())
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	base := HeartbeatRequest{SentinelID: "sen-1", SessionID: "sess-A", SessionStartedAt: time.Now().UTC(), Status: "running"}
	if rr := heartbeatAs(t, srv, cred, base); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d", rr.Code)
	}
	stop := base
	stop.Status = SessionStoppedStatus
	if rr := heartbeatAs(t, srv, cred, stop); rr.Code != http.StatusOK {
		t.Fatalf("stop heartbeat: %d", rr.Code)
	}

	resp := listSessions(t, srv, "?sentinel=sen-1")
	v := resp.Sessions[0]
	if v.Status != SessionStopped {
		t.Fatalf("expected STOPPED, got %s", v.Status)
	}
	if v.StoppedAt == nil {
		t.Fatal("a clean stop must record stopped_at")
	}
	if v.Current {
		t.Fatal("a stopped session is history, not the current session")
	}
}

// --- 22: a buffered stop reported by a later session ------------------------

func TestServerHistory_BufferedSessionStopReportIsApplied(t *testing.T) {
	srv, _, auth, _, _ := newHistoryServer(t, DefaultRetention())
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	stoppedAt := time.Now().UTC().Add(-time.Minute)
	if rr := heartbeatAs(t, srv, cred, HeartbeatRequest{
		SentinelID: "sen-1", SessionID: "sess-A", SessionStartedAt: stoppedAt.Add(-time.Hour), Status: "running",
	}); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d", rr.Code)
	}
	// A later session flushes the stop the previous one could not deliver.
	if rr := heartbeatAs(t, srv, cred, HeartbeatRequest{
		SentinelID: "sen-1", SessionID: "sess-B", SessionStartedAt: time.Now().UTC(), Status: "running",
	}); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat B: %d", rr.Code)
	}
	batch := ReportBatch{SentinelID: "sen-1", Reports: []Report{{
		ID: "stop-A", SessionID: "sess-A", Type: ReportSessionStopped, At: stoppedAt, Summary: "session stopped cleanly",
	}}}
	if rr := doAs(t, srv, http.MethodPost, "/api/fleet/reports", batch, cred); rr.Code != http.StatusOK {
		t.Fatalf("report upload: %d %s", rr.Code, rr.Body.String())
	}

	sess, _ := srv.sessionStore.Get("sess-A")
	if sess.StoppedAt == nil || !sess.StoppedAt.Equal(stoppedAt) {
		t.Fatalf("a buffered stop must set the session's own stopped_at, got %v", sess.StoppedAt)
	}
}

// --- 15/46: ownership is enforced at the HTTP boundary ----------------------

func TestServerHistory_SentinelCannotWriteAnotherSentinelsSession(t *testing.T) {
	srv, _, auth, _, _ := newHistoryServer(t, DefaultRetention())
	credA, _ := enrollWithToken(t, srv, auth, "sen-1")
	credB, _ := enrollWithToken(t, srv, auth, "sen-2")

	if rr := heartbeatAs(t, srv, credA, HeartbeatRequest{
		SentinelID: "sen-1", SessionID: "sess-A", SessionStartedAt: time.Now().UTC(), Status: "running", AllowCount: 3,
	}); rr.Code != http.StatusOK {
		t.Fatalf("setup heartbeat: %d", rr.Code)
	}

	// sen-2 claims sen-1's session id in its own heartbeat. Its credential is
	// perfectly valid -- it simply does not own that session.
	rr := heartbeatAs(t, srv, credB, HeartbeatRequest{
		SentinelID: "sen-2", SessionID: "sess-A", SessionStartedAt: time.Now().UTC(), Status: "running", AllowCount: 9999,
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when writing another sentinel's session, got %d %s", rr.Code, rr.Body)
	}
	sess, _ := srv.sessionStore.Get("sess-A")
	if sess.SentinelID != "sen-1" || sess.AllowCount == 9999 {
		t.Fatalf("the victim session was mutated: %+v", sess)
	}

	// Same via a buffered stop report.
	batch := ReportBatch{SentinelID: "sen-2", Reports: []Report{{
		ID: "hostile", SessionID: "sess-A", Type: ReportSessionStopped, At: time.Now().UTC(),
	}}}
	if rr := doAs(t, srv, http.MethodPost, "/api/fleet/reports", batch, credB); rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 stopping another sentinel's session, got %d", rr.Code)
	}
	sess, _ = srv.sessionStore.Get("sess-A")
	if sess.StoppedAt != nil {
		t.Fatal("the victim session must not have been stopped by another sentinel")
	}
}

// --- 45: operator auth on history reads -------------------------------------

func TestServerHistory_ReadAPIsRequireOperatorAuth(t *testing.T) {
	dir := t.TempDir()
	store, _ := OpenStore(filepath.Join(dir, "fleet.json"))
	policyStore, _ := OpenPolicyStore(filepath.Join(dir, "p.json"))
	authStore, _ := OpenAuthStore(filepath.Join(dir, "a.json"))
	sessionStore, _ := OpenSessionStore(filepath.Join(dir, "s.json"), DefaultRetention())
	srv := NewServerWithOptions(store, policyStore, "operator-secret", ServerOptions{
		AuthStore: authStore, SessionStore: sessionStore, RequireEnrollment: true,
	})

	for _, path := range []string{"/api/fleet/sessions", "/api/fleet/sessions/sess-A", "/api/fleet/sentinels/sen-1/sessions"} {
		if rr := doJSON(t, srv, http.MethodGet, path, nil, ""); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s must require operator auth, got %d", path, rr.Code)
		}
		if rr := doJSON(t, srv, http.MethodGet, path, nil, "wrong"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s must reject a wrong token, got %d", path, rr.Code)
		}
	}
	// A Sentinel credential is not an operator credential.
	cred, _ := enrollWithToken(t, srv, authStore, "sen-1")
	if rr := doAs(t, srv, http.MethodGet, "/api/fleet/sessions", nil, cred); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a sentinel credential must not read fleet-wide history, got %d", rr.Code)
	}
	if rr := doJSON(t, srv, http.MethodGet, "/api/fleet/sessions", nil, "operator-secret"); rr.Code != http.StatusOK {
		t.Fatalf("the operator token should be accepted, got %d", rr.Code)
	}
}

// --- 34/35: history sync off, health still on -------------------------------

func TestServerHistory_HistorySyncDisabledSuppressesHistoryButNotHealth(t *testing.T) {
	srv, store, auth, _, sessions := newHistoryServer(t, DefaultRetention())
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	if rr := heartbeatAs(t, srv, cred, HeartbeatRequest{
		SentinelID: "sen-1", SessionID: "sess-A", SessionStartedAt: time.Now().UTC(),
		Status: "running", HistorySyncDisabled: true,
		PolicyID: "production", PolicyVersion: "12", AllowCount: 7, DenyCount: 2,
	}); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat must still succeed with history sync off, got %d", rr.Code)
	}

	if len(sessions.List()) != 0 {
		t.Fatal("history sync is disabled; no session metadata may be recorded")
	}
	// ...but everything health/present-state related still works.
	rec, ok := store.Get("sen-1")
	if !ok {
		t.Fatal("the sentinel must still be in inventory")
	}
	if Health(rec, time.Now().UTC()) != "ACTIVE" {
		t.Fatal("health heartbeat must keep working when history sync is off")
	}
	if rec.PolicyVersion != "12" || rec.AllowCount != 7 || rec.DenyCount != 2 {
		t.Fatalf("present state must still update with history sync off, got %+v", rec)
	}
}

// --- 23/24/25: revocation and history ---------------------------------------

func TestServerHistory_RevocationPreservesHistoryAndDoesNotClaimLocalStop(t *testing.T) {
	srv, _, auth, _, _ := newHistoryServer(t, DefaultRetention())
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")
	if rr := heartbeatAs(t, srv, cred, HeartbeatRequest{
		SentinelID: "sen-1", SessionID: "sess-A", SessionStartedAt: time.Now().UTC(),
		Status: "running", PolicyID: "production", PolicyVersion: "12",
	}); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d", rr.Code)
	}

	if err := auth.RevokeSentinel("sen-1", "laptop returned"); err != nil {
		t.Fatal(err)
	}

	resp := listSessions(t, srv, "?sentinel=sen-1")
	if len(resp.Sessions) != 1 {
		t.Fatalf("revocation must not delete history, got %d sessions", len(resp.Sessions))
	}
	v := resp.Sessions[0]
	if v.StoppedAt != nil {
		t.Fatal("revocation is not a shutdown: no stopped_at may be fabricated")
	}
	if v.PolicyVersion != "12" {
		t.Fatal("historical policy must survive revocation")
	}

	// The session page must state the distinction explicitly rather than
	// leaving "revoked" to read as "stopped".
	page := doJSON(t, srv, http.MethodGet, "/fleet/sessions/sess-A", nil, "").Body.String()
	for _, want := range []string{
		"Fleet credential has been revoked",
		"not the same as the Sentinel stopping",
		"keeps enforcing its last-known-good policy",
		"recording the end of its own visibility, not the end of governance",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("a revoked Sentinel's session page must say %q", want)
		}
	}
	// And it must not claim a shutdown happened.
	if strings.Contains(page, "clean shutdown reported") {
		t.Fatal("revocation must never be rendered as a clean shutdown")
	}
}

// --- 26/27: the privacy boundary --------------------------------------------

func TestServerHistory_SessionPayloadsCarryNoEvidenceOrSecrets(t *testing.T) {
	srv, _, auth, alerts, _ := newHistoryServer(t, DefaultRetention())
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")
	if rr := heartbeatAs(t, srv, cred, HeartbeatRequest{
		SentinelID: "sen-1", SessionID: "sess-A", SessionStartedAt: time.Now().UTC(),
		Status: "running", PolicyID: "production", PolicyVersion: "12", SignatureState: "VERIFIED",
	}); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d", rr.Code)
	}
	if _, err := alerts.Ingest("sen-1", []Report{{
		ID: "a1", SessionID: "sess-A", Type: ReportDeny, At: time.Now().UTC(), Path: ".env", Summary: "write blocked and reverted",
	}}); err != nil {
		t.Fatal(err)
	}

	// A FleetSession is a fixed struct, so the exhaustive check is over its
	// serialized keys: anything resembling content, a diff, a prompt, or a
	// secret would have to appear as a field, and none does.
	sess, _ := srv.sessionStore.Get("sess-A")
	blob, err := json.Marshal(sess)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(blob, &keys); err != nil {
		t.Fatal(err)
	}
	// signature_state and signer_key_id are deliberately allowed: they are
	// trust LABELS ("VERIFIED", a public key id), not signature material or
	// key material. Everything else matching these shapes would be a payload
	// this record has no business carrying.
	allowed := map[string]bool{"signature_state": true, "signer_key_id": true}
	forbidden := []string{
		"content", "contents", "diff", "patch", "body", "prompt", "response",
		"message", "conversation", "model", "token", "credential", "secret",
		"private", "signature", "events", "evidence_path", "yaml",
	}
	for key := range keys {
		lower := strings.ToLower(key)
		if allowed[lower] {
			continue
		}
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Fatalf("session metadata must not carry a %q-shaped field, found %q", bad, key)
			}
		}
	}
	// The allowed trust labels must genuinely be labels, not smuggled
	// material: a real Ed25519 signature is 128 hex characters.
	for _, key := range []string{"signature_state", "signer_key_id"} {
		if v, ok := keys[key].(string); ok && len(v) > 32 {
			t.Fatalf("%s looks like key or signature material, not a label: %q", key, v)
		}
	}

	// The same must hold for what the APIs and pages actually return.
	for _, body := range []string{
		doJSON(t, srv, http.MethodGet, "/api/fleet/sessions", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/api/fleet/sessions/sess-A", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/api/fleet/sentinels/sen-1/sessions", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/fleet/sessions/sess-A", nil, "").Body.String(),
	} {
		if strings.Contains(body, cred) {
			t.Fatal("a sentinel credential leaked into a history response")
		}
		for _, bad := range []string{"\"diff\"", "\"patch\"", "\"prompt\"", "\"yaml\""} {
			if strings.Contains(body, bad) {
				t.Fatalf("history response contains %s", bad)
			}
		}
	}

	// And the evidence reference must be logical, not an openable path.
	rr := doJSON(t, srv, http.MethodGet, "/api/fleet/sessions/sess-A", nil, "")
	var detail struct {
		Evidence EvidenceRef `json:"evidence"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Evidence.Location != "LOCAL" || detail.Evidence.SessionID != "sess-A" {
		t.Fatalf("unexpected evidence reference: %+v", detail.Evidence)
	}
	if strings.Contains(detail.Evidence.Kind, "/") || strings.HasPrefix(detail.Evidence.SessionID, "/") {
		t.Fatal("the evidence reference must not be a filesystem path")
	}
}

// --- 42/43: the UI renders history and evidence locality --------------------

func TestServerHistory_UIRendersCurrentAndHistoricalSessions(t *testing.T) {
	srv, _, auth, _, _ := newHistoryServer(t, DefaultRetention())
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	old := HeartbeatRequest{SentinelID: "sen-1", SessionID: "sess-OLD", SessionStartedAt: time.Now().UTC().Add(-2 * time.Hour), Status: "running", PolicyID: "production", PolicyVersion: "10"}
	heartbeatAs(t, srv, cred, old)
	stop := old
	stop.Status = SessionStoppedStatus
	heartbeatAs(t, srv, cred, stop)
	heartbeatAs(t, srv, cred, HeartbeatRequest{SentinelID: "sen-1", SessionID: "sess-NEW", SessionStartedAt: time.Now().UTC(), Status: "running", PolicyID: "production", PolicyVersion: "12", SignatureState: "VERIFIED"})

	// The Sentinel detail page must carry the history surface.
	detail := doJSON(t, srv, http.MethodGet, "/fleet/sentinels/sen-1", nil, "").Body.String()
	for _, want := range []string{"Session history", "Raw evidence remains local", "loadHistory", "CURRENT · ACTIVE"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("the sentinel detail page should contain %q", want)
		}
	}

	// The stopped session's own page must read as historical and say where
	// evidence lives.
	page := doJSON(t, srv, http.MethodGet, "/fleet/sessions/sess-OLD", nil, "").Body.String()
	for _, want := range []string{"HISTORICAL · STOPPED", "LOCAL TO SENTINEL", "never left the machine", "airlock inspect"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the session page should contain %q", want)
		}
	}
	if strings.Contains(page, "Open evidence") {
		t.Fatal("the page must not offer to open evidence the control plane cannot reach")
	}

	current := doJSON(t, srv, http.MethodGet, "/fleet/sessions/sess-NEW", nil, "").Body.String()
	if !strings.Contains(current, "CURRENT · ACTIVE") {
		t.Fatal("the active session's page should mark it current")
	}

	if rr := doJSON(t, srv, http.MethodGet, "/fleet/sessions/does-not-exist", nil, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown session should 404, got %d", rr.Code)
	}
}

// --- 14: exposed totals equal derived session totals ------------------------

func TestServerHistory_TotalsAreDerivedFromSessions(t *testing.T) {
	srv, _, auth, _, _ := newHistoryServer(t, DefaultRetention())
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	heartbeatAs(t, srv, cred, HeartbeatRequest{SentinelID: "sen-1", SessionID: "s1", SessionStartedAt: time.Now().UTC().Add(-2 * time.Hour), Status: "running", AllowCount: 100, DenyCount: 4, RevertedCount: 4})
	heartbeatAs(t, srv, cred, HeartbeatRequest{SentinelID: "sen-1", SessionID: "s2", SessionStartedAt: time.Now().UTC(), Status: "running", AllowCount: 40, DenyCount: 2, RevertedCount: 1, RevertFailedCount: 1})

	resp := listSessions(t, srv, "?sentinel=sen-1")
	if resp.Totals == nil {
		t.Fatal("a sentinel-scoped listing should carry totals")
	}
	var sum SentinelTotals
	for _, v := range resp.Sessions {
		sum.AllowCount += v.AllowCount
		sum.DenyCount += v.DenyCount
		sum.RevertedCount += v.RevertedCount
		sum.RevertFailedCount += v.RevertFailedCount
	}
	sum.SessionCount = len(resp.Sessions)
	if *resp.Totals != sum {
		t.Fatalf("totals must equal the sum of the rows shown: %+v vs %+v", *resp.Totals, sum)
	}
}
