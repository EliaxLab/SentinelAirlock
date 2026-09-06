package fleet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTrustServer builds a control plane with the full Prompt 14B trust
// machinery attached.
func newTrustServer(t *testing.T, requireEnrollment bool) (*Server, *Store, *PolicyStore, *AuthStore, *AlertStore, *SigningKey) {
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
	key, _, err := LoadOrCreateSigningKey(filepath.Join(dir, "signing-key"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServerWithOptions(store, policyStore, "", ServerOptions{
		AuthStore: authStore, AlertStore: alertStore, SigningKey: key, RequireEnrollment: requireEnrollment,
	})
	return srv, store, policyStore, authStore, alertStore, key
}

// doAs issues a request carrying a Sentinel credential.
func doAs(t *testing.T, srv *Server, method, path string, body any, credential string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if credential != "" {
		req.Header.Set(CredentialHeader, credential)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

func enrollWithToken(t *testing.T, srv *Server, auth *AuthStore, sentinelID string) (credential string, resp EnrollResponse) {
	t.Helper()
	token, _, err := auth.CreateEnrollToken("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rr := doJSON(t, srv, http.MethodPost, "/api/fleet/enroll", EnrollRequest{
		SentinelID: sentinelID, MachineID: "mach-1", RepoPath: "/repo/" + sentinelID, EnrollToken: token,
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("enroll with a valid token failed: %d %s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Credential == "" {
		t.Fatal("a first enrollment must return a durable credential")
	}
	return resp.Credential, resp
}

// --- 1/3: enrollment over HTTP issues a credential and advertises the key ---

func TestServerTrust_EnrollWithTokenIssuesCredentialAndAdvertisesSigningKey(t *testing.T) {
	srv, _, _, auth, _, key := newTrustServer(t, true)
	cred, resp := enrollWithToken(t, srv, auth, "sen-1")

	if resp.SigningKeyID != key.KeyID || resp.SigningPublicKey != key.PublicKeyHex() {
		t.Fatal("enrollment must advertise the control plane's signing key so a Sentinel can pin it")
	}
	if !resp.RequireEnrollment {
		t.Fatal("the response should tell the Sentinel which trust posture the control plane runs")
	}
	rr := doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: "sen-1"}, cred)
	if rr.Code != http.StatusOK {
		t.Fatalf("an authenticated heartbeat should succeed: %d %s", rr.Code, rr.Body.String())
	}
}

// --- 2: an invalid enrollment token is rejected over HTTP -------------------

func TestServerTrust_InvalidEnrollTokenRejected(t *testing.T) {
	srv, _, _, auth, _, _ := newTrustServer(t, true)
	rr := doJSON(t, srv, http.MethodPost, "/api/fleet/enroll", EnrollRequest{
		SentinelID: "sen-1", MachineID: "m", EnrollToken: "airlock_et_bogus",
	}, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("a bogus enrollment token must be rejected, got %d", rr.Code)
	}

	token, _, _ := auth.CreateEnrollToken("", time.Hour)
	if rr := doJSON(t, srv, http.MethodPost, "/api/fleet/enroll", EnrollRequest{SentinelID: "sen-1", MachineID: "m", EnrollToken: token}, ""); rr.Code != http.StatusOK {
		t.Fatalf("first use should succeed, got %d", rr.Code)
	}
	if rr := doJSON(t, srv, http.MethodPost, "/api/fleet/enroll", EnrollRequest{SentinelID: "sen-9", MachineID: "m", EnrollToken: token}, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a consumed token must not work a second time, got %d", rr.Code)
	}
}

func TestServerTrust_RequireEnrollmentRejectsTokenlessEnrollment(t *testing.T) {
	srv, _, _, _, _, _ := newTrustServer(t, true)
	rr := doJSON(t, srv, http.MethodPost, "/api/fleet/enroll", EnrollRequest{SentinelID: "sen-1", MachineID: "m"}, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("the production posture must require an enrollment token, got %d", rr.Code)
	}
}

// --- 4: a random sentinel_id cannot impersonate an enrolled Sentinel --------

func TestServerTrust_UnauthenticatedRequestCannotImpersonateEnrolledSentinel(t *testing.T) {
	// This is the property that must hold in BOTH postures, so it is checked
	// with require-enrollment OFF -- the weaker configuration.
	srv, _, _, auth, _, _ := newTrustServer(t, false)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	rr := doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: "sen-1", DenyCount: 999}, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("a heartbeat claiming an enrolled sentinel_id without its credential must be rejected, got %d", rr.Code)
	}

	// ...and holding *a* valid credential is not enough either: it must be
	// the credential issued to the identity being claimed.
	otherCred, _ := enrollWithToken(t, srv, auth, "sen-2")
	rr = doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: "sen-1", DenyCount: 999}, otherCred)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("sen-2's credential must not let it act as sen-1, got %d", rr.Code)
	}

	// The real owner still works, and nothing the impostors sent landed.
	if rr := doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: "sen-1"}, cred); rr.Code != http.StatusOK {
		t.Fatalf("the genuine sentinel must still be able to heartbeat, got %d", rr.Code)
	}
	rec, _ := srv.store.Get("sen-1")
	if rec.DenyCount == 999 {
		t.Fatal("an impersonated heartbeat must not have mutated the record")
	}
}

// --- 5: a wrong credential is rejected over HTTP ----------------------------

func TestServerTrust_WrongCredentialRejected(t *testing.T) {
	srv, _, _, auth, _, _ := newTrustServer(t, true)
	enrollWithToken(t, srv, auth, "sen-1")
	rr := doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: "sen-1"}, "airlock_sc_nope")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong credential must be rejected, got %d", rr.Code)
	}
}

// --- 6: a revoked credential is rejected, and says so -----------------------

func TestServerTrust_RevokedCredentialRejectedWithMachineReadableReason(t *testing.T) {
	srv, _, _, auth, _, _ := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	rr := doJSON(t, srv, http.MethodPost, "/api/fleet/sentinels/sen-1/revoke", map[string]string{"reason": "laptop stolen"}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("revocation should succeed for an operator: %d %s", rr.Code, rr.Body.String())
	}

	rr = doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: "sen-1"}, cred)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("a revoked credential must be rejected with 403, got %d", rr.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["error"] != ErrorCredentialRevoked {
		t.Fatalf("revocation must be distinguishable from a generic rejection, got %v", payload)
	}

	// And the inventory shows it as REVOKED without the Sentinel having said so.
	rr = doJSON(t, srv, http.MethodGet, "/api/fleet/sentinels/sen-1", nil, "")
	var view SentinelView
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Identity != "REVOKED" || view.RevokedReason != "laptop stolen" {
		t.Fatalf("expected a computed REVOKED identity with its reason, got %+v", view)
	}
}

// --- 24: the private signing key is never exposed through the API -----------

func TestServerTrust_PrivateSigningKeyIsNeverExposed(t *testing.T) {
	srv, _, policyStore, auth, _, key := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")
	if _, err := policyStore.Create("production", "v1", signedSampleYAML); err != nil {
		t.Fatal(err)
	}

	// Sweep every endpoint that returns trust-adjacent data and assert the
	// private key's bytes appear in none of them.
	privateHex := strings.TrimSpace(mustReadKeyFile(t, srv))
	if privateHex == "" {
		t.Fatal("test setup: could not read the private key to search for it")
	}
	responses := []string{
		doJSON(t, srv, http.MethodGet, "/api/fleet/trust", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/api/fleet/sentinels", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/api/fleet/sentinels/sen-1", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/api/fleet/policies", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/api/fleet/policies/production", nil, "").Body.String(),
		doAs(t, srv, http.MethodGet, "/api/fleet/policies/production/versions/1", nil, cred).Body.String(),
		doJSON(t, srv, http.MethodGet, "/api/fleet/enroll-tokens", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/api/fleet/alerts", nil, "").Body.String(),
		doJSON(t, srv, http.MethodGet, "/", nil, "").Body.String(),
	}
	for i, body := range responses {
		if strings.Contains(body, privateHex) {
			t.Fatalf("response %d exposed the private signing key", i)
		}
		if strings.Contains(body, cred) {
			t.Fatalf("response %d exposed a sentinel credential", i)
		}
	}
	// The PUBLIC key is meant to be published, and is.
	trustBody := doJSON(t, srv, http.MethodGet, "/api/fleet/trust", nil, "").Body.String()
	if !strings.Contains(trustBody, key.PublicKeyHex()) {
		t.Fatal("the trust endpoint should publish the public verification key")
	}
}

// mustReadKeyFile reaches into the unexported private key so the test has
// concrete bytes to search API responses for. That this requires in-package
// access is itself the point: there is no exported path to the private key.
func mustReadKeyFile(t *testing.T, srv *Server) string {
	t.Helper()
	if srv.signingKey == nil {
		t.Fatal("test server has no signing key")
	}
	return hex.EncodeToString(srv.signingKey.priv)
}

// --- signed policy distribution ---------------------------------------------

func TestServerTrust_PolicyStoreSignsEveryVersion(t *testing.T) {
	srv, _, policyStore, auth, _, key := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	v1, err := policyStore.Create("production", "v1", signedSampleYAML)
	if err != nil {
		t.Fatal(err)
	}
	if !v1.Signed() || v1.Issuer != key.KeyID || v1.Digest == "" {
		t.Fatalf("a version created by a signing control plane must be signed, got %+v", v1)
	}
	if err := VerifyPolicyVersion(v1, Trust(key.KeyID, key.PublicKeyHex())); err != nil {
		t.Fatalf("the stored signature must verify: %v", err)
	}

	// And what a Sentinel actually fetches carries the same verifiable
	// material.
	rr := doAs(t, srv, http.MethodGet, "/api/fleet/policies/production/versions/1", nil, cred)
	if rr.Code != http.StatusOK {
		t.Fatalf("an enrolled sentinel must be able to fetch its assigned policy, got %d", rr.Code)
	}
	var fetched PolicyVersion
	if err := json.Unmarshal(rr.Body.Bytes(), &fetched); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicyVersion(fetched, Trust(key.KeyID, key.PublicKeyHex())); err != nil {
		t.Fatalf("the fetched policy must verify end to end: %v", err)
	}
}

func TestServerTrust_SentinelCannotCreateOrAssignPolicy(t *testing.T) {
	srv, _, policyStore, auth, _, _ := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")
	if _, err := policyStore.Create("production", "v1", signedSampleYAML); err != nil {
		t.Fatal(err)
	}
	// A Sentinel credential is for reporting and fetching, not for changing
	// what the fleet is told to enforce.
	if rr := doAs(t, srv, http.MethodPost, "/api/fleet/policies/production/versions", createPolicyRequest{YAML: signedSampleYAML}, cred); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a sentinel must not be able to create policy versions, got %d", rr.Code)
	}
	if rr := doAs(t, srv, http.MethodPost, "/api/fleet/sentinels/sen-1/assign", assignPolicyRequest{PolicyID: "production", Version: 1}, cred); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a sentinel must not be able to assign its own desired policy, got %d", rr.Code)
	}
}

// --- rollback grants over the wire ------------------------------------------

func TestServerTrust_AssignWithAllowRollbackIssuesSignedGrant(t *testing.T) {
	srv, _, policyStore, auth, _, key := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")
	v1, err := policyStore.Create("production", "v1", signedSampleYAML)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyStore.AddVersion("production", "v2", "version: 1\npolicy:\n  deny_write: []\n"); err != nil {
		t.Fatal(err)
	}

	// An ordinary assignment carries no grant at all.
	doJSON(t, srv, http.MethodPost, "/api/fleet/sentinels/sen-1/assign", assignPolicyRequest{PolicyID: "production", Version: 2}, "")
	rr := doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: "sen-1"}, cred)
	var resp HeartbeatResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RollbackGrant != nil {
		t.Fatal("a normal assignment must not carry a rollback authorization")
	}

	// An explicit rollback does, and it verifies.
	doJSON(t, srv, http.MethodPost, "/api/fleet/sentinels/sen-1/assign", assignPolicyRequest{PolicyID: "production", Version: 1, AllowRollback: true}, "")
	rr = doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: "sen-1"}, cred)
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RollbackGrant == nil {
		t.Fatal("an explicit rollback assignment must carry a signed authorization")
	}
	ref := PolicyRef{PolicyID: "production", Version: 1, Hash: v1.Hash}
	if err := VerifyRollbackGrant(resp.RollbackGrant, Trust(key.KeyID, key.PublicKeyHex()), "sen-1", ref, v1.Digest, time.Now().UTC()); err != nil {
		t.Fatalf("the issued grant must verify against the control plane's key: %v", err)
	}
}

// --- 21/22: report ingestion is authenticated and idempotent ----------------

func TestServerTrust_ReportsAreAttributedToTheAuthenticatedSentinel(t *testing.T) {
	srv, _, _, auth, alerts, _ := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")
	enrollWithToken(t, srv, auth, "sen-2")

	at := time.Now().UTC()
	// sen-1 tries to file an alert under sen-2's name in the body.
	batch := ReportBatch{SentinelID: "sen-1", Reports: []Report{{
		ID: "r1", SentinelID: "sen-2", Type: ReportDeny, At: at, Path: ".env",
	}}}
	if rr := doAs(t, srv, http.MethodPost, "/api/fleet/reports", batch, cred); rr.Code != http.StatusOK {
		t.Fatalf("report upload failed: %d %s", rr.Code, rr.Body.String())
	}
	recent := alerts.Recent(10)
	if len(recent) != 1 || recent[0].SentinelID != "sen-1" {
		t.Fatalf("an alert must be attributed to the authenticated sentinel, not the body's claim: %+v", recent)
	}
}

func TestServerTrust_DuplicateReportUploadDoesNotDuplicateAlert(t *testing.T) {
	srv, _, _, auth, alerts, _ := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")

	at := time.Now().UTC()
	batch := ReportBatch{SentinelID: "sen-1", Reports: []Report{
		{ID: "dup-1", Type: ReportDeny, At: at, Path: ".env"},
		{ID: "dup-2", Type: ReportReverted, At: at, Path: "secrets/key"},
	}}
	for i := 0; i < 3; i++ {
		rr := doAs(t, srv, http.MethodPost, "/api/fleet/reports", batch, cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("upload %d failed: %d", i, rr.Code)
		}
		var resp ReportBatchResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.AcceptedIDs) != 2 {
			t.Fatalf("every upload should acknowledge both ids so the sender can clear them, got %v", resp.AcceptedIDs)
		}
		if i > 0 && resp.Duplicates != 2 {
			t.Fatalf("re-uploading the same reports should be recognized as duplicates, got %+v", resp)
		}
	}
	if alerts.Len() != 2 {
		t.Fatalf("three uploads of the same two reports must produce exactly 2 alerts, got %d", alerts.Len())
	}
}

func TestServerTrust_UnauthenticatedReportUploadRejected(t *testing.T) {
	srv, _, _, auth, alerts, _ := newTrustServer(t, true)
	enrollWithToken(t, srv, auth, "sen-1")
	batch := ReportBatch{SentinelID: "sen-1", Reports: []Report{{ID: "x", Type: ReportDeny, At: time.Now().UTC()}}}
	if rr := doAs(t, srv, http.MethodPost, "/api/fleet/reports", batch, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous report upload for an enrolled sentinel must be rejected, got %d", rr.Code)
	}
	if alerts.Len() != 0 {
		t.Fatal("a rejected upload must not store anything")
	}
}

// --- 25: the fleet UI renders trust state -----------------------------------

func TestServerTrust_UIShowsTrustAndRevocationState(t *testing.T) {
	srv, store, _, auth, _, _ := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, "sen-1")
	if rr := doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{
		SentinelID: "sen-1", SignatureState: "VERIFIED", SignerKeyID: "key-abc",
	}, cred); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d", rr.Code)
	}

	rr := doJSON(t, srv, http.MethodGet, "/fleet/sentinels/sen-1", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("detail page status=%d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"AUTHENTICATED", "VERIFIED", "key-abc", "Trust"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the detail page should show %q, body was:\n%s", want, body)
		}
	}

	if err := auth.RevokeSentinel("sen-1", "decommissioned"); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, srv, http.MethodGet, "/fleet/sentinels/sen-1", nil, "")
	body = rr.Body.String()
	if !strings.Contains(body, "REVOKED") || !strings.Contains(body, "decommissioned") {
		t.Fatalf("the detail page must show revocation and its reason, body was:\n%s", body)
	}
	if !strings.Contains(body, "not an instruction to stop protecting a repository") {
		t.Fatal("the page must state that revocation does not disable local enforcement")
	}

	// The index page must expose the computed counters the table relies on.
	if _, err := store.UpsertHeartbeat("sen-1", func(r *Record) { r.LastHeartbeat = time.Now().UTC() }); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, srv, http.MethodGet, "/api/fleet/sentinels", nil, "")
	var snap Snapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Revoked != 1 {
		t.Fatalf("the snapshot should count 1 revoked sentinel, got %+v", snap)
	}
	index := doJSON(t, srv, http.MethodGet, "/", nil, "").Body.String()
	for _, want := range []string{"Revoked", "Drifted", "identityBadge", "Recent fleet alerts"} {
		if !strings.Contains(index, want) {
			t.Fatalf("the fleet index should render %q", want)
		}
	}
}
