package fleet

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	idA = "11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	idB = "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	// shares an 8-char prefix with idA, so the displayed short ID is ambiguous.
	idA2 = "11111111-cccc-4ccc-8ccc-cccccccccccc"
)

func enrollIDs(t *testing.T, srv *Server, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if rr := doJSON(t, srv, http.MethodPost, "/api/fleet/enroll", EnrollRequest{SentinelID: id, MachineID: "m-" + id[:4]}, ""); rr.Code != http.StatusOK {
			t.Fatalf("enroll %s: %d %s", id, rr.Code, rr.Body.String())
		}
	}
}

func assign(t *testing.T, srv *Server, idArg string, version int) int {
	t.Helper()
	return doJSON(t, srv, http.MethodPost, "/api/fleet/sentinels/"+idArg+"/assign",
		map[string]any{"policy_id": "production", "version": version}, "").Code
}

func inventoryIDs(s *Store) []string {
	var out []string
	for _, r := range s.List() {
		out = append(out, r.SentinelID)
	}
	return out
}

func TestAssign_FullUUID_UpdatesExistingSentinel(t *testing.T) {
	srv, store, ps := newTestServer(t, "")
	v, _ := ps.Create("production", "", sampleYAML)
	enrollIDs(t, srv, idA, idB)

	if code := assign(t, srv, idA, v.Version); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if rec, _ := store.Get(idA); rec.DesiredPolicyID != "production" {
		t.Fatalf("desired policy not set on %s: %+v", idA, rec)
	}
	if rec, _ := store.Get(idB); rec.DesiredPolicyID != "" {
		t.Fatalf("assignment leaked to a different sentinel: %+v", rec)
	}
	if n := len(store.List()); n != 2 {
		t.Fatalf("inventory changed: %v", inventoryIDs(store))
	}
}

// The displayed short ID (first 8 chars of `fleet list`) resolves to the
// existing Sentinel and creates no new record.
func TestAssign_UniqueShortID_ResolvesToExistingSentinel(t *testing.T) {
	srv, store, ps := newTestServer(t, "")
	v, _ := ps.Create("production", "", sampleYAML)
	enrollIDs(t, srv, idA, idB)

	if code := assign(t, srv, idA[:8], v.Version); code != http.StatusOK {
		t.Fatalf("short-ID assign status %d", code)
	}
	if ids := inventoryIDs(store); len(ids) != 2 {
		t.Fatalf("short-ID assignment changed inventory (phantom record?): %v", ids)
	}
	if _, ok := store.Get(idA[:8]); ok {
		t.Fatal("a record keyed by the short ID was created")
	}
	if rec, _ := store.Get(idA); rec.DesiredPolicyID != "production" || rec.DesiredPolicyVersion != v.Version {
		t.Fatalf("existing sentinel was not updated: %+v", rec)
	}
}

func TestAssign_UnknownID_FailsWithoutCreatingRecord(t *testing.T) {
	srv, store, ps := newTestServer(t, "")
	v, _ := ps.Create("production", "", sampleYAML)
	enrollIDs(t, srv, idA, idB)

	for _, bad := range []string{"deadbeef", "99999999-zzzz-4zzz-8zzz-zzzzzzzzzzzz", "nonexistent"} {
		if code := assign(t, srv, bad, v.Version); code != http.StatusNotFound {
			t.Fatalf("%s: expected 404, got %d", bad, code)
		}
	}
	if ids := inventoryIDs(store); len(ids) != 2 {
		t.Fatalf("unknown-ID assignment created a record: %v", ids)
	}
	for _, id := range []string{idA, idB} {
		if rec, _ := store.Get(id); rec.DesiredPolicyID != "" {
			t.Fatalf("unknown-ID assignment changed %s: %+v", id, rec)
		}
	}
}

func TestAssign_AmbiguousPrefix_FailsClearlyWithoutChanges(t *testing.T) {
	srv, store, ps := newTestServer(t, "")
	v, _ := ps.Create("production", "", sampleYAML)
	enrollIDs(t, srv, idA, idA2, idB)

	rr := doJSON(t, srv, http.MethodPost, "/api/fleet/sentinels/"+idA[:8]+"/assign",
		map[string]any{"policy_id": "production", "version": v.Version}, "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 for an ambiguous prefix, got %d", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "ambiguous") || !strings.Contains(body, idA) || !strings.Contains(body, idA2) {
		t.Fatalf("error should name the ambiguity and the candidates, got %q", body)
	}
	if ids := inventoryIDs(store); len(ids) != 3 {
		t.Fatalf("ambiguous assignment changed inventory: %v", ids)
	}
	for _, id := range []string{idA, idA2, idB} {
		if rec, _ := store.Get(id); rec.DesiredPolicyID != "" {
			t.Fatalf("ambiguous assignment changed %s: %+v", id, rec)
		}
	}
	// A longer prefix that is unique still works.
	if code := assign(t, srv, idA[:13], v.Version); code != http.StatusOK {
		t.Fatalf("a unique longer prefix should resolve, got %d", code)
	}
}

// Very short prefixes are refused so a typo cannot target an unintended sentinel.
func TestAssign_TooShortPrefix_Rejected(t *testing.T) {
	srv, store, ps := newTestServer(t, "")
	v, _ := ps.Create("production", "", sampleYAML)
	enrollIDs(t, srv, idA)
	if code := assign(t, srv, "1", v.Version); code != http.StatusNotFound && code != http.StatusBadRequest {
		t.Fatalf("expected rejection of a 1-char prefix, got %d", code)
	}
	if rec, _ := store.Get(idA); rec.DesiredPolicyID != "" {
		t.Fatal("1-char prefix assigned a policy")
	}
}

// A rollback grant must be issued for the canonical full ID, never the typed
// prefix; otherwise the Sentinel (which verifies the grant against its own full
// ID) would reject it.
func TestAssign_ShortID_RollbackGrantBoundToFullID(t *testing.T) {
	srv, _, policyStore, auth, _, key := newTrustServer(t, true)
	cred, _ := enrollWithToken(t, srv, auth, idA)
	v1, err := policyStore.Create("production", "v1", signedSampleYAML)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyStore.AddVersion("production", "v2", "version: 1\npolicy:\n  deny_write: []\n"); err != nil {
		t.Fatal(err)
	}
	doJSON(t, srv, http.MethodPost, "/api/fleet/sentinels/"+idA[:8]+"/assign", assignPolicyRequest{PolicyID: "production", Version: 2}, "")
	rr := doJSON(t, srv, http.MethodPost, "/api/fleet/sentinels/"+idA[:8]+"/assign", assignPolicyRequest{PolicyID: "production", Version: 1, AllowRollback: true}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("assign by short ID failed: %d %s", rr.Code, rr.Body.String())
	}
	hb := doAs(t, srv, http.MethodPost, "/api/fleet/heartbeat", HeartbeatRequest{SentinelID: idA}, cred)
	var resp HeartbeatResponse
	if err := json.Unmarshal(hb.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RollbackGrant == nil {
		t.Fatal("expected a rollback grant")
	}
	ref := PolicyRef{PolicyID: "production", Version: 1, Hash: v1.Hash}
	if err := VerifyRollbackGrant(resp.RollbackGrant, Trust(key.KeyID, key.PublicKeyHex()), idA, ref, v1.Digest, time.Now().UTC()); err != nil {
		t.Fatalf("grant must be bound to the full sentinel ID: %v", err)
	}
}
