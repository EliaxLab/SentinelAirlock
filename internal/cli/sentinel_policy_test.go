package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
)

const denySpecialYAML = `version: 1
policy:
  deny_write: ["special.txt"]
network:
  mode: "off"
`

const allowAllYAML = `version: 1
policy:
  deny_write: []
network:
  mode: "off"
`

func newTestFleetServerWithStores(t *testing.T) (*httptest.Server, *fleet.Store, *fleet.PolicyStore) {
	t.Helper()
	store, err := fleet.OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	policyStore, err := fleet.OpenPolicyStore(filepath.Join(t.TempDir(), "fleet-policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fleet.NewServer(store, policyStore, "").Handler())
	t.Cleanup(srv.Close)
	return srv, store, policyStore
}

// seedEnrolled makes sure sentinelID is already an enrolled identity in store.
// Assignment never creates an identity (enrollment is the only path that
// does), so tests that assign before the Sentinel process has started enroll
// the record first, exactly as an operator would have had to.
func seedEnrolled(t *testing.T, store *fleet.Store, sentinelID string) {
	t.Helper()
	if _, ok := store.Get(sentinelID); ok {
		return
	}
	if _, err := store.UpsertEnroll(fleet.Record{SentinelID: sentinelID, MachineID: "test-seed", LastHeartbeat: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

func assignPolicyViaHTTP(t *testing.T, baseURL, sentinelID, policyID string, version int) {
	t.Helper()
	enroll, _ := json.Marshal(fleet.EnrollRequest{SentinelID: sentinelID, MachineID: "test-seed"})
	if resp, err := http.Post(baseURL+"/api/fleet/enroll", "application/json", bytes.NewReader(enroll)); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	body, _ := json.Marshal(map[string]any{"policy_id": policyID, "version": version})
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

func reserveTestAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func startFleetServerOn(t *testing.T, addr string, store *fleet.Store, policyStore *fleet.PolicyStore) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: fleet.NewServer(store, policyStore, "").Handler()}}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// --- 8/9/10/11/12/13/14/15/23: drift, reconciliation, real effect ----------

func TestSentinel_PolicyReconciliation_DriftToInSync_RealFilesystemEffect(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	srv, _, policyStore := newTestFleetServerWithStores(t)

	v1, err := policyStore.Create("production", "v1", denySpecialYAML)
	if err != nil {
		t.Fatal(err)
	}
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	assignPolicyViaHTTP(t, srv.URL, sentinelID, "production", v1.Version)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()

	if !pollUntil(t, 3*time.Second, func() bool {
		ref := sess.getFleetPolicyRef()
		return ref.PolicyID == "production" && ref.Version == 1
	}) {
		t.Fatal("expected the sentinel to reconcile to v1 (DRIFTED -> IN_SYNC)")
	}

	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, "special.txt"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected special.txt to be denied under v1")
	}

	// v2 changes the rule: special.txt is no longer denied. Assigning it
	// must cause real drift, then real reconciliation, then a real change
	// in what gets enforced.
	v2, err := policyStore.AddVersion("production", "v2", allowAllYAML)
	if err != nil {
		t.Fatal(err)
	}
	assignPolicyViaHTTP(t, srv.URL, sentinelID, "production", v2.Version)

	if !pollUntil(t, 3*time.Second, func() bool {
		return sess.getFleetPolicyRef().Version == 2
	}) {
		t.Fatal("expected the sentinel to reconcile to v2")
	}

	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("now allowed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(filepath.Join(dir, "special.txt"))
		return string(b) == "now allowed"
	}) {
		t.Fatal("expected special.txt to be ALLOWED under v2 -- the reconciled policy must take real effect on enforcement")
	}
}

// A successful reconciliation reports IN_SYNC immediately as part of the
// same reconcile call (a dedicated post-success heartbeat), not only on
// whatever the next regularly-scheduled heartbeat tick happens to be --
// otherwise the dashboard could lag real enforcement by up to a full
// DefaultHeartbeatInterval after a policy change already took effect. The
// internal ticker is parked for an hour so this test can drive one
// heartbeat+reconcile cycle manually and deterministically, with no race
// against the ticker's own schedule.
func TestSentinel_PolicyReconciliation_SuccessReportedPromptly(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "1h")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	srv, store, policyStore := newTestFleetServerWithStores(t)

	v1, err := policyStore.Create("production", "", denySpecialYAML)
	if err != nil {
		t.Fatal(err)
	}
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	assignPolicyViaHTTP(t, srv.URL, sentinelID, "production", v1.Version)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()

	resp, err := sess.fleetClient.Heartbeat(sess.buildHeartbeatRequest())
	if err != nil {
		t.Fatal(err)
	}
	sess.reconcileFleetPolicy(resp)

	rec, ok := store.Get(sentinelID)
	if !ok || !fleetReconcileStateIsInSync(rec) {
		t.Fatalf("expected IN_SYNC immediately after a successful reconciliation, without waiting for a subsequent heartbeat tick (parked for an hour), got %+v", rec)
	}
}

func fleetReconcileStateIsInSync(rec fleet.Record) bool {
	status, _ := fleet.ReconcileState(rec)
	return status == "IN_SYNC"
}

// --- 16/17/18: invalid update never replaces a valid policy ----------------

func TestSentinel_PolicyReconciliation_HashMismatch_KeepsLastKnownGood(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	srv, store, policyStore := newTestFleetServerWithStores(t)

	v1, err := policyStore.Create("production", "", denySpecialYAML)
	if err != nil {
		t.Fatal(err)
	}
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	assignPolicyViaHTTP(t, srv.URL, sentinelID, "production", v1.Version)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()

	if !pollUntil(t, 3*time.Second, func() bool { return sess.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected initial reconciliation to v1")
	}
	lkgBefore := sess.getFleetPolicyRef()

	// Corrupt the assignment directly: claim v1 should hash to something it
	// never will. GetPolicyVersion still returns v1's real, valid content
	// and real hash -- this exercises the fetched-hash-vs-desired-hash
	// integrity check, not a YAML parse failure (PolicyStore's own Create/
	// AddVersion already reject invalid YAML, so a stored version can never
	// itself be unparsable).
	seedEnrolled(t, store, sentinelID)
	if _, err := store.AssignPolicy(sentinelID, fleet.PolicyRef{PolicyID: "production", Version: v1.Version, Hash: "not-the-real-hash"}, "", nil); err != nil {
		t.Fatal(err)
	}

	if !pollUntil(t, 3*time.Second, func() bool {
		rec, ok := store.Get(sentinelID)
		return ok && rec.ReconcileStatus == "RECONCILE_FAILED" && rec.ReconcileError != ""
	}) {
		t.Fatal("expected a RECONCILE_FAILED report with a non-empty error")
	}

	if sess.getFleetPolicyRef() != lkgBefore {
		t.Fatal("a failed reconciliation must not change the currently-applied last-known-good policy")
	}

	// The original rule must still be enforced -- an invalid/mismatched
	// update must never leave the Sentinel with a broken or absent policy.
	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, "special.txt"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected v1's rule to still be enforced after a failed reconciliation attempt")
	}
}

// --- 21: repeated identical desired state causes no unnecessary rewrite ---

func TestSentinel_PolicyReconciliation_IdenticalDesiredState_NoRedundantReinstall(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "50ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	srv, _, policyStore := newTestFleetServerWithStores(t)

	v1, err := policyStore.Create("production", "", denySpecialYAML)
	if err != nil {
		t.Fatal(err)
	}
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	assignPolicyViaHTTP(t, srv.URL, sentinelID, "production", v1.Version)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()

	if !pollUntil(t, 2*time.Second, func() bool { return sess.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected reconciliation to v1")
	}
	info1, err := os.Stat(fleetPolicyLKGPath(repoAbs))
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond) // several more heartbeat ticks at the same, already-satisfied desired state

	info2, err := os.Stat(fleetPolicyLKGPath(repoAbs))
	if err != nil {
		t.Fatal(err)
	}
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatal("expected no reinstall once actual already matches desired -- the LKG file should not be rewritten repeatedly")
	}
}

// --- LKG durability across a Sentinel restart, control plane unreachable --

func TestSentinel_PolicyReconciliation_LKGPersistsAcrossRestartEvenIfFleetUnreachable(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	srv, _, policyStore := newTestFleetServerWithStores(t)

	v1, err := policyStore.Create("production", "", denySpecialYAML)
	if err != nil {
		t.Fatal(err)
	}
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	assignPolicyViaHTTP(t, srv.URL, sentinelID, "production", v1.Version)

	sess1, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool { return sess1.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected initial reconciliation")
	}
	sess1.shutdown()

	// Restart against an UNREACHABLE fleet URL: the control plane is "down"
	// from this Sentinel's perspective at startup. It must restore and keep
	// enforcing v1 from the durable LKG, never silently fall back to local
	// airlock.yaml (which has no deny rule for special.txt at all).
	sess2, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: unreachableFleetURL(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer sess2.shutdown()

	if got := sess2.getFleetPolicyRef(); got.PolicyID != "production" || got.Version != 1 {
		t.Fatalf("expected the restored LKG ref to be production v1, got %+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, "special.txt"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected v1's deny rule to still be enforced from the persisted LKG, even though the control plane is unreachable")
	}
}

// --- 19/20: control-plane outage does not stop enforcement; reconnect -----
// --- resumes reconciliation with no Sentinel restart ------------------------

func TestSentinel_PolicyReconciliation_ResumesAfterControlPlaneRestart(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)

	store, err := fleet.OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	policyStore, err := fleet.OpenPolicyStore(filepath.Join(t.TempDir(), "fleet-policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	v1, err := policyStore.Create("production", "", denySpecialYAML)
	if err != nil {
		t.Fatal(err)
	}
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	seedEnrolled(t, store, sentinelID)
	if _, err := store.AssignPolicy(sentinelID, fleet.PolicyRef{PolicyID: "production", Version: v1.Version, Hash: v1.Hash}, "", nil); err != nil {
		t.Fatal(err)
	}

	addr := reserveTestAddr(t)
	srv1 := startFleetServerOn(t, addr, store, policyStore)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: "http://" + addr})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()
	if !pollUntil(t, 2*time.Second, func() bool { return sess.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected initial reconciliation to v1")
	}
	srv1.Close() // control plane goes down; the Sentinel process is NOT restarted

	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, "special.txt"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("expected v1 to still be enforced locally while the control plane is down")
	}

	// A new version is assigned directly against the durable store while
	// the control plane process is down (as if an operator used the CLI
	// against a store the control plane will pick back up).
	v2, err := policyStore.AddVersion("production", "", allowAllYAML)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AssignPolicy(sentinelID, fleet.PolicyRef{PolicyID: "production", Version: v2.Version, Hash: v2.Hash}, "", nil); err != nil {
		t.Fatal(err)
	}

	// Restart the control plane on the exact same address -- no Sentinel
	// restart, no re-run of `airlock sentinel`.
	startFleetServerOn(t, addr, store, policyStore)

	if !pollUntil(t, 3*time.Second, func() bool { return sess.getFleetPolicyRef().Version == 2 }) {
		t.Fatal("expected reconciliation to resume automatically once the control plane returned")
	}
}
