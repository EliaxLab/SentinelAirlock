package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirelahmed-commits/SentinelAirlock/internal/fleet"
)

func newTestFleetServer(t *testing.T) *httptest.Server {
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
	return srv
}

func fetchFleetRecord(t *testing.T, srv *httptest.Server, sentinelID string) (fleet.Record, bool) {
	t.Helper()
	resp, err := http.Get(srv.URL + "/api/fleet/sentinels/" + sentinelID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fleet.Record{}, false
	}
	var view fleet.SentinelView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	return view.Record, true
}

// unreachableFleetURL returns a URL nothing is listening on, so connections
// fail immediately (connection refused) instead of waiting out a slow
// network timeout -- keeping "control plane is down" tests fast.
func unreachableFleetURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + ln.Addr().String()
	_ = ln.Close()
	return url
}

// --- 2/3/4/5/9/10/11/12/13/14/15: enrollment, identity, heartbeat ----------

func TestSentinel_FleetIdentity_DurableAcrossRestart_SessionIndependent(t *testing.T) {
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	srv := newTestFleetServer(t)

	sess1, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	session1ID := sess1.sessionID
	if !pollUntil(t, 2*time.Second, func() bool {
		rec, ok := fetchFleetRecord(t, srv, sentinelID)
		return ok && rec.SessionID == session1ID
	}) {
		t.Fatal("sentinel did not enroll with the fleet control plane in time")
	}
	sess1.shutdown()

	sess2, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer sess2.shutdown()

	sentinelID2, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	if sentinelID2 != sentinelID {
		t.Fatalf("sentinel identity must be stable across a restart: %q != %q", sentinelID2, sentinelID)
	}
	if sess2.sessionID == session1ID {
		t.Fatal("session identity must change independently of sentinel identity across a restart")
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		rec, ok := fetchFleetRecord(t, srv, sentinelID)
		return ok && rec.SessionID == sess2.sessionID
	}) {
		t.Fatal("second session did not re-enroll (with the same durable sentinel_id) in time")
	}
}

func TestSentinel_FleetHeartbeat_ReportsVersionRepoPolicyCounters(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	srv := newTestFleetServer(t)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "status.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var rec fleet.Record
	if !pollUntil(t, 3*time.Second, func() bool {
		r, ok := fetchFleetRecord(t, srv, sentinelID)
		if !ok {
			return false
		}
		rec = r
		return rec.AllowCount > 0 && rec.DenyCount > 0
	}) {
		t.Fatalf("expected heartbeat counters to reflect governance activity, last seen: %+v", rec)
	}
	if rec.RepoPath != repoAbs {
		t.Errorf("expected repo_path=%s, got %s", repoAbs, rec.RepoPath)
	}
	if rec.SentinelVersion == "" {
		t.Error("expected sentinel_version to be reported")
	}
	if rec.Platform == "" {
		t.Error("expected platform to be reported")
	}
	if rec.RevertedCount == 0 {
		t.Error("expected the denied write to be reported as reverted")
	}
	if rec.PolicyHash == "" {
		t.Error("expected a non-empty policy_hash to be reported")
	}
}

// --- 16/17: disconnected operation is non-negotiable ------------------------

func TestSentinel_FleetUnreachable_LocalGovernanceContinues(t *testing.T) {
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	unreachable := unreachableFleetURL(t)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: unreachable})
	if err != nil {
		t.Fatalf("session must start even when the fleet control plane is unreachable: %v", err)
	}
	defer sess.shutdown()

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, ".env"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("denied write should still be detected and reverted locally even though the fleet control plane is unreachable")
	}
}

func TestSentinel_FleetEnroll_BoundedRetries(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_ENROLL_BACKOFF_BASE", "1ms")
	unreachable := unreachableFleetURL(t)

	sess := &sentinelSession{
		repoAbs:        t.TempDir(),
		sessionID:      "test-session",
		startedAt:      time.Now().UTC(),
		sentinelID:     "test-sentinel",
		fleetMachineID: "test-machine",
		fleetClient:    fleet.NewClient(unreachable, ""),
		fleetStopCh:    make(chan struct{}),
	}
	done := make(chan bool, 1)
	go func() { done <- sess.fleetTryEnroll() }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("expected enrollment against an unreachable control plane to fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fleetTryEnroll did not return within a bounded time -- retry loop appears unbounded")
	}
}

// --- 20/21: standalone mode is unaffected by fleet code existing -----------

func TestSentinel_NoFleetConfigured_NoFleetGoroutineStarted(t *testing.T) {
	dir := chdirTempRepo(t)
	sess := startTestSentinel(t, dir)
	if sess.fleetClient != nil || sess.fleetStopCh != nil || sess.fleetDone != nil {
		t.Fatal("no fleet client/goroutine should be created when --fleet is unset")
	}
	if _, err := os.Stat(filepath.Join(dir, ".airlock", "sentinel_id")); err == nil {
		t.Fatal("no durable sentinel_id file should be created when --fleet is unset")
	}
}

// --- 22: repo paths with spaces ---------------------------------------------

func TestSentinel_FleetEnroll_RepoPathWithSpaces(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "my repo with spaces")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	if err := os.WriteFile(filepath.Join(dir, "airlock.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repoAbs := canonicalRepo(t, dir)
	srv := newTestFleetServer(t)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()
	sentinelID, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}

	if !pollUntil(t, 2*time.Second, func() bool {
		rec, ok := fetchFleetRecord(t, srv, sentinelID)
		return ok && rec.RepoPath == repoAbs
	}) {
		t.Fatal("expected a repo path containing spaces to enroll and report correctly")
	}
}
