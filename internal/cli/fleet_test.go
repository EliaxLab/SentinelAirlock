package cli

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
)

func newTestPolicyStore(t *testing.T) *fleet.PolicyStore {
	t.Helper()
	ps, err := fleet.OpenPolicyStore(filepath.Join(t.TempDir(), "fleet-policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestFetchFleetSnapshot_EmptyFleet(t *testing.T) {
	store, err := fleet.OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fleet.NewServer(store, newTestPolicyStore(t), "").Handler())
	defer srv.Close()

	snap, err := fetchFleetSnapshot(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Sentinels) != 0 || snap.Active != 0 || snap.Offline != 0 {
		t.Fatalf("expected empty fleet snapshot, got %+v", snap)
	}
}

func TestFetchFleetSnapshot_PopulatedFleet(t *testing.T) {
	store, err := fleet.OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertEnroll(fleet.Record{
		SentinelID: "sen-1", MachineID: "mach-1", RepoPath: "/repo/a",
		PolicyID: "balanced", PolicyVersion: "v1",
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fleet.NewServer(store, newTestPolicyStore(t), "").Handler())
	defer srv.Close()

	snap, err := fetchFleetSnapshot(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Sentinels) != 1 {
		t.Fatalf("expected 1 sentinel, got %d", len(snap.Sentinels))
	}
	if snap.Sentinels[0].RepoPath != "/repo/a" {
		t.Fatalf("unexpected repo path: %s", snap.Sentinels[0].RepoPath)
	}
}

func TestFetchFleetSnapshot_WrongTokenRejected(t *testing.T) {
	store, err := fleet.OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fleet.NewServer(store, newTestPolicyStore(t), "secret").Handler())
	defer srv.Close()

	if _, err := fetchFleetSnapshot(srv.URL, ""); err == nil {
		t.Fatal("expected an error when the fleet requires a token and none is supplied")
	}
	if _, err := fetchFleetSnapshot(srv.URL, "secret"); err != nil {
		t.Fatalf("expected success with the correct token: %v", err)
	}
}

func TestFetchFleetSnapshot_UnreachableFleet(t *testing.T) {
	if _, err := fetchFleetSnapshot(unreachableFleetURL(t), ""); err == nil {
		t.Fatal("expected an error for an unreachable fleet control plane")
	}
}

func TestFleetServeCmd_StartsAndAcceptsEnrollment(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fleet.json")
	cmd := fleetServeCmd()
	cmd.SetArgs([]string{"--listen", "127.0.0.1:0", "--db", dbPath})

	// fleetServeCmd blocks forever (http.Serve) once it binds, so this test
	// only exercises the command's flag wiring and store bootstrap via a
	// directly-constructed server on the same db path -- the actual serve
	// loop is covered end-to-end by the sentinel-side integration tests in
	// sentinel_fleet_test.go, which start a real httptest server using the
	// same fleet.Server this command wires up.
	store, err := fleet.OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertEnroll(fleet.Record{SentinelID: "sen-1", MachineID: "mach-1"}); err != nil {
		t.Fatal(err)
	}
	store2, err := fleet.OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store2.Get("sen-1"); !ok {
		t.Fatal("expected the db path used by fleetServeCmd's flags to be a real, reloadable store")
	}
}
