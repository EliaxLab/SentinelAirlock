package fleet

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore_UpsertEnroll_NewRecord(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rec, err := s.UpsertEnroll(Record{SentinelID: "sen-1", MachineID: "mach-1", RepoPath: "/repo/a", StartedAt: now, EnrolledAt: now, LastHeartbeat: now})
	if err != nil {
		t.Fatal(err)
	}
	if rec.EnrolledAt.IsZero() {
		t.Fatal("expected EnrolledAt to be set on first enrollment")
	}
	got, ok := s.Get("sen-1")
	if !ok || got.RepoPath != "/repo/a" {
		t.Fatalf("Get after enroll = %+v, %v", got, ok)
	}
}

func TestStore_UpsertEnroll_PreservesOriginalEnrolledAt(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := time.Now().UTC().Add(-time.Hour)
	if _, err := s.UpsertEnroll(Record{SentinelID: "sen-1", MachineID: "mach-1", EnrolledAt: first, LastHeartbeat: first}); err != nil {
		t.Fatal(err)
	}
	second := time.Now().UTC()
	rec, err := s.UpsertEnroll(Record{SentinelID: "sen-1", MachineID: "mach-1", EnrolledAt: second, StartedAt: second, LastHeartbeat: second})
	if err != nil {
		t.Fatal(err)
	}
	if !rec.EnrolledAt.Equal(first) {
		t.Fatalf("EnrolledAt should stay sticky across re-enrollment: got %v, want %v", rec.EnrolledAt, first)
	}
	if !rec.StartedAt.Equal(second) {
		t.Fatalf("StartedAt should refresh on re-enrollment: got %v, want %v", rec.StartedAt, second)
	}
}

func TestStore_UpsertEnroll_PreservesDesiredPolicyAssignment(t *testing.T) {
	// A desired policy may be assigned before a Sentinel has ever enrolled,
	// or while it's offline/restarting. Re-enrolling (which happens on
	// every Sentinel restart) must never silently clear that assignment --
	// the enroll request has no opinion on desired state at all.
	s, err := OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignPolicy("sen-1", PolicyRef{PolicyID: "production", Version: 3, Hash: "abc"}, "", nil); err != nil {
		t.Fatal(err)
	}
	rec, err := s.UpsertEnroll(Record{SentinelID: "sen-1", MachineID: "mach-1", LastHeartbeat: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if rec.DesiredPolicyID != "production" || rec.DesiredPolicyVersion != 3 || rec.DesiredPolicyHash != "abc" {
		t.Fatalf("enroll must not clear a pre-existing desired policy assignment, got %+v", rec)
	}
}

func TestStore_UpsertHeartbeat_UpdatesExistingRecord(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s.UpsertEnroll(Record{SentinelID: "sen-1", MachineID: "mach-1", RepoPath: "/repo/a", EnrolledAt: now, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}
	later := now.Add(30 * time.Second)
	rec, err := s.UpsertHeartbeat("sen-1", func(r *Record) {
		r.LastHeartbeat = later
		r.AllowCount = 5
		r.DenyCount = 2
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.RepoPath != "/repo/a" {
		t.Fatalf("heartbeat should not blank fields it did not set: RepoPath=%q", rec.RepoPath)
	}
	if rec.AllowCount != 5 || rec.DenyCount != 2 {
		t.Fatalf("counters not applied: %+v", rec)
	}
	if !rec.LastHeartbeat.Equal(later) {
		t.Fatalf("LastHeartbeat not updated: %v", rec.LastHeartbeat)
	}
}

func TestStore_UpsertHeartbeat_UnknownID_CreatesMinimalRecord(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.UpsertHeartbeat("never-enrolled", func(r *Record) {
		r.LastHeartbeat = time.Now().UTC()
		r.Status = "running"
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.SentinelID != "never-enrolled" {
		t.Fatalf("expected minimal record to be created with the heartbeat's id, got %+v", rec)
	}
	if _, ok := s.Get("never-enrolled"); !ok {
		t.Fatal("record should be visible in the store after a heartbeat for an unknown id")
	}
}

func TestStore_List_RetainsOfflineSentinels(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	stale := time.Now().UTC().Add(-time.Hour)
	if _, err := s.UpsertEnroll(Record{SentinelID: "sen-old", MachineID: "m", EnrolledAt: stale, LastHeartbeat: stale}); err != nil {
		t.Fatal(err)
	}
	list := s.List()
	if len(list) != 1 {
		t.Fatalf("expected the stale sentinel to remain listed, got %d entries", len(list))
	}
	if Health(list[0], time.Now().UTC()) != "OFFLINE" {
		t.Fatal("expected stale heartbeat to compute OFFLINE")
	}
}

func TestStore_MultipleSentinels_Coexist(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i, id := range []string{"sen-a", "sen-b", "sen-c"} {
		_, err := s.UpsertEnroll(Record{SentinelID: id, MachineID: "mach-1", RepoPath: "/repo/" + id, EnrolledAt: now, LastHeartbeat: now})
		if err != nil {
			t.Fatalf("enroll %d: %v", i, err)
		}
	}
	list := s.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 sentinels, got %d", len(list))
	}
}

func TestStore_RestartPreservesDurableInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	s1, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s1.UpsertEnroll(Record{SentinelID: "sen-1", MachineID: "mach-1", RepoPath: "/repo/a", EnrolledAt: now, LastHeartbeat: now}); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := s2.Get("sen-1")
	if !ok || rec.RepoPath != "/repo/a" {
		t.Fatalf("expected inventory to survive a fresh OpenStore (simulated control-plane restart): %+v, %v", rec, ok)
	}
}

func TestHealth_RecentHeartbeatIsActive(t *testing.T) {
	rec := Record{LastHeartbeat: time.Now().UTC()}
	if Health(rec, time.Now().UTC()) != "ACTIVE" {
		t.Fatal("expected recent heartbeat to be ACTIVE")
	}
}

func TestHealth_StaleHeartbeatIsOffline(t *testing.T) {
	rec := Record{LastHeartbeat: time.Now().UTC().Add(-OfflineThreshold - time.Second)}
	if Health(rec, time.Now().UTC()) != "OFFLINE" {
		t.Fatal("expected stale heartbeat to be OFFLINE")
	}
}

func TestHealth_NeverHeartbeatIsOffline(t *testing.T) {
	if Health(Record{}, time.Now().UTC()) != "OFFLINE" {
		t.Fatal("expected zero-value LastHeartbeat to be OFFLINE")
	}
}
