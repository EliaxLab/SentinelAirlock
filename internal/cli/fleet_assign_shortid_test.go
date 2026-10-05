package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const denyConfigTxtYAML = `version: 1
policy:
  deny_write:
    - "config.txt"
network:
  mode: "off"
`

func runFleetAssign(t *testing.T, fleetURL, sentinel string, version int) error {
	t.Helper()
	cmd := fleetPolicyAssignCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"production", "--fleet", fleetURL, "--sentinel", sentinel, "--version", strconv.Itoa(version)})
	return cmd.Execute()
}

// Assigning by the short ID `fleet list` displays must update the existing,
// enrolled Sentinel -- no phantom record -- and the signed policy must reach
// that Sentinel, reach IN_SYNC, and be enforced by the same running process.
func TestFleetAssign_ShortID_DeliversSignedPolicyToRunningSentinel(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)
	sentinelID := sentinelIDFor(t, repoAbs)

	sess := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	defer sess.shutdown()
	if !pollUntil(t, 3*time.Second, func() bool { return sess.getIdentityState() == "AUTHENTICATED" }) {
		t.Fatal("sentinel did not enroll")
	}
	if n := len(tf.store.List()); n != 1 {
		t.Fatalf("expected exactly 1 enrolled sentinel, got %d", n)
	}

	v1, err := tf.policyStore.Create("production", "v1", denyConfigTxtYAML)
	if err != nil {
		t.Fatal(err)
	}
	if !v1.Signed() {
		t.Fatal("test setup: the control plane should have signed v1")
	}

	// Before the assignment the local policy allows config.txt.
	cfg := filepath.Join(dir, "config.txt")
	if err := os.WriteFile(cfg, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if b, err := os.ReadFile(cfg); err != nil || string(b) != "a" {
		t.Fatalf("config.txt should be allowed before the Fleet policy is assigned (content=%q err=%v)", b, err)
	}

	short := sentinelID[:8]
	if err := runFleetAssign(t, tf.srv.URL, short, 1); err != nil {
		t.Fatalf("assign by short ID failed: %v", err)
	}

	// Inventory unchanged: still one record, the real one; nothing keyed by the short ID.
	if recs := tf.store.List(); len(recs) != 1 || recs[0].SentinelID != sentinelID {
		t.Fatalf("assignment changed inventory: %+v", recs)
	}
	if _, ok := tf.store.Get(short); ok {
		t.Fatal("a phantom record keyed by the short ID was created")
	}

	// Signed policy reaches the intended Sentinel and it reports IN_SYNC.
	if !pollUntil(t, 4*time.Second, func() bool {
		return sess.getFleetPolicyRef().Version == 1 && sess.getSignatureState() == "VERIFIED"
	}) {
		t.Fatalf("expected a verified reconciliation to v1, got ref=%+v state=%q", sess.getFleetPolicyRef(), sess.getSignatureState())
	}
	if !pollUntil(t, 4*time.Second, func() bool {
		rec, ok := tf.store.Get(sentinelID)
		return ok && fleetReconcileStateIsInSync(rec)
	}) {
		rec, _ := tf.store.Get(sentinelID)
		t.Fatalf("expected IN_SYNC, got %+v", rec)
	}

	// The new rule is enforced by the same, un-restarted session.
	if err := os.WriteFile(cfg, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 3*time.Second, func() bool {
		b, err := os.ReadFile(cfg)
		return err == nil && string(b) == "a"
	}) {
		b, _ := os.ReadFile(cfg)
		t.Fatalf("the newly assigned deny rule was not enforced (config.txt=%q)", b)
	}
	if recs := tf.store.List(); len(recs) != 1 {
		t.Fatalf("inventory changed after reconciliation: %+v", recs)
	}
}

// Unknown IDs fail clearly through the real CLI command and change nothing.
func TestFleetAssign_UnknownID_FailsClearlyAndChangesNothing(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)
	sentinelID := sentinelIDFor(t, repoAbs)

	sess := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	defer sess.shutdown()
	if !pollUntil(t, 3*time.Second, func() bool { return sess.getIdentityState() == "AUTHENTICATED" }) {
		t.Fatal("sentinel did not enroll")
	}
	if _, err := tf.policyStore.Create("production", "v1", denyConfigTxtYAML); err != nil {
		t.Fatal(err)
	}

	err := runFleetAssign(t, tf.srv.URL, "deadbeef", 1)
	if err == nil || !strings.Contains(err.Error(), "sentinel not found") {
		t.Fatalf("expected a clear 'sentinel not found' error, got %v", err)
	}
	recs := tf.store.List()
	if len(recs) != 1 || recs[0].SentinelID != sentinelID || recs[0].DesiredPolicyID != "" {
		t.Fatalf("a failed assignment changed inventory or assignments: %+v", recs)
	}
}
