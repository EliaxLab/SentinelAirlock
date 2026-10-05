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
	"strings"
	"testing"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
)

// trustFleet is a control plane with the full Prompt 14B trust machinery,
// reachable over real HTTP, for end-to-end Sentinel tests.
type trustFleet struct {
	srv         *httptest.Server
	store       *fleet.Store
	policyStore *fleet.PolicyStore
	authStore   *fleet.AuthStore
	alertStore  *fleet.AlertStore
	key         *fleet.SigningKey
	dir         string
}

func newTrustFleet(t *testing.T) *trustFleet {
	t.Helper()
	tf := buildTrustFleet(t, t.TempDir())
	tf.srv = httptest.NewServer(tf.handler())
	t.Cleanup(tf.srv.Close)
	return tf
}

func buildTrustFleet(t *testing.T, dir string) *trustFleet {
	t.Helper()
	store, err := fleet.OpenStore(filepath.Join(dir, "fleet.json"))
	if err != nil {
		t.Fatal(err)
	}
	policyStore, err := fleet.OpenPolicyStore(filepath.Join(dir, "fleet-policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	authStore, err := fleet.OpenAuthStore(filepath.Join(dir, "fleet-auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	alertStore, err := fleet.OpenAlertStore(filepath.Join(dir, "fleet-alerts.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := fleet.LoadOrCreateSigningKey(filepath.Join(dir, "signing-key"))
	if err != nil {
		t.Fatal(err)
	}
	return &trustFleet{store: store, policyStore: policyStore, authStore: authStore, alertStore: alertStore, key: key, dir: dir}
}

func (tf *trustFleet) handler() http.Handler {
	return fleet.NewServerWithOptions(tf.store, tf.policyStore, "", fleet.ServerOptions{
		AuthStore: tf.authStore, AlertStore: tf.alertStore, SigningKey: tf.key, RequireEnrollment: true,
	}).Handler()
}

func (tf *trustFleet) enrollToken(t *testing.T) string {
	t.Helper()
	token, _, err := tf.authStore.CreateEnrollToken("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// assign posts a desired-policy assignment as an operator.
func (tf *trustFleet) assign(t *testing.T, sentinelID, policyID string, version int, allowRollback bool) {
	t.Helper()
	seedEnrolled(t, tf.store, sentinelID)
	body, _ := json.Marshal(map[string]any{"policy_id": policyID, "version": version, "allow_rollback": allowRollback})
	resp, err := http.Post(tf.srv.URL+"/api/fleet/sentinels/"+sentinelID+"/assign", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("assign failed: %s: %s", resp.Status, msg)
	}
}

func sentinelIDFor(t *testing.T, repoAbs string) string {
	t.Helper()
	id, err := fleet.SentinelID(repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// startTrustSentinel starts a Sentinel enrolled against tf with a one-time
// token, and waits for it to become authenticated.
func startTrustSentinel(t *testing.T, repoAbs string, fleetURL, enrollToken string) *sentinelSession {
	t.Helper()
	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false,
		fleetOptions{URL: fleetURL, EnrollToken: enrollToken})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// --- 1/3/23: enrollment establishes a credential, stored safely -------------

func TestSentinelTrust_EnrollsWithTokenAndStoresCredentialSecurely(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)

	sess := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	defer sess.shutdown()

	if !pollUntil(t, 3*time.Second, func() bool { return sess.getIdentityState() == "AUTHENTICATED" }) {
		t.Fatal("expected the sentinel to become AUTHENTICATED after enrolling with a valid token")
	}

	credPath := fleetCredentialPath(repoAbs)
	st, err := os.Stat(credPath)
	if err != nil {
		t.Fatalf("expected a durable credential file: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("the credential file holds a bearer secret and must be owner-only, got %04o", st.Mode().Perm())
	}
	cred, ok := loadFleetCredential(repoAbs)
	if !ok || cred.Credential == "" {
		t.Fatal("expected a stored credential")
	}
	if cred.SigningKeyID != tf.key.KeyID || cred.SigningPublicKey != tf.key.PublicKeyHex() {
		t.Fatal("the control plane's signing key should have been pinned at enrollment")
	}

	// --- 23: the secret must not leak into ordinary evidence output.
	assertSecretNotInEvidence(t, repoAbs, cred.Credential)
}

// assertSecretNotInEvidence walks everything a session writes under .airlock/
// (except the 0600 credential file itself, which is where the secret is
// supposed to live) and fails if the secret appears anywhere in it.
func assertSecretNotInEvidence(t *testing.T, repoAbs, secret string) {
	t.Helper()
	if secret == "" {
		t.Fatal("test setup: no secret to search for")
	}
	credPath := fleetCredentialPath(repoAbs)
	err := filepath.Walk(filepath.Join(repoAbs, ".airlock"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || path == credPath {
			return nil //nolint:nilerr // an unreadable path is not what this test is about
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(b), secret) {
			t.Fatalf("a credential secret leaked into %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// --- 8/13: a signed policy verifies and takes real effect -------------------

func TestSentinelTrust_SignedPolicyIsVerifiedAndEnforced(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)

	v1, err := tf.policyStore.Create("production", "v1", denySpecialYAML)
	if err != nil {
		t.Fatal(err)
	}
	if !v1.Signed() {
		t.Fatal("test setup: the control plane should have signed v1")
	}
	tf.assign(t, sentinelIDFor(t, repoAbs), "production", 1, false)

	sess := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	defer sess.shutdown()

	if !pollUntil(t, 3*time.Second, func() bool {
		return sess.getFleetPolicyRef().Version == 1 && sess.getSignatureState() == "VERIFIED"
	}) {
		t.Fatalf("expected a verified reconciliation to v1, got ref=%+v state=%q",
			sess.getFleetPolicyRef(), sess.getSignatureState())
	}

	// Verified is not enough on its own -- the policy has to actually govern.
	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, "special.txt"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("the signed policy should be genuinely enforced (special.txt reverted)")
	}
}

// --- 9/16: a tampered policy is rejected and the LKG stays active -----------

func TestSentinelTrust_TamperedPolicyRejectedAndLastKnownGoodStaysActive(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)
	sentinelID := sentinelIDFor(t, repoAbs)

	if _, err := tf.policyStore.Create("production", "v1", denySpecialYAML); err != nil {
		t.Fatal(err)
	}
	tf.assign(t, sentinelID, "production", 1, false)

	sess := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	defer sess.shutdown()
	if !pollUntil(t, 3*time.Second, func() bool { return sess.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected v1 to be applied first")
	}

	// v2 legitimately relaxes the rule -- then someone swaps its contents in
	// the control plane's store without re-signing, exactly as a compromised
	// or man-in-the-middle control plane would.
	v2, err := tf.policyStore.AddVersion("production", "v2", allowAllYAML)
	if err != nil {
		t.Fatal(err)
	}
	tamperStoredPolicyContent(t, tf, "production", 2, denyEverythingYAML)
	tf.assign(t, sentinelID, "production", v2.Version, false)

	// The Sentinel must refuse it, and must not silently keep trying forever.
	if !pollUntil(t, 3*time.Second, func() bool {
		rec, ok := tf.store.Get(sentinelID)
		return ok && rec.ReconcileStatus != "" && rec.ReconcileStatus != fleet.ReconcileInProcess
	}) {
		t.Fatal("expected the sentinel to report a reconciliation refusal")
	}
	rec, _ := tf.store.Get(sentinelID)
	if rec.ReconcileStatus != fleet.ReconcileFailed && rec.ReconcileStatus != fleet.SignatureInvalid {
		t.Fatalf("expected a trust/integrity refusal, got %q (%s)", rec.ReconcileStatus, rec.ReconcileError)
	}

	// The critical property: v1 is still what is enforced. Not "no policy",
	// not the tampered content -- the last-known-good.
	if got := sess.getFleetPolicyRef().Version; got != 1 {
		t.Fatalf("the last-known-good policy must stay in force after a rejection, got v%d", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, "special.txt"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("v1 must still be genuinely enforced after the rejected update")
	}
}

const denyEverythingYAML = `version: 1
policy:
  deny_write: ["**"]
network:
  mode: "off"
`

// tamperStoredPolicyContent rewrites a stored version's YAML on disk and
// reloads the control plane's policy store from it, simulating a control
// plane whose stored content no longer matches what was signed.
func tamperStoredPolicyContent(t *testing.T, tf *trustFleet, policyID string, version int, newYAML string) {
	t.Helper()
	path := filepath.Join(tf.dir, "fleet-policies.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policies map[string][]fleet.PolicyVersion
	if err := json.Unmarshal(b, &policies); err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range policies[policyID] {
		if policies[policyID][i].Version == version {
			policies[policyID][i].YAML = newYAML
			found = true
		}
	}
	if !found {
		t.Fatalf("test setup: %s v%d not found to tamper with", policyID, version)
	}
	out, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := fleet.OpenPolicyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.SetSigner(nil)
	tf.policyStore = reloaded
	tf.srv.Config.Handler = tf.handler()
}

// --- 14: an unauthorized downgrade is rejected; an authorized one is not ----

func TestSentinelTrust_DowngradeRejectedUnlessExplicitlyAuthorized(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)
	sentinelID := sentinelIDFor(t, repoAbs)

	if _, err := tf.policyStore.Create("production", "v1", denySpecialYAML); err != nil {
		t.Fatal(err)
	}
	if _, err := tf.policyStore.AddVersion("production", "v2", allowAllYAML); err != nil {
		t.Fatal(err)
	}
	tf.assign(t, sentinelID, "production", 2, false)

	sess := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	defer sess.shutdown()
	if !pollUntil(t, 3*time.Second, func() bool { return sess.getFleetPolicyRef().Version == 2 }) {
		t.Fatal("expected v2 to be applied first")
	}

	// A plain assignment back to v1 is a downgrade, and must be refused.
	tf.assign(t, sentinelID, "production", 1, false)
	if !pollUntil(t, 3*time.Second, func() bool {
		rec, ok := tf.store.Get(sentinelID)
		return ok && rec.ReconcileStatus == fleet.DowngradeRejected
	}) {
		rec, _ := tf.store.Get(sentinelID)
		t.Fatalf("expected DOWNGRADE_REJECTED, got %q (%s)", rec.ReconcileStatus, rec.ReconcileError)
	}
	if got := sess.getFleetPolicyRef().Version; got != 2 {
		t.Fatalf("a refused downgrade must leave v2 in force, got v%d", got)
	}

	// The same move, explicitly authorized with a signed grant, is accepted.
	tf.assign(t, sentinelID, "production", 1, true)
	if !pollUntil(t, 4*time.Second, func() bool { return sess.getFleetPolicyRef().Version == 1 }) {
		rec, _ := tf.store.Get(sentinelID)
		t.Fatalf("an explicitly authorized rollback should be accepted, still at v%d (%s: %s)",
			sess.getFleetPolicyRef().Version, rec.ReconcileStatus, rec.ReconcileError)
	}
}

// --- 15: a hash mismatch is rejected ----------------------------------------

func TestSentinelTrust_DesiredHashMismatchIsRejected(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)
	sentinelID := sentinelIDFor(t, repoAbs)

	v1, err := tf.policyStore.Create("production", "v1", denySpecialYAML)
	if err != nil {
		t.Fatal(err)
	}
	// Desired state that claims a hash the real content does not have.
	seedEnrolled(t, tf.store, sentinelID)
	if _, err := tf.store.AssignPolicy(sentinelID,
		fleet.PolicyRef{PolicyID: "production", Version: v1.Version, Hash: "0000000000000000"}, v1.Digest, nil); err != nil {
		t.Fatal(err)
	}

	sess := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	defer sess.shutdown()

	if !pollUntil(t, 3*time.Second, func() bool {
		rec, ok := tf.store.Get(sentinelID)
		return ok && rec.ReconcileStatus == fleet.ReconcileFailed
	}) {
		t.Fatal("expected a hash mismatch to be refused")
	}
	if !sess.getFleetPolicyRef().Empty() {
		t.Fatal("nothing should have been applied from a hash-mismatched assignment")
	}
}

// --- 17/18: LKG survives restart, and an outage does not disable it ---------

func TestSentinelTrust_LastKnownGoodSurvivesRestartAndControlPlaneOutage(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)
	sentinelID := sentinelIDFor(t, repoAbs)

	if _, err := tf.policyStore.Create("production", "v1", denySpecialYAML); err != nil {
		t.Fatal(err)
	}
	tf.assign(t, sentinelID, "production", 1, false)

	first := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	if !pollUntil(t, 3*time.Second, func() bool { return first.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected v1 to be applied")
	}
	first.shutdown()

	// The control plane is now gone entirely. A restarted Sentinel must come
	// back up enforcing the signed policy it last accepted -- verified again
	// against its pinned key, not merely trusted because a file exists.
	tf.srv.Close()
	second, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false,
		fleetOptions{URL: tf.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer second.shutdown()

	ref := second.getFleetPolicyRef()
	if ref.PolicyID != "production" || ref.Version != 1 {
		t.Fatalf("expected the last-known-good policy to be restored, got %+v", ref)
	}
	if second.getSignatureState() != "VERIFIED" {
		t.Fatalf("the restored policy should have been re-verified against the pinned key, got %q", second.getSignatureState())
	}

	// And it is genuinely governing, with nothing reachable.
	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, "special.txt"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("local enforcement must continue with the control plane down")
	}
}

func TestSentinelTrust_TamperedLastKnownGoodIsNotTrusted(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)
	sentinelID := sentinelIDFor(t, repoAbs)

	if _, err := tf.policyStore.Create("production", "v1", denySpecialYAML); err != nil {
		t.Fatal(err)
	}
	tf.assign(t, sentinelID, "production", 1, false)
	first := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	if !pollUntil(t, 3*time.Second, func() bool { return first.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected v1 to be applied")
	}
	first.shutdown()
	tf.srv.Close()

	// Edit the stored policy on disk. Signed content that no longer matches
	// its signature must not be enforced just because it is sitting in the
	// right file -- otherwise editing JSON would be a way to choose policy.
	lkgPath := fleetPolicyLKGPath(repoAbs)
	b, err := os.ReadFile(lkgPath)
	if err != nil {
		t.Fatal(err)
	}
	var lkg map[string]any
	if err := json.Unmarshal(b, &lkg); err != nil {
		t.Fatal(err)
	}
	lkg["yaml"] = allowAllYAML
	out, _ := json.MarshalIndent(lkg, "", "  ")
	if err := os.WriteFile(lkgPath, out, 0o644); err != nil {
		t.Fatal(err)
	}

	second, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false,
		fleetOptions{URL: tf.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer second.shutdown()
	if !second.getFleetPolicyRef().Empty() {
		t.Fatalf("a tampered last-known-good file must not be adopted, got %+v", second.getFleetPolicyRef())
	}
	// It falls back to the repository's own airlock.yaml -- never to "no
	// policy at all".
	if second.getCfg() == nil {
		t.Fatal("a sentinel must never end up with no policy; it should fall back to local airlock.yaml")
	}
}

// --- 19/21/22: buffering while offline, then flushing on reconnect ----------

func TestSentinelTrust_ReportsBufferWhileOfflineAndFlushOnReconnect(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)

	// secrets/ exists before the session starts, so it is part of the initial
	// watch set. Creating a watched directory and immediately writing into it
	// races the watcher's registration -- a real property of fsnotify, but not
	// what this test is about.
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Bind a fixed address so the control plane can be stopped and restarted
	// at the same URL, the way a real one would be.
	addr := reserveTestAddr(t)
	tf := buildTrustFleet(t, t.TempDir())
	fleetURL := "http://" + addr
	srv := startOn(t, addr, tf.handler())
	tf.srv = srv

	sess := startTrustSentinel(t, repoAbs, fleetURL, tf.enrollToken(t))
	defer sess.shutdown()
	if !pollUntil(t, 3*time.Second, func() bool { return sess.getIdentityState() == "AUTHENTICATED" }) {
		t.Fatal("expected the sentinel to enroll before the outage")
	}

	// Control plane goes away. Governance keeps happening.
	srv.Close()
	for _, name := range []string{".env", "secrets/one.txt", "secrets/two.txt"} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// --- 19: what happened during the outage is buffered, durably.
	if !pollUntil(t, 4*time.Second, func() bool { return sess.bufferedReportCount() >= 3 }) {
		t.Fatalf("expected denials during the outage to be buffered, got %d", sess.bufferedReportCount())
	}
	buffered, err := fleet.OpenOutbox(fleetOutboxPath(repoAbs))
	if err != nil {
		t.Fatal(err)
	}
	if buffered.Len() == 0 {
		t.Fatal("the buffer must be durable on disk, not only in memory")
	}

	// --- 21: the control plane comes back; the buffer drains without a
	// Sentinel restart.
	restarted := startOn(t, addr, tf.handler())
	defer restarted.Close()

	if !pollUntil(t, 6*time.Second, func() bool { return sess.bufferedReportCount() == 0 }) {
		t.Fatalf("expected the outbox to flush on reconnect, %d still pending", sess.bufferedReportCount())
	}
	if tf.alertStore.Len() < 3 {
		t.Fatalf("expected the buffered alerts to arrive at the control plane, got %d", tf.alertStore.Len())
	}

	// --- 22: nothing arrived twice, and no alert carries file contents.
	seen := map[string]bool{}
	for _, a := range tf.alertStore.Recent(100) {
		if seen[a.ID] {
			t.Fatalf("duplicate alert id %s reached the control plane", a.ID)
		}
		seen[a.ID] = true
		if strings.Contains(a.Summary, "secret") || strings.Contains(a.Path, "secret\n") {
			t.Fatalf("an alert appears to carry file contents: %+v", a)
		}
		if filepath.IsAbs(a.Path) {
			t.Fatalf("alert paths must be repo-relative metadata, not absolute, got %q", a.Path)
		}
	}
}

func startOn(t *testing.T, addr string, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: h}}
	srv.Start()
	return srv
}

// --- 7: a revoked Sentinel keeps governing locally --------------------------

func TestSentinelTrust_RevokedSentinelKeepsEnforcingLocally(t *testing.T) {
	t.Setenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL", "80ms")
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)
	tf := newTrustFleet(t)
	sentinelID := sentinelIDFor(t, repoAbs)

	if _, err := tf.policyStore.Create("production", "v1", denySpecialYAML); err != nil {
		t.Fatal(err)
	}
	tf.assign(t, sentinelID, "production", 1, false)

	sess := startTrustSentinel(t, repoAbs, tf.srv.URL, tf.enrollToken(t))
	defer sess.shutdown()
	if !pollUntil(t, 3*time.Second, func() bool { return sess.getFleetPolicyRef().Version == 1 }) {
		t.Fatal("expected v1 to be applied before revocation")
	}

	if err := tf.authStore.RevokeSentinel(sentinelID, "test revocation"); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 4*time.Second, func() bool { return sess.getIdentityState() == "REVOKED" }) {
		t.Fatal("expected the sentinel to notice its credential was revoked")
	}

	// The whole point: revocation removes it from the fleet, and does NOT
	// switch off the protection it was deployed to provide.
	if err := os.WriteFile(filepath.Join(dir, "special.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, "special.txt"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("a revoked sentinel must keep enforcing its last-known-good policy locally")
	}
	if got := sess.getFleetPolicyRef().Version; got != 1 {
		t.Fatalf("revocation must not clear the enforced policy, got v%d", got)
	}

	// And it says so locally, where an operator on that machine can see it.
	st, ok := loadFleetStatus(repoAbs)
	if !ok || st.Identity != "REVOKED" {
		t.Fatalf("expected local status to report the revoked identity, got %+v", st)
	}
}

// --- 26: a standalone Sentinel is untouched by any of this ------------------

func TestSentinelTrust_StandaloneSentinelCreatesNoFleetState(t *testing.T) {
	dir := chdirTempRepo(t)
	repoAbs := canonicalRepo(t, dir)

	sess, err := startSentinelSession(repoAbs, filepath.Join(repoAbs, "airlock.yaml"), "", false, fleetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.shutdown()

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pollUntil(t, 2*time.Second, func() bool {
		_, statErr := os.Stat(filepath.Join(dir, ".env"))
		return os.IsNotExist(statErr)
	}) {
		t.Fatal("a standalone sentinel must govern exactly as before")
	}
	for _, p := range []string{
		fleetCredentialPath(repoAbs), fleetPolicyLKGPath(repoAbs),
		fleetOutboxPath(repoAbs), fleetStatusPath(repoAbs),
	} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("a standalone sentinel must not create fleet state, but %s exists", p)
		}
	}
}
