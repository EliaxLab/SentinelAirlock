package fleet

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newTestAuthStore(t *testing.T) *AuthStore {
	t.Helper()
	s, err := OpenAuthStore(filepath.Join(t.TempDir(), "fleet-auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// --- 1: a one-time enrollment token works -----------------------------------

func TestAuth_EnrollTokenIssuesCredential(t *testing.T) {
	auth := newTestAuthStore(t)
	token, rec, err := auth.CreateEnrollToken("laptop", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || rec.TokenHash == "" {
		t.Fatal("expected both a plaintext token and a stored hash")
	}
	if strings.Contains(rec.TokenHash, token) {
		t.Fatal("the stored record must not contain the plaintext token")
	}

	cred, credRec, err := auth.ConsumeEnrollToken(token, "sen-1")
	if err != nil {
		t.Fatalf("a valid token should enroll: %v", err)
	}
	if cred == "" {
		t.Fatal("expected a credential to be issued")
	}
	if credRec.CredentialHash == "" || strings.Contains(credRec.CredentialHash, cred) {
		t.Fatal("only the credential's hash may be stored")
	}

	// --- 3: the credential authenticates, and resolves to its own identity.
	id, err := auth.Authenticate(cred)
	if err != nil || id != "sen-1" {
		t.Fatalf("the issued credential must authenticate as sen-1, got %q, %v", id, err)
	}
}

// --- 2: used / expired / revoked tokens are rejected ------------------------

func TestAuth_UsedEnrollTokenIsRejected(t *testing.T) {
	auth := newTestAuthStore(t)
	token, _, err := auth.CreateEnrollToken("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.ConsumeEnrollToken(token, "sen-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.ConsumeEnrollToken(token, "sen-2"); !errors.Is(err, ErrEnrollTokenInvalid) {
		t.Fatalf("a one-time token must not work twice, got %v", err)
	}
}

func TestAuth_ExpiredEnrollTokenIsRejected(t *testing.T) {
	auth := newTestAuthStore(t)
	token, _, err := auth.CreateEnrollToken("", time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, _, err := auth.ConsumeEnrollToken(token, "sen-1"); !errors.Is(err, ErrEnrollTokenInvalid) {
		t.Fatalf("an expired token must be rejected, got %v", err)
	}
}

func TestAuth_RevokedEnrollTokenIsRejected(t *testing.T) {
	auth := newTestAuthStore(t)
	token, rec, err := auth.CreateEnrollToken("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RevokeEnrollToken(rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.ConsumeEnrollToken(token, "sen-1"); !errors.Is(err, ErrEnrollTokenInvalid) {
		t.Fatalf("a revoked token must be rejected, got %v", err)
	}
}

func TestAuth_UnknownEnrollTokenIsRejected(t *testing.T) {
	auth := newTestAuthStore(t)
	if _, _, err := auth.ConsumeEnrollToken("airlock_et_not-a-real-token", "sen-1"); !errors.Is(err, ErrEnrollTokenInvalid) {
		t.Fatalf("an unknown token must be rejected, got %v", err)
	}
}

func TestAuth_EnrollTokenCannotSeizeAnEnrolledIdentity(t *testing.T) {
	// An enrollment token brings a NEW identity online. It must not be a way
	// for whoever holds one to claim an identity that already has a working
	// credential -- otherwise a token handed to a new machine could be used
	// to become an existing Sentinel and inherit its policy assignment.
	auth := newTestAuthStore(t)
	first, _, _ := auth.CreateEnrollToken("", time.Hour)
	if _, _, err := auth.ConsumeEnrollToken(first, "sen-1"); err != nil {
		t.Fatal(err)
	}
	second, _, _ := auth.CreateEnrollToken("", time.Hour)
	if _, _, err := auth.ConsumeEnrollToken(second, "sen-1"); !errors.Is(err, ErrSentinelAlreadyEnrolled) {
		t.Fatalf("expected takeover of an enrolled identity to be refused, got %v", err)
	}

	// After an operator revokes it, re-enrollment is allowed again.
	if err := auth.RevokeSentinel("sen-1", "machine rebuilt"); err != nil {
		t.Fatal(err)
	}
	third, _, _ := auth.CreateEnrollToken("", time.Hour)
	if _, _, err := auth.ConsumeEnrollToken(third, "sen-1"); err != nil {
		t.Fatalf("re-enrollment after revocation should be allowed, got %v", err)
	}
}

// --- 5: a wrong credential is rejected --------------------------------------

func TestAuth_WrongCredentialIsRejected(t *testing.T) {
	auth := newTestAuthStore(t)
	token, _, _ := auth.CreateEnrollToken("", time.Hour)
	if _, _, err := auth.ConsumeEnrollToken(token, "sen-1"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "airlock_sc_wrong", "sen-1"} {
		if _, err := auth.Authenticate(bad); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("credential %q must not authenticate, got %v", bad, err)
		}
	}
}

// --- 6: a revoked credential is rejected, distinguishably -------------------

func TestAuth_RevokedCredentialIsRejectedAsRevoked(t *testing.T) {
	auth := newTestAuthStore(t)
	token, _, _ := auth.CreateEnrollToken("", time.Hour)
	cred, _, err := auth.ConsumeEnrollToken(token, "sen-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RevokeSentinel("sen-1", "decommissioned"); err != nil {
		t.Fatal(err)
	}
	id, err := auth.Authenticate(cred)
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("a revoked credential must be rejected as revoked (not as generic failure), got %v", err)
	}
	if id != "sen-1" {
		t.Fatalf("revocation should still identify which sentinel was revoked, got %q", id)
	}
}

func TestAuth_StoreSurvivesRestartAndStaysOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-auth.json")
	first, err := OpenAuthStore(path)
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ := first.CreateEnrollToken("", time.Hour)
	cred, _, err := first.ConsumeEnrollToken(token, "sen-1")
	if err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("the auth store holds secret material and must be owner-only, got %04o", st.Mode().Perm())
		}
	}

	second, err := OpenAuthStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := second.Authenticate(cred); err != nil || id != "sen-1" {
		t.Fatalf("credentials must survive a control-plane restart, got %q, %v", id, err)
	}
}

// --- 23: no plaintext secret is ever persisted ------------------------------

func TestAuth_NoPlaintextSecretsAreWrittenToDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet-auth.json")
	auth, err := OpenAuthStore(path)
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ := auth.CreateEnrollToken("laptop", time.Hour)
	cred, _, err := auth.ConsumeEnrollToken(token, "sen-1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stored := string(b)
	if strings.Contains(stored, token) {
		t.Fatal("the enrollment token's plaintext must never be persisted")
	}
	if strings.Contains(stored, cred) {
		t.Fatal("the credential's plaintext must never be persisted")
	}
}

func TestPrincipal_CanActAsOnlyItself(t *testing.T) {
	sentinel := Principal{Type: PrincipalSentinel, SentinelID: "sen-1"}
	if !sentinel.CanActAs("sen-1") {
		t.Fatal("a sentinel principal must be able to act as itself")
	}
	if sentinel.CanActAs("sen-2") {
		t.Fatal("a sentinel principal must not be able to act as another sentinel")
	}
	// An operator credential manages the fleet; it is not a licence to submit
	// data as a member of it.
	if (Principal{Type: PrincipalOperator}).CanActAs("sen-1") {
		t.Fatal("an operator principal must not be able to impersonate a sentinel")
	}
	if (Principal{Type: PrincipalAnonymous}).CanActAs("") {
		t.Fatal("an anonymous principal must never act as anything")
	}
}
