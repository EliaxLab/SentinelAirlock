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

const signedSampleYAML = `version: 1
policy:
  deny_write: ["**/.env"]
network:
  mode: "off"
`

func newSignedVersion(t *testing.T, key *SigningKey, policyID string, version int, yamlContent string) PolicyVersion {
	t.Helper()
	digest, short, _, err := ComputePolicyDigest(yamlContent)
	if err != nil {
		t.Fatal(err)
	}
	pv := PolicyVersion{PolicyID: policyID, Version: version, Hash: short, Digest: digest, YAML: yamlContent}
	if err := key.SignPolicyVersion(&pv, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return pv
}

func testKey(t *testing.T) *SigningKey {
	t.Helper()
	k, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// --- 8: a genuine signature verifies ----------------------------------------

func TestSigning_ValidSignatureVerifies(t *testing.T) {
	key := testKey(t)
	pv := newSignedVersion(t, key, "production", 1, signedSampleYAML)
	if err := VerifyPolicyVersion(pv, Trust(key.KeyID, key.PublicKeyHex())); err != nil {
		t.Fatalf("a policy signed by the trusted key should verify, got %v", err)
	}
}

// --- 9: modified contents fail verification ---------------------------------

func TestSigning_ModifiedContentFailsVerification(t *testing.T) {
	key := testKey(t)
	pv := newSignedVersion(t, key, "production", 1, signedSampleYAML)
	trust := Trust(key.KeyID, key.PublicKeyHex())

	// Swap the rules for something looser while leaving every other field --
	// including the signature and the claimed digest -- untouched. This is
	// the attack the signature exists to stop.
	tampered := pv
	tampered.YAML = "version: 1\npolicy:\n  deny_write: []\nnetwork:\n  mode: \"off\"\n"
	if err := VerifyPolicyVersion(tampered, trust); err == nil {
		t.Fatal("modified policy content must not verify")
	} else if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected a digest mismatch, got %v", err)
	}

	// And with the digest updated to match the new content, so only the
	// signature is stale: it must still fail.
	digest, short, _, err := ComputePolicyDigest(tampered.YAML)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Digest, tampered.Hash = digest, short
	if err := VerifyPolicyVersion(tampered, trust); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("content swapped with a recomputed digest must fail the signature check, got %v", err)
	}
}

// --- 10: a modified signature fails -----------------------------------------

func TestSigning_ModifiedSignatureFails(t *testing.T) {
	key := testKey(t)
	pv := newSignedVersion(t, key, "production", 1, signedSampleYAML)
	trust := Trust(key.KeyID, key.PublicKeyHex())

	flipped := []byte(pv.Signature)
	if flipped[0] == 'a' {
		flipped[0] = 'b'
	} else {
		flipped[0] = 'a'
	}
	pv.Signature = string(flipped)
	if err := VerifyPolicyVersion(pv, trust); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a mutated signature must fail, got %v", err)
	}
}

func TestSigning_UnsignedPolicyIsRejectedWhenAKeyIsPinned(t *testing.T) {
	key := testKey(t)
	digest, short, _, err := ComputePolicyDigest(signedSampleYAML)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := PolicyVersion{PolicyID: "production", Version: 1, Hash: short, Digest: digest, YAML: signedSampleYAML}
	if err := VerifyPolicyVersion(unsigned, Trust(key.KeyID, key.PublicKeyHex())); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("an unsigned policy must be rejected once a signing key is pinned, got %v", err)
	}
}

// --- 11: an unknown signer fails --------------------------------------------

func TestSigning_UnknownSignerFails(t *testing.T) {
	attacker := testKey(t)
	legitimate := testKey(t)
	pv := newSignedVersion(t, attacker, "production", 1, signedSampleYAML)
	if err := VerifyPolicyVersion(pv, Trust(legitimate.KeyID, legitimate.PublicKeyHex())); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("a policy signed by an untrusted key must be rejected, got %v", err)
	}
}

func TestSigning_SignatureIsBoundToPolicyIdentity(t *testing.T) {
	// A valid signed body must not be relabelable as a different policy or
	// version: the identifying fields are inside the signed bytes.
	key := testKey(t)
	trust := Trust(key.KeyID, key.PublicKeyHex())
	pv := newSignedVersion(t, key, "production", 7, signedSampleYAML)

	relabeledID := pv
	relabeledID.PolicyID = "permissive"
	if err := VerifyPolicyVersion(relabeledID, trust); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("relabeling the policy id must invalidate the signature, got %v", err)
	}

	relabeledVersion := pv
	relabeledVersion.Version = 99
	if err := VerifyPolicyVersion(relabeledVersion, trust); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("relabeling the version must invalidate the signature, got %v", err)
	}

	reissued := pv
	reissued.IssuedAt = pv.IssuedAt.Add(time.Hour)
	if err := VerifyPolicyVersion(reissued, trust); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("changing issued_at must invalidate the signature, got %v", err)
	}
}

// --- 12: the canonical signing input is deterministic -----------------------

func TestSigning_CanonicalInputIsDeterministic(t *testing.T) {
	payload := PolicySigningPayload{
		Kind: PolicySigningKind, PolicyID: "production", Version: 3,
		Digest: "abc", Canonical: `{"x":1}`, Issuer: "key-1", IssuedAt: "2026-09-05T00:00:00Z",
	}
	first, err := CanonicalSigningInput(payload)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		again, err := CanonicalSigningInput(payload)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("canonical signing input must be byte-identical across calls:\n%s\n%s", first, again)
		}
	}
}

func TestSigning_CanonicalPolicyBytesIgnoreFormatting(t *testing.T) {
	// Two documents that mean the same thing must sign identically, so a
	// reformat or an added comment is not mistaken for a policy change.
	withComments := "# a comment\nversion: 1\npolicy:\n\n  deny_write:   [\"**/.env\"]\nnetwork:\n  mode: \"off\"\n"
	a, _, _, err := ComputePolicyDigest(signedSampleYAML)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := ComputePolicyDigest(withComments)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("equivalent policies must produce the same digest:\n%s\n%s", a, b)
	}
}

func TestSigning_DigestIsFullSHA256AndShortHashDerivesFromIt(t *testing.T) {
	digest, short, _, err := ComputePolicyDigest(signedSampleYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatalf("the signing digest must be a full SHA-256 (64 hex chars), got %d", len(digest))
	}
	if len(short) != 16 || !strings.HasPrefix(digest, short) {
		t.Fatalf("the short display hash must be the digest's prefix, got %q from %q", short, digest)
	}
}

// --- 14: anti-downgrade / rollback grants -----------------------------------

func TestRollbackGrant_ValidGrantAuthorizesExactlyItsTarget(t *testing.T) {
	key := testKey(t)
	trust := Trust(key.KeyID, key.PublicKeyHex())
	ref := PolicyRef{PolicyID: "production", Version: 3, Hash: "aaaa"}
	now := time.Now().UTC()

	grant, err := key.IssueRollbackGrant("sen-1", ref, "digest-3", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRollbackGrant(grant, trust, "sen-1", ref, "digest-3", now); err != nil {
		t.Fatalf("a freshly issued grant must verify for its own target, got %v", err)
	}
	if err := VerifyRollbackGrant(grant, trust, "sen-2", ref, "digest-3", now); err == nil {
		t.Fatal("a grant must not authorize a different sentinel")
	}
	if err := VerifyRollbackGrant(grant, trust, "sen-1", PolicyRef{PolicyID: "production", Version: 2}, "digest-3", now); err == nil {
		t.Fatal("a grant must not authorize a different version")
	}
	if err := VerifyRollbackGrant(grant, trust, "sen-1", ref, "some-other-digest", now); err == nil {
		t.Fatal("a grant must not authorize different content")
	}
	if err := VerifyRollbackGrant(grant, trust, "sen-1", ref, "digest-3", now.Add(2*time.Hour)); err == nil {
		t.Fatal("an expired grant must not authorize a downgrade")
	}
}

func TestRollbackGrant_ForgedOrUnsignedGrantIsRejected(t *testing.T) {
	key := testKey(t)
	attacker := testKey(t)
	trust := Trust(key.KeyID, key.PublicKeyHex())
	ref := PolicyRef{PolicyID: "production", Version: 3}
	now := time.Now().UTC()

	if err := VerifyRollbackGrant(nil, trust, "sen-1", ref, "digest-3", now); err == nil {
		t.Fatal("a missing grant must not authorize a downgrade")
	}

	// A grant an attacker simply fabricated, with no signature at all.
	fabricated := &RollbackGrant{
		Kind: RollbackGrantKind, SentinelID: "sen-1", PolicyID: "production", Version: 3,
		Digest: "digest-3", Issuer: key.KeyID, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := VerifyRollbackGrant(fabricated, trust, "sen-1", ref, "digest-3", now); err == nil {
		t.Fatal("an unsigned grant must be rejected")
	}

	// A grant correctly signed, but by a key this Sentinel does not trust.
	forged, err := attacker.IssueRollbackGrant("sen-1", ref, "digest-3", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRollbackGrant(forged, trust, "sen-1", ref, "digest-3", now); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("a grant signed by an untrusted key must be rejected, got %v", err)
	}
}

// --- 24: key material handling ----------------------------------------------

func TestSigningKey_PrivateKeyIsWrittenOwnerOnlyAndNeverSerialized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing-key")
	key, created, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected a new key to be created")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("the signing private key must be owner-only, got mode %04o", st.Mode().Perm())
	}
	pubBytes, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatalf("expected a distributable public key file: %v", err)
	}
	if strings.TrimSpace(string(pubBytes)) != key.PublicKeyHex() {
		t.Fatal("the .pub file must contain the public key")
	}

	// The private key must not be reachable through the type's exported
	// surface: PublicKeyHex is public material, and there is no accessor that
	// yields the private half.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(key.PublicKeyHex(), strings.TrimSpace(string(raw))) {
		t.Fatal("the public key must not contain the private key")
	}
}

func TestSigningKey_ReloadIsStableAndRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing-key")
	first, _, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, created, err := LoadOrCreateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("an existing key must be loaded, never silently replaced")
	}
	if first.KeyID != second.KeyID {
		t.Fatalf("key id must be stable across loads: %s vs %s", first.KeyID, second.KeyID)
	}

	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not the access control on windows")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(path); err == nil {
		t.Fatal("a world-readable signing key must be refused, not merely warned about")
	}
}
