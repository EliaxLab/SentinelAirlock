package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Policy signing (Prompt 14B).
//
// Ed25519 is used because it is already this project's signing primitive
// (internal/runmeta/verify.go and internal/cli/run.go sign run digests with
// it, reading hex- or base64-encoded keys), so operators meet one key format
// and one algorithm across Airlock rather than two. It needs no parameter
// choices, produces small fixed-size signatures, and is entirely in the Go
// standard library -- no new dependency.
//
// What is signed is a canonical, fully-typed payload (see
// PolicySigningPayload), never a raw map serialization: Go's encoding/json
// emits struct fields in declaration order, so marshaling a struct with no
// map-typed fields is deterministic. That determinism is what makes a
// signature reproducible on the Sentinel side from the policy's own stored
// fields.

const (
	// PolicySigningKind and RollbackGrantKind are domain separators. They
	// are part of the signed bytes so a signature over one kind of statement
	// can never be replayed as the other, even if the remaining fields
	// happened to line up.
	PolicySigningKind = "airlock.fleet.policy/v1"
	RollbackGrantKind = "airlock.fleet.rollback-grant/v1"

	// SignatureAlgEd25519 records which algorithm produced a signature, so a
	// future second algorithm can be added without ambiguity about how to
	// verify existing stored signatures.
	SignatureAlgEd25519 = "ed25519"

	// DefaultRollbackGrantTTL bounds how long an explicit downgrade
	// authorization stays usable. Expiry is an *additional* bound on top of
	// the signature -- never the primary check -- so a grant legitimately
	// issued months ago cannot be replayed later to force a Sentinel back
	// onto an old policy. See VerifyRollbackGrant.
	DefaultRollbackGrantTTL = time.Hour
)

var (
	// ErrNoSignature means a policy version carries no signature at all.
	ErrNoSignature = errors.New("policy version is not signed")
	// ErrUnknownSigner means the signature names a key this Sentinel does
	// not trust.
	ErrUnknownSigner = errors.New("policy signed by an untrusted key")
	// ErrBadSignature means the signature did not verify against the
	// canonical payload rebuilt from the policy's own contents.
	ErrBadSignature = errors.New("policy signature is not valid for its contents")
	// ErrDigestMismatch means the policy's stored digest does not match its
	// actual canonical content.
	ErrDigestMismatch = errors.New("policy digest does not match its contents")
)

// SigningKey is the control plane's policy-signing identity. The private key
// is never serialized by this type, never returned by any API, and never
// printed -- only KeyID and PublicKeyHex are safe to surface.
type SigningKey struct {
	KeyID string
	priv  ed25519.PrivateKey
}

// PublicKeyHex returns the hex-encoded public verification key. This is the
// material an operator distributes to Sentinels; it is not a secret.
func (k *SigningKey) PublicKeyHex() string {
	if k == nil {
		return ""
	}
	return hex.EncodeToString(k.priv.Public().(ed25519.PublicKey))
}

// KeyIDFor derives a short, stable identifier for a public key: the first 8
// bytes of its SHA-256, hex encoded. Same construction airlock run already
// uses for run-digest signing key ids (internal/cli/run.go), so operators see
// one key-id format across the product.
func KeyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// GenerateSigningKey creates a fresh Ed25519 signing identity in memory.
func GenerateSigningKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SigningKey{KeyID: KeyIDFor(pub), priv: priv}, nil
}

// LoadOrCreateSigningKey loads the control plane's signing key from path, or
// generates and persists one if path does not exist. The private key is
// written 0600 (owner-only); the public key is written alongside it as
// <path>.pub with 0644, since it is meant to be distributed.
//
// created reports whether a new key was generated, so the caller can tell an
// operator about a first-run bootstrap without implying a key was rotated.
func LoadOrCreateSigningKey(path string) (key *SigningKey, created bool, err error) {
	if k, err := LoadSigningKey(path); err == nil {
		return k, false, nil
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	k, err := GenerateSigningKey()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	// 0600: the signing key is the control plane's authority to tell every
	// enrolled Sentinel what to enforce. Anything readable beyond its owner
	// is a compromise of that authority.
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k.priv)+"\n"), 0o600); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path+".pub", []byte(k.PublicKeyHex()+"\n"), 0o644); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// LoadSigningKey reads an Ed25519 private key (hex-encoded full key or seed)
// from path. It refuses a key file that is readable by anyone but its owner:
// a signing key with loose permissions is a finding, not a warning, and
// failing closed here is far cheaper than discovering it after the fact.
// The permission check is skipped on Windows, where Unix mode bits are not a
// meaningful representation of the ACL that actually governs the file.
func LoadSigningKey(path string) (*SigningKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("signing key %s is readable by other users (mode %04o); run: chmod 600 %s", path, st.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("signing key %s is not hex-encoded", path)
	}
	var priv ed25519.PrivateKey
	switch len(raw) {
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(raw)
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(raw)
	default:
		return nil, fmt.Errorf("signing key %s is not an ed25519 key", path)
	}
	return &SigningKey{KeyID: KeyIDFor(priv.Public().(ed25519.PublicKey)), priv: priv}, nil
}

// ParsePublicKeyHex decodes a hex-encoded Ed25519 public key.
func ParsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not a hex-encoded ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// PolicySigningPayload is the exact statement a control plane signs about a
// policy version. It binds the policy's *meaning*, not just its rule bytes:
// policy id, version, full canonical digest, the canonical content itself,
// the issuing key, and when it was issued are all inside the signature. A
// valid signed body therefore cannot be relabeled as a different policy id or
// version -- doing so changes the signed bytes and invalidates the signature.
//
// Every field is a scalar and the struct contains no maps, so json.Marshal
// output is byte-for-byte reproducible from the same values.
type PolicySigningPayload struct {
	Kind      string `json:"kind"`
	PolicyID  string `json:"policy_id"`
	Version   int    `json:"version"`
	Digest    string `json:"digest"`
	Canonical string `json:"canonical"`
	Issuer    string `json:"issuer"`
	IssuedAt  string `json:"issued_at"`
}

// CanonicalSigningInput renders the deterministic bytes that get signed and
// verified. Both sides build it from the same fields via this one function,
// so there is exactly one definition of "what was signed."
func CanonicalSigningInput(p PolicySigningPayload) ([]byte, error) {
	return json.Marshal(p)
}

// SignPolicyVersion signs pv in place: it recomputes pv's canonical content
// and full digest from pv.YAML (never trusting fields already on the struct),
// then records the algorithm, issuer key id, issue time, and signature.
func (k *SigningKey) SignPolicyVersion(pv *PolicyVersion, issuedAt time.Time) error {
	canonical, _, err := CanonicalPolicyBytes(pv.YAML)
	if err != nil {
		return err
	}
	digest := DigestOf(canonical)
	payload := PolicySigningPayload{
		Kind:      PolicySigningKind,
		PolicyID:  pv.PolicyID,
		Version:   pv.Version,
		Digest:    digest,
		Canonical: string(canonical),
		Issuer:    k.KeyID,
		IssuedAt:  issuedAt.UTC().Format(time.RFC3339Nano),
	}
	input, err := CanonicalSigningInput(payload)
	if err != nil {
		return err
	}
	pv.Digest = digest
	pv.Hash = ShortHash(digest)
	pv.SignatureAlg = SignatureAlgEd25519
	pv.Issuer = k.KeyID
	pv.IssuedAt = issuedAt.UTC()
	pv.Signature = hex.EncodeToString(ed25519.Sign(k.priv, input))
	return nil
}

// TrustStore is a Sentinel's set of trusted policy signers: key id -> hex
// public key. In this release a Sentinel pins exactly one control-plane key
// (established out-of-band at enrollment, see internal/cli/sentinel.go), but
// the map shape is what a later key-rotation story needs, so it is the type
// from the start.
type TrustStore struct {
	Keys map[string]string `json:"keys"`
}

// Trust returns a TrustStore containing a single pinned key.
func Trust(keyID, publicKeyHex string) TrustStore {
	if strings.TrimSpace(keyID) == "" || strings.TrimSpace(publicKeyHex) == "" {
		return TrustStore{}
	}
	return TrustStore{Keys: map[string]string{keyID: publicKeyHex}}
}

// Empty reports whether this Sentinel trusts no signer at all -- meaning it
// has never established a signing relationship with a control plane and
// cannot verify any signature.
func (t TrustStore) Empty() bool { return len(t.Keys) == 0 }

func (t TrustStore) publicKey(keyID string) (ed25519.PublicKey, bool) {
	hexKey, ok := t.Keys[keyID]
	if !ok {
		return nil, false
	}
	pub, err := ParsePublicKeyHex(hexKey)
	if err != nil {
		return nil, false
	}
	return pub, true
}

// VerifyPolicyVersion is the single gate a fetched policy must pass before a
// Sentinel will consider applying it. It checks, in order:
//
//  1. a signature is present at all
//  2. the naming signer is one this Sentinel trusts
//  3. the policy's stored digest actually matches its own content
//  4. the signature verifies over the canonical payload rebuilt from the
//     policy's own fields
//
// Step 3 comes before step 4 deliberately: the digest is rebuilt from
// pv.YAML rather than read from pv.Digest, so a payload whose content was
// swapped fails here even before the signature check, and the signature check
// itself is performed over content that has already been proven to match the
// digest being signed. Together these mean a modification to either the
// content or any identifying field invalidates the result.
func VerifyPolicyVersion(pv PolicyVersion, trust TrustStore) error {
	if strings.TrimSpace(pv.Signature) == "" || strings.TrimSpace(pv.Issuer) == "" {
		return ErrNoSignature
	}
	pub, ok := trust.publicKey(pv.Issuer)
	if !ok {
		return fmt.Errorf("%w: key id %s", ErrUnknownSigner, pv.Issuer)
	}
	canonical, _, err := CanonicalPolicyBytes(pv.YAML)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDigestMismatch, err)
	}
	digest := DigestOf(canonical)
	if pv.Digest == "" || digest != pv.Digest {
		return ErrDigestMismatch
	}
	payload := PolicySigningPayload{
		Kind:      PolicySigningKind,
		PolicyID:  pv.PolicyID,
		Version:   pv.Version,
		Digest:    digest,
		Canonical: string(canonical),
		Issuer:    pv.Issuer,
		IssuedAt:  pv.IssuedAt.UTC().Format(time.RFC3339Nano),
	}
	input, err := CanonicalSigningInput(payload)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(pv.Signature)
	if err != nil {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, input, sig) {
		return ErrBadSignature
	}
	return nil
}

// RollbackGrant is an explicit, signed authorization to move a specific
// Sentinel *backwards* to a specific older policy version.
//
// This exists so that legitimate rollback is a modeled operation rather than
// a global weakening of the anti-downgrade rule. A grant is bound to one
// sentinel id, one policy id, one version, and one content digest, and it
// expires -- so it cannot be replayed against a different Sentinel, reused
// for a different version, or dug up months later to force a Sentinel back
// onto stale policy.
type RollbackGrant struct {
	Kind       string    `json:"kind"`
	SentinelID string    `json:"sentinel_id"`
	PolicyID   string    `json:"policy_id"`
	Version    int       `json:"version"`
	Digest     string    `json:"digest"`
	Issuer     string    `json:"issuer"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Signature  string    `json:"signature,omitempty"`
}

// grantSigningInput renders the deterministic signed bytes of a grant: every
// field except the signature itself.
func grantSigningInput(g RollbackGrant) ([]byte, error) {
	g.Signature = ""
	g.Kind = RollbackGrantKind
	g.IssuedAt = g.IssuedAt.UTC()
	g.ExpiresAt = g.ExpiresAt.UTC()
	return json.Marshal(g)
}

// IssueRollbackGrant signs a downgrade authorization for one Sentinel.
func (k *SigningKey) IssueRollbackGrant(sentinelID string, ref PolicyRef, digest string, now time.Time, ttl time.Duration) (*RollbackGrant, error) {
	if ttl <= 0 {
		ttl = DefaultRollbackGrantTTL
	}
	g := RollbackGrant{
		Kind:       RollbackGrantKind,
		SentinelID: sentinelID,
		PolicyID:   ref.PolicyID,
		Version:    ref.Version,
		Digest:     digest,
		Issuer:     k.KeyID,
		IssuedAt:   now.UTC(),
		ExpiresAt:  now.UTC().Add(ttl),
	}
	input, err := grantSigningInput(g)
	if err != nil {
		return nil, err
	}
	g.Signature = hex.EncodeToString(ed25519.Sign(k.priv, input))
	return &g, nil
}

// VerifyRollbackGrant checks that g really authorizes sentinelID to move to
// the given policy version and content digest, right now. The signature is
// the primary check; the expiry window and the sentinel/policy/version/digest
// binding are additional constraints on top of it, not substitutes for it.
func VerifyRollbackGrant(g *RollbackGrant, trust TrustStore, sentinelID string, ref PolicyRef, digest string, now time.Time) error {
	if g == nil {
		return errors.New("no rollback authorization present")
	}
	if g.Kind != RollbackGrantKind {
		return errors.New("rollback authorization has the wrong kind")
	}
	if g.SentinelID != sentinelID {
		return errors.New("rollback authorization was issued for a different sentinel")
	}
	if g.PolicyID != ref.PolicyID || g.Version != ref.Version {
		return errors.New("rollback authorization does not match the requested policy version")
	}
	if g.Digest == "" || g.Digest != digest {
		return errors.New("rollback authorization does not match the policy content digest")
	}
	if now.After(g.ExpiresAt) {
		return fmt.Errorf("rollback authorization expired at %s", g.ExpiresAt.UTC().Format(time.RFC3339))
	}
	pub, ok := trust.publicKey(g.Issuer)
	if !ok {
		return fmt.Errorf("%w: rollback authorization key id %s", ErrUnknownSigner, g.Issuer)
	}
	input, err := grantSigningInput(*g)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(g.Signature)
	if err != nil || !ed25519.Verify(pub, input, sig) {
		return errors.New("rollback authorization signature is not valid")
	}
	return nil
}
