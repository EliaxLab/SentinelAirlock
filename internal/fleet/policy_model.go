package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mirelahmed-commits/SentinelAirlock/internal/policy"
	"gopkg.in/yaml.v3"
)

// PolicyVersion is one immutable, centrally-managed version of a named
// policy. Content is stored as the raw YAML text of an airlock.yaml-shaped
// document (internal/policy.Config) -- the exact same shape a Sentinel
// already knows how to load locally, so applying a fetched PolicyVersion
// requires no new parsing logic, only a new source for it.
//
// Trust fields (Prompt 14B) were reserved by 14A and are now populated: a
// version created by a signing-capable control plane carries the full
// canonical SHA-256 Digest plus the Signature/Issuer/IssuedAt that bind it.
// Hash remains the short 16-hex display/drift fingerprint -- it is never the
// digest a signature is computed over. See signing.go.
type PolicyVersion struct {
	PolicyID    string    `json:"policy_id"`
	Version     int       `json:"version"`
	Hash        string    `json:"hash"`
	YAML        string    `json:"yaml"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`

	// Digest is the full 64-hex SHA-256 of the canonical policy content --
	// the cryptographic identity of this version's meaning, and what
	// signatures are computed over. Hash (above) is derived from it purely
	// for compact display; a truncated hash must never be the only integrity
	// check standing between a control plane and what a Sentinel enforces.
	Digest string `json:"digest,omitempty"`

	SignatureAlg string    `json:"signature_alg,omitempty"`
	Signature    string    `json:"signature,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	IssuedAt     time.Time `json:"issued_at,omitempty"`
}

// Signed reports whether this version carries signature material at all.
func (v PolicyVersion) Signed() bool {
	return v.Signature != "" && v.Issuer != ""
}

// PolicyRef names a specific version of a named policy -- what gets assigned
// to a Sentinel as its desired state, and what a Sentinel reports back as
// its actual state.
type PolicyRef struct {
	PolicyID string `json:"policy_id"`
	Version  int    `json:"version"`
	Hash     string `json:"hash,omitempty"`
}

func (r PolicyRef) Empty() bool { return r.PolicyID == "" }

// Equal reports whether two refs name the same policy content. Hash is the
// authoritative equality check (it's what actually changes when content
// changes); Version is compared too so a hash collision alone can never
// silently mask a version mismatch in the (extremely unlikely) case one
// occurs.
func (r PolicyRef) Equal(other PolicyRef) bool {
	return r.PolicyID == other.PolicyID && r.Version == other.Version && r.Hash == other.Hash
}

// ComputePolicyHash parses yamlContent as an airlock.yaml-shaped document
// and returns a deterministic content hash plus the parsed config, or an
// error if the content does not parse. The hash is computed from the parsed
// *policy.Config re-marshaled to JSON -- not from the raw YAML text -- so
// whitespace, comments, and key-order differences in equivalent documents
// never produce different hashes, and two independently-typed-out YAML
// files with the same effective policy hash identically. This is called
// both server-side (at policy creation) and Sentinel-side (after fetching,
// to verify the content matches what the server claims before installing
// it) using the exact same algorithm, so a mismatch reliably indicates
// either corruption or a version that has genuinely changed.
func ComputePolicyHash(yamlContent string) (string, *policy.Config, error) {
	_, short, cfg, err := ComputePolicyDigest(yamlContent)
	return short, cfg, err
}

// CanonicalPolicyBytes is the single definition of "the canonical form of
// this policy": parse the YAML into a policy.Config and re-marshal it to
// JSON. policy.Config is a struct with no map-typed fields, so encoding/json
// emits its fields in declaration order and the output is byte-for-byte
// reproducible -- which is what lets the same bytes be hashed on the control
// plane and re-derived on a Sentinel to check a signature.
//
// Canonicalizing through the parsed config (rather than over raw YAML text)
// is also what makes whitespace, comments, and key ordering irrelevant: two
// differently-typed documents with the same effective policy canonicalize
// identically.
func CanonicalPolicyBytes(yamlContent string) ([]byte, *policy.Config, error) {
	var cfg policy.Config
	if err := yaml.Unmarshal([]byte(yamlContent), &cfg); err != nil {
		return nil, nil, fmt.Errorf("invalid policy document: %w", err)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	return b, &cfg, nil
}

// DigestOf returns the full hex SHA-256 of canonical bytes.
func DigestOf(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// ShortHash truncates a full digest to the 16-hex fingerprint used in tables,
// status output, and drift comparison. It is a display convenience only --
// see PolicyVersion.Digest for why it is never the sole integrity check.
func ShortHash(digest string) string {
	if len(digest) <= 16 {
		return digest
	}
	return digest[:16]
}

// ComputePolicyDigest parses yamlContent and returns both its full canonical
// SHA-256 digest (used for signing and integrity) and the short fingerprint
// (used for display and drift comparison), plus the parsed config.
func ComputePolicyDigest(yamlContent string) (digest, short string, cfg *policy.Config, err error) {
	canonical, parsed, err := CanonicalPolicyBytes(yamlContent)
	if err != nil {
		return "", "", nil, err
	}
	digest = DigestOf(canonical)
	return digest, ShortHash(digest), parsed, nil
}

// ReconcileState derives a Sentinel's policy sync status for display,
// analogous to Health() for liveness: computed fresh from the record's
// current desired/actual/reported-error fields rather than trusted as a
// standing flag. See Store.AssignPolicy for how Desired* is set and
// internal/cli/sentinel.go's fleetLoop for how Actual*/Reconcile* get
// reported.
//
//   - "" (unmanaged): no desired policy has ever been assigned.
//   - RECONCILING: the Sentinel has told us it is actively fetching/applying
//     the current desired ref right now.
//   - RECONCILE_FAILED: the Sentinel tried the *current* desired ref and
//     failed; ReconcileError explains why. Reported only against the
//     specific hash it failed for (ReconcileForHash), so assigning a new
//     desired policy after a failure clears the stale error back to DRIFTED
//     instead of leaving an old failure message stuck forever.
//   - IN_SYNC: actual matches desired (policy_id, version, and hash all
//     agree).
//   - DRIFTED: anything else -- including the normal, brief window between
//     an assignment and the Sentinel's next successful reconciliation.
func ReconcileState(rec Record) (status string, errMsg string) {
	desired := PolicyRef{PolicyID: rec.DesiredPolicyID, Version: rec.DesiredPolicyVersion, Hash: rec.DesiredPolicyHash}
	if desired.Empty() {
		return "", ""
	}
	// Ground truth first: if actual already matches desired, that wins over
	// any stale self-reported RECONCILING/RECONCILE_FAILED from an earlier
	// attempt against the same hash (e.g. a transient failure that
	// succeeded on retry) -- the Sentinel is not required to explicitly
	// "clear" its own prior status report for this to display correctly.
	actual := PolicyRef{PolicyID: rec.PolicyID, Version: actualVersionAsInt(rec.PolicyVersion), Hash: rec.PolicyHash}
	if actual.Equal(desired) {
		return "IN_SYNC", ""
	}
	if rec.ReconcileStatus == "RECONCILING" {
		return "RECONCILING", ""
	}
	if isReconcileFailure(rec.ReconcileStatus) && rec.ReconcileForHash == desired.Hash {
		return rec.ReconcileStatus, rec.ReconcileError
	}
	return "DRIFTED", ""
}

// Reconcile failure statuses. RECONCILE_FAILED is the general case from
// Prompt 14A; SIGNATURE_INVALID and DOWNGRADE_REJECTED (Prompt 14B) are
// deliberately distinct rather than folded into it, because they mean
// something categorically different to an operator: not "this didn't work,
// retry," but "a Sentinel refused this policy on trust grounds." Those two
// deserve to be visible as themselves in the fleet UI, not buried in an
// error string.
const (
	ReconcileFailed    = "RECONCILE_FAILED"
	SignatureInvalid   = "SIGNATURE_INVALID"
	DowngradeRejected  = "DOWNGRADE_REJECTED"
	ReconcileInProcess = "RECONCILING"
)

func isReconcileFailure(status string) bool {
	switch status {
	case ReconcileFailed, SignatureInvalid, DowngradeRejected:
		return true
	}
	return false
}

// IdentityState reports the control plane's view of a Sentinel's Fleet
// identity, computed rather than stored (the same principle Health and
// ReconcileState follow):
//
//   - REVOKED: this Sentinel's credential has been revoked by an operator. It
//     can no longer participate in Fleet. It is expected to keep enforcing
//     its last-known-good policy locally -- revocation removes a Sentinel
//     from the control plane, it does not disable local protection. See
//     progress.md's Prompt 14B handoff for the full semantics.
//   - AUTHENTICATED: an active per-Sentinel credential exists.
//   - UNAUTHENTICATED: no credential has ever been issued for this Sentinel
//     (a pre-14B or development-posture Sentinel reporting without one).
func IdentityState(rec Record) string {
	switch {
	case rec.Revoked:
		return "REVOKED"
	case rec.CredentialIssued:
		return "AUTHENTICATED"
	default:
		return "UNAUTHENTICATED"
	}
}

func actualVersionAsInt(v string) int {
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return -1 // non-numeric actual version (e.g. a local policy-pack version string) can never equal a desired int version
		}
		n = n*10 + int(c-'0')
	}
	if v == "" {
		return -1
	}
	return n
}
