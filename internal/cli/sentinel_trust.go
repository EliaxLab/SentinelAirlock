package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
	"github.com/EliaxLab/SentinelAirlock/internal/policy"
)

// Sentinel-side Fleet trust material (Prompt 14B).
//
// A Fleet-managed Sentinel keeps four small durable files under <repo>/
// .airlock/, each with one job:
//
//	fleet-credential.json  its own credential + the pinned control-plane
//	                       signing key           (0600 -- secret material)
//	fleet-policy.json      last-known-good policy content, its signature,
//	                       and the anti-downgrade high-water mark
//	fleet-outbox.json      bounded buffer of undelivered reports
//	fleet-status.json      human/CLI-readable trust status (no secrets)
//
// Everything here is off the enforcement path: these files are read at
// startup and written from the fleet goroutine. A filesystem decision never
// waits on any of them.

const (
	fleetCredentialName = "fleet-credential.json"
	fleetPolicyName     = "fleet-policy.json"
	fleetOutboxName     = "fleet-outbox.json"
	fleetStatusName     = "fleet-status.json"
)

func fleetCredentialPath(repoAbs string) string {
	return filepath.Join(repoAbs, ".airlock", fleetCredentialName)
}
func fleetPolicyLKGPath(repoAbs string) string {
	return filepath.Join(repoAbs, ".airlock", fleetPolicyName)
}
func fleetOutboxPath(repoAbs string) string {
	return filepath.Join(repoAbs, ".airlock", fleetOutboxName)
}
func fleetStatusPath(repoAbs string) string {
	return filepath.Join(repoAbs, ".airlock", fleetStatusName)
}

// fleetCredentialFile is this Sentinel's durable Fleet identity: the
// credential the control plane issued in exchange for a one-time enrollment
// token, plus the control-plane signing key pinned at that same moment.
//
// Pinning at enrollment is what makes the trust relationship meaningful: the
// enrollment token was delivered out-of-band by an operator, so the key
// advertised in that exchange is the key that operator intended. Afterwards a
// different key is refused rather than silently adopted -- an attacker who
// takes over the control plane's address cannot re-point an already-enrolled
// Sentinel at their own signing key.
type fleetCredentialFile struct {
	SentinelID       string    `json:"sentinel_id"`
	FleetURL         string    `json:"fleet_url"`
	Credential       string    `json:"credential"`
	SigningKeyID     string    `json:"signing_key_id,omitempty"`
	SigningPublicKey string    `json:"signing_public_key,omitempty"`
	EnrolledAt       time.Time `json:"enrolled_at"`
}

func loadFleetCredential(repoAbs string) (fleetCredentialFile, bool) {
	var f fleetCredentialFile
	b, err := os.ReadFile(fleetCredentialPath(repoAbs))
	if err != nil {
		return f, false
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return fleetCredentialFile{}, false
	}
	if strings.TrimSpace(f.Credential) == "" {
		return fleetCredentialFile{}, false
	}
	return f, true
}

// saveFleetCredential writes the credential file atomically at mode 0600.
// 0600 because this file holds a bearer secret: anything that can read it can
// speak to the control plane as this Sentinel.
func saveFleetCredential(repoAbs string, f fleetCredentialFile) error {
	path := fleetCredentialPath(repoAbs)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// fleetLKGFile is the durable last-known-good record of the most recently
// successfully-applied Fleet-managed policy: content, identity, the signature
// it was accepted under, and the anti-downgrade high-water mark, all in one
// file written via a single atomic rename (installFleetPolicy) so there is
// never a window where any of them could disagree with each other.
type fleetLKGFile struct {
	PolicyID  string    `json:"policy_id"`
	Version   int       `json:"version"`
	Hash      string    `json:"hash"`
	Digest    string    `json:"digest,omitempty"`
	YAML      string    `json:"yaml"`
	AppliedAt time.Time `json:"applied_at"`

	SignatureAlg string    `json:"signature_alg,omitempty"`
	Signature    string    `json:"signature,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	IssuedAt     time.Time `json:"issued_at,omitempty"`

	// MaxAccepted is the anti-downgrade state: the highest version of each
	// policy id this Sentinel has ever accepted. It lives here, in the same
	// atomically-written file as the policy itself, because the two always
	// change together -- a version is only ever recorded as accepted at the
	// moment it is actually installed.
	MaxAccepted map[string]int `json:"max_accepted_version,omitempty"`
}

// fleetLKG is the loaded, verified last-known-good state.
type fleetLKG struct {
	cfg            *policy.Config
	ref            fleet.PolicyRef
	digest         string
	maxAccepted    map[string]int
	signatureState string // VERIFIED | UNSIGNED
	signerKeyID    string
}

// loadFleetLKG returns the last-known-good Fleet-managed policy for repoAbs,
// if one has ever been successfully applied and is still trustworthy right
// now. ok=false (nothing logged) simply means "nothing to restore" for a
// Sentinel that has never reconciled.
//
// Trustworthy means re-checked, not merely present:
//
//   - the stored content is re-canonicalized and re-digested, and must match
//     the digest recorded alongside it
//   - if a signing key is pinned, the stored signature must still verify
//     against it
//
// A file that fails either check is not used. That matters because this file
// is the one thing that decides what a restarted, disconnected Sentinel
// enforces: trusting it because it merely exists on disk would make editing a
// JSON file a way to choose your own policy.
func loadFleetLKG(repoAbs string, trust fleet.TrustStore) (*fleetLKG, bool) {
	b, err := os.ReadFile(fleetPolicyLKGPath(repoAbs))
	if err != nil {
		return nil, false
	}
	var f fleetLKGFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, false
	}
	digest, short, cfg, err := fleet.ComputePolicyDigest(f.YAML)
	if err != nil || short != f.Hash {
		return nil, false
	}
	if f.Digest != "" && digest != f.Digest {
		return nil, false
	}

	state := "UNSIGNED"
	if !trust.Empty() {
		pv := fleet.PolicyVersion{
			PolicyID: f.PolicyID, Version: f.Version, Hash: f.Hash, Digest: digest, YAML: f.YAML,
			SignatureAlg: f.SignatureAlg, Signature: f.Signature, Issuer: f.Issuer, IssuedAt: f.IssuedAt,
		}
		if err := fleet.VerifyPolicyVersion(pv, trust); err != nil {
			fmt.Printf("WARN: stored Fleet policy %s v%d no longer verifies (%v); not restoring it\n", f.PolicyID, f.Version, err)
			return nil, false
		}
		state = "VERIFIED"
	}

	maxAccepted := f.MaxAccepted
	if maxAccepted == nil {
		maxAccepted = map[string]int{}
	}
	// A last-known-good policy is by definition one this Sentinel accepted,
	// so it establishes at least its own version as the floor -- even for an
	// LKG file written before anti-downgrade state existed.
	if f.PolicyID != "" && maxAccepted[f.PolicyID] < f.Version {
		maxAccepted[f.PolicyID] = f.Version
	}
	return &fleetLKG{
		cfg:            cfg,
		ref:            fleet.PolicyRef{PolicyID: f.PolicyID, Version: f.Version, Hash: f.Hash},
		digest:         digest,
		maxAccepted:    maxAccepted,
		signatureState: state,
		signerKeyID:    f.Issuer,
	}, true
}

// installFleetPolicy durably and atomically records pv as repoAbs's new
// last-known-good Fleet policy, together with the updated anti-downgrade
// high-water mark: write to a temp file in the same directory, then a single
// os.Rename over the real path. Same-directory rename is atomic on the
// filesystems Airlock targets, so a reader -- a concurrent load, or this same
// process after a crash mid-write -- only ever observes the complete old file
// or the complete new one.
func installFleetPolicy(repoAbs string, pv fleet.PolicyVersion, maxAccepted map[string]int) error {
	path := fleetPolicyLKGPath(repoAbs)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f := fleetLKGFile{
		PolicyID: pv.PolicyID, Version: pv.Version, Hash: pv.Hash, Digest: pv.Digest,
		YAML: pv.YAML, AppliedAt: time.Now().UTC(),
		SignatureAlg: pv.SignatureAlg, Signature: pv.Signature, Issuer: pv.Issuer, IssuedAt: pv.IssuedAt,
		MaxAccepted: maxAccepted,
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// fleetStatusFile is the locally-readable trust status of a Fleet-managed
// Sentinel, rewritten as things change and printed by
// `airlock sentinel --status`.
//
// It deliberately contains no secrets: the credential is represented only by
// whether one exists, and the signing key by its public key id. A Sentinel
// that can no longer reach or authenticate to its control plane still shows
// exactly what it is enforcing and why it trusts it -- which is the whole
// point of an architecture where the control plane going away does not take
// governance with it.
type fleetStatusFile struct {
	FleetURL   string `json:"fleet_url"`
	SentinelID string `json:"sentinel_id"`
	Identity   string `json:"identity"` // AUTHENTICATED | UNAUTHENTICATED | REVOKED

	// Connected is transport reachability, deliberately separate from
	// Identity: a Sentinel that cannot reach its control plane is not the
	// same as one whose credential was revoked, and collapsing the two would
	// make an outage look like a security event (and vice versa).
	Connected       bool       `json:"connected"`
	SignerKeyID     string     `json:"signer_key_id,omitempty"`
	SignatureState  string     `json:"signature_state,omitempty"` // VERIFIED | UNSIGNED | INVALID
	PolicyID        string     `json:"policy_id,omitempty"`
	PolicyVersion   int        `json:"policy_version,omitempty"`
	PolicyHash      string     `json:"policy_hash,omitempty"`
	LastReconcileAt *time.Time `json:"last_reconcile_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	BufferedReports int        `json:"buffered_reports"`
	DroppedReports  int        `json:"dropped_reports"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func saveFleetStatus(repoAbs string, st fleetStatusFile) {
	st.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	path := fleetStatusPath(repoAbs)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func loadFleetStatus(repoAbs string) (fleetStatusFile, bool) {
	var st fleetStatusFile
	b, err := os.ReadFile(fleetStatusPath(repoAbs))
	if err != nil {
		return st, false
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return fleetStatusFile{}, false
	}
	return st, true
}

// resolvePinnedPublicKey turns a --fleet-pubkey value into hex key material.
// It accepts either the hex key itself or a path to a file containing it, so
// an operator can paste what `airlock fleet init` printed or point at the
// .pub file it wrote.
func resolvePinnedPublicKey(value string) (keyID, hexKey string, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", nil
	}
	candidate := value
	if b, readErr := os.ReadFile(value); readErr == nil {
		candidate = strings.TrimSpace(string(b))
	}
	pub, err := fleet.ParsePublicKeyHex(candidate)
	if err != nil {
		return "", "", fmt.Errorf("--fleet-pubkey is neither a hex ed25519 public key nor a file containing one: %w", err)
	}
	return fleet.KeyIDFor(pub), candidate, nil
}
