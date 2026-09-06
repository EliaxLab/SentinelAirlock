package fleet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// PolicyStore is the control plane's durable record of centrally-managed
// policies: every version of every named policy, immutable once created.
// Same plain-JSON-file-with-mutex convention as Store (Sentinel inventory) --
// see progress.md's Prompt 14 handoff for why that convention was chosen
// over a database, which applies identically here.
type PolicyStore struct {
	mu   sync.RWMutex
	path string
	// signer, when set, signs every version at creation time (Prompt 14B).
	// Signing happens here -- at the one point where a version's content and
	// identity are both finalized -- rather than at distribution time, so a
	// stored version can never be served with a signature that was computed
	// over anything but exactly what is stored.
	signer   *SigningKey
	Policies map[string][]PolicyVersion // policy_id -> versions, ascending by Version
}

// SetSigner attaches the control plane's policy-signing key. A PolicyStore
// with no signer still works and produces unsigned versions -- that is the
// pre-14B behavior, retained so an existing deployment does not break -- but
// a Sentinel that has pinned a signing key will refuse them. See
// VerifyPolicyVersion and internal/cli/sentinel.go's verifyFleetPolicy.
func (s *PolicyStore) SetSigner(k *SigningKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signer = k
}

// SignerKeyID returns the key id versions are signed with, or "" if this
// control plane does not sign policy.
func (s *PolicyStore) SignerKeyID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.signer == nil {
		return ""
	}
	return s.signer.KeyID
}

// OpenPolicyStore loads path if it exists, or starts an empty, durable store
// that will create path on first write.
func OpenPolicyStore(path string) (*PolicyStore, error) {
	s := &PolicyStore{path: path, Policies: map[string][]PolicyVersion{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return s, nil
	}
	var policies map[string][]PolicyVersion
	if err := json.Unmarshal(b, &policies); err != nil {
		return nil, err
	}
	if policies != nil {
		s.Policies = policies
	}
	return s, nil
}

// Create makes the first version (version 1) of a new named policy. It
// fails if policyID already exists -- use AddVersion to extend an existing
// policy instead, so "create" can never silently overwrite history.
func (s *PolicyStore) Create(policyID, description, yamlContent string) (PolicyVersion, error) {
	digest, hash, _, err := ComputePolicyDigest(yamlContent)
	if err != nil {
		return PolicyVersion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Policies[policyID]; exists {
		return PolicyVersion{}, fmt.Errorf("policy %q already exists; use AddVersion to add a new version", policyID)
	}
	v := PolicyVersion{
		PolicyID: policyID, Version: 1, Hash: hash, Digest: digest, YAML: yamlContent,
		Description: description, CreatedAt: time.Now().UTC(),
	}
	if err := s.signLocked(&v); err != nil {
		return PolicyVersion{}, err
	}
	s.Policies[policyID] = []PolicyVersion{v}
	if err := s.saveLocked(); err != nil {
		return PolicyVersion{}, err
	}
	return v, nil
}

// AddVersion appends a new, immutable version to an existing policy. The
// previous version's content is never mutated -- it remains addressable by
// its own version number (see GetVersion) so "what exactly did v4 contain"
// is always answerable, even after v5 exists.
func (s *PolicyStore) AddVersion(policyID, description, yamlContent string) (PolicyVersion, error) {
	digest, hash, _, err := ComputePolicyDigest(yamlContent)
	if err != nil {
		return PolicyVersion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, exists := s.Policies[policyID]
	if !exists || len(versions) == 0 {
		return PolicyVersion{}, fmt.Errorf("policy %q does not exist; use Create to make a new policy", policyID)
	}
	next := versions[len(versions)-1].Version + 1
	v := PolicyVersion{
		PolicyID: policyID, Version: next, Hash: hash, Digest: digest, YAML: yamlContent,
		Description: description, CreatedAt: time.Now().UTC(),
	}
	if err := s.signLocked(&v); err != nil {
		return PolicyVersion{}, err
	}
	s.Policies[policyID] = append(versions, v)
	if err := s.saveLocked(); err != nil {
		return PolicyVersion{}, err
	}
	return v, nil
}

// signLocked signs v in place if a signer is configured. Called with s.mu
// held, from Create/AddVersion, before the version is ever stored -- so a
// signing failure aborts creation rather than storing an unsigned version a
// Sentinel would later refuse.
func (s *PolicyStore) signLocked(v *PolicyVersion) error {
	if s.signer == nil {
		return nil
	}
	return s.signer.SignPolicyVersion(v, time.Now().UTC())
}

// GetLatest returns the highest version of policyID.
func (s *PolicyStore) GetLatest(policyID string) (PolicyVersion, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := s.Policies[policyID]
	if len(versions) == 0 {
		return PolicyVersion{}, false
	}
	return versions[len(versions)-1], true
}

// GetVersion returns a specific historical (or current) version of policyID.
func (s *PolicyStore) GetVersion(policyID string, version int) (PolicyVersion, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.Policies[policyID] {
		if v.Version == version {
			return v, true
		}
	}
	return PolicyVersion{}, false
}

// AllVersions returns every version of policyID, ascending.
func (s *PolicyStore) AllVersions(policyID string) ([]PolicyVersion, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.Policies[policyID]
	if !ok {
		return nil, false
	}
	out := make([]PolicyVersion, len(versions))
	copy(out, versions)
	return out, true
}

// ListLatest returns the latest version of every known policy, sorted by
// PolicyID, for an inventory-style listing.
func (s *PolicyStore) ListLatest() []PolicyVersion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PolicyVersion, 0, len(s.Policies))
	for _, versions := range s.Policies {
		if len(versions) > 0 {
			out = append(out, versions[len(versions)-1])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PolicyID < out[j].PolicyID })
	return out
}

func (s *PolicyStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.Policies, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}
