package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sentinel authentication (Prompt 14B).
//
// Two directions of trust are modeled separately. This file is the control
// plane's half: "this request really comes from enrolled Sentinel X." The
// other half -- "this policy really came from my control plane" -- is
// signing.go, and neither substitutes for the other.
//
// The mechanism:
//
//	operator creates a one-time enrollment token   (out-of-band, short-lived)
//	        v
//	Sentinel enrolls presenting that token
//	        v
//	control plane issues a durable per-Sentinel credential
//	        v
//	the enrollment token is consumed and can never be used again
//	        v
//	every later heartbeat/fetch/report authenticates with the credential
//
// The credential is an opaque high-entropy secret. Crucially, the control
// plane resolves *which* Sentinel a request comes from by looking up that
// credential -- never by reading a sentinel_id field out of the request body.
// A request claiming sentinel_id=sentinel-437 is only ever treated as
// sentinel-437 if the credential it presented is the one issued to
// sentinel-437. See Server.authenticate and requireSentinel.

const (
	// DefaultEnrollTokenTTL bounds how long an unused enrollment token stays
	// usable. Enrollment tokens are meant to be created, handed to one
	// machine, and consumed within minutes; a token that lingers for days is
	// a credential nobody is tracking.
	DefaultEnrollTokenTTL = time.Hour

	// credentialEntropyBytes is the size of the random secret behind a
	// Sentinel credential and an enrollment token. 32 bytes (256 bits) from
	// crypto/rand is far beyond guessing range and matches the strength of
	// the Ed25519 keys used elsewhere in this package.
	credentialEntropyBytes = 32

	// enrollTokenPrefix / credentialPrefix make a leaked secret identifiable
	// on sight (in a paste, a log someone shouldn't have written, a
	// screenshot) so it can be revoked without first having to work out what
	// kind of string it is.
	enrollTokenPrefix = "airlock_et_"
	credentialPrefix  = "airlock_sc_"
)

var (
	// ErrEnrollTokenInvalid covers every unusable-token case (unknown, used,
	// expired, revoked). The distinction matters to an operator reading the
	// server's own records, not to the client presenting it -- the API
	// deliberately answers all four the same way so a caller cannot probe
	// which tokens exist.
	ErrEnrollTokenInvalid = errors.New("enrollment token is not valid")

	// ErrSentinelAlreadyEnrolled means an enrollment token was presented for
	// a sentinel id that already holds an active credential. Re-enrolling an
	// existing identity requires that identity's own credential (which a
	// restarted Sentinel already has on disk); a fresh enrollment token is
	// not a way to take over someone else's identity.
	ErrSentinelAlreadyEnrolled = errors.New("sentinel already has an active credential; revoke it before re-enrolling with a token")

	// ErrCredentialRevoked means a valid-looking credential has been revoked.
	ErrCredentialRevoked = errors.New("sentinel credential has been revoked")

	// ErrUnauthenticated means no usable credential or operator token was
	// presented.
	ErrUnauthenticated = errors.New("unauthenticated")
)

// EnrollTokenRecord is the control plane's record of a one-time enrollment
// token. The token itself is never stored -- only its SHA-256 -- so a leak of
// the auth store does not hand an attacker usable enrollment tokens. The
// plaintext exists exactly once, in the response to the operator who created
// it.
type EnrollTokenRecord struct {
	ID          string     `json:"id"`
	TokenHash   string     `json:"token_hash"`
	Description string     `json:"description,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	UsedBy      string     `json:"used_by,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// State describes a token's usability at now, for operator listings.
func (t EnrollTokenRecord) State(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "REVOKED"
	case t.UsedAt != nil:
		return "USED"
	case now.After(t.ExpiresAt):
		return "EXPIRED"
	default:
		return "VALID"
	}
}

// CredentialRecord is a durable per-Sentinel credential. Like enrollment
// tokens, only the hash is persisted; the plaintext is returned once, at
// enrollment, and lives thereafter only in the Sentinel's own 0600 credential
// file.
type CredentialRecord struct {
	SentinelID     string     `json:"sentinel_id"`
	CredentialHash string     `json:"credential_hash"`
	CreatedAt      time.Time  `json:"created_at"`
	EnrollTokenID  string     `json:"enroll_token_id,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevokedReason  string     `json:"revoked_reason,omitempty"`
}

// Active reports whether this credential can still authenticate.
func (c *CredentialRecord) Active() bool { return c != nil && c.RevokedAt == nil }

type authData struct {
	EnrollTokens map[string]*EnrollTokenRecord `json:"enroll_tokens"` // keyed by token id
	Credentials  map[string]*CredentialRecord  `json:"credentials"`   // keyed by credential hash
}

// AuthStore holds enrollment tokens and Sentinel credentials, in the same
// plain-JSON-file-with-mutex style as Store and PolicyStore. It is written
// 0600 rather than 0644: unlike the inventory and policy stores, every value
// in it is security-sensitive material.
type AuthStore struct {
	mu   sync.RWMutex
	path string
	data authData
}

// OpenAuthStore loads path if it exists, or starts an empty store that
// creates path on first write.
func OpenAuthStore(path string) (*AuthStore, error) {
	s := &AuthStore{path: path, data: authData{
		EnrollTokens: map[string]*EnrollTokenRecord{},
		Credentials:  map[string]*CredentialRecord{},
	}}
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
	var data authData
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}
	if data.EnrollTokens != nil {
		s.data.EnrollTokens = data.EnrollTokens
	}
	if data.Credentials != nil {
		s.data.Credentials = data.Credentials
	}
	return s, nil
}

// hashSecret is the one place a presented secret becomes a stored value.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

func randomSecret(prefix string) (string, error) {
	buf := make([]byte, credentialEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buf), nil
}

// CreateEnrollToken mints a one-time enrollment token. The plaintext is
// returned to the caller and never stored anywhere; only its hash is
// persisted. ttl <= 0 means DefaultEnrollTokenTTL.
func (s *AuthStore) CreateEnrollToken(description string, ttl time.Duration) (plaintext string, rec EnrollTokenRecord, err error) {
	if ttl <= 0 {
		ttl = DefaultEnrollTokenTTL
	}
	plaintext, err = randomSecret(enrollTokenPrefix)
	if err != nil {
		return "", EnrollTokenRecord{}, err
	}
	idBuf := make([]byte, 8)
	if _, err := rand.Read(idBuf); err != nil {
		return "", EnrollTokenRecord{}, err
	}
	now := time.Now().UTC()
	rec = EnrollTokenRecord{
		ID:          hex.EncodeToString(idBuf),
		TokenHash:   hashSecret(plaintext),
		Description: description,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.EnrollTokens[rec.ID] = &rec
	if err := s.saveLocked(); err != nil {
		return "", EnrollTokenRecord{}, err
	}
	return plaintext, rec, nil
}

// RevokeEnrollToken makes an unused token permanently unusable.
func (s *AuthStore) RevokeEnrollToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data.EnrollTokens[id]
	if !ok {
		return fmt.Errorf("enrollment token %s does not exist", id)
	}
	if rec.RevokedAt == nil {
		now := time.Now().UTC()
		rec.RevokedAt = &now
	}
	return s.saveLocked()
}

// ListEnrollTokens returns every enrollment token record (hashes only, never
// plaintext), newest first.
func (s *AuthStore) ListEnrollTokens() []EnrollTokenRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]EnrollTokenRecord, 0, len(s.data.EnrollTokens))
	for _, t := range s.data.EnrollTokens {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ConsumeEnrollToken validates token and, if it is usable, atomically marks
// it used and issues a durable credential for sentinelID.
//
// "Atomically" matters: validation and consumption happen under one lock, so
// two Sentinels racing on the same one-time token cannot both be issued a
// credential -- exactly one wins and the other sees ErrEnrollTokenInvalid.
func (s *AuthStore) ConsumeEnrollToken(token, sentinelID string) (credential string, rec CredentialRecord, err error) {
	hash := hashSecret(token)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	var match *EnrollTokenRecord
	for _, t := range s.data.EnrollTokens {
		// Constant-time comparison: these are hashes of secrets, and the
		// habit of never comparing secret-derived material with == is worth
		// keeping even where the timing channel is narrow.
		if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(hash)) == 1 {
			match = t
			break
		}
	}
	if match == nil || match.State(now) != "VALID" {
		return "", CredentialRecord{}, ErrEnrollTokenInvalid
	}
	// An enrollment token authorizes bringing a *new* identity online. It is
	// not a way to seize an identity that already has a working credential --
	// otherwise anyone an operator ever hands a token to could claim to be an
	// existing Sentinel and inherit its policy assignment.
	if existing := s.credentialForLocked(sentinelID); existing.Active() {
		return "", CredentialRecord{}, ErrSentinelAlreadyEnrolled
	}

	credential, err = randomSecret(credentialPrefix)
	if err != nil {
		return "", CredentialRecord{}, err
	}
	rec = CredentialRecord{
		SentinelID:     sentinelID,
		CredentialHash: hashSecret(credential),
		CreatedAt:      now,
		EnrollTokenID:  match.ID,
	}
	// Replace any revoked credential for this identity, so a revoked-then-
	// re-enrolled Sentinel has exactly one credential rather than an
	// accumulating pile of dead ones.
	for h, c := range s.data.Credentials {
		if c.SentinelID == sentinelID {
			delete(s.data.Credentials, h)
		}
	}
	s.data.Credentials[rec.CredentialHash] = &rec
	match.UsedAt = &now
	match.UsedBy = sentinelID
	if err := s.saveLocked(); err != nil {
		return "", CredentialRecord{}, err
	}
	return credential, rec, nil
}

// Authenticate resolves a presented credential to the Sentinel it was issued
// to. It returns ErrCredentialRevoked (distinct from ErrUnauthenticated) for
// a known-but-revoked credential, so the control plane can tell a Sentinel
// specifically that its identity was revoked -- which is what lets the
// Sentinel report that state locally instead of only seeing a generic
// rejection.
func (s *AuthStore) Authenticate(credential string) (sentinelID string, err error) {
	if strings.TrimSpace(credential) == "" {
		return "", ErrUnauthenticated
	}
	hash := hashSecret(credential)
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.data.Credentials[hash]
	if !ok {
		return "", ErrUnauthenticated
	}
	if !rec.Active() {
		return rec.SentinelID, ErrCredentialRevoked
	}
	return rec.SentinelID, nil
}

// CredentialFor returns the credential record for sentinelID, if any.
func (s *AuthStore) CredentialFor(sentinelID string) (CredentialRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec := s.credentialForLocked(sentinelID)
	if rec == nil {
		return CredentialRecord{}, false
	}
	return *rec, true
}

func (s *AuthStore) credentialForLocked(sentinelID string) *CredentialRecord {
	for _, c := range s.data.Credentials {
		if c.SentinelID == sentinelID {
			return c
		}
	}
	return nil
}

// RevokeSentinel revokes sentinelID's credential. After this, that credential
// can no longer authenticate to the control plane.
//
// It deliberately does NOT tell the Sentinel to stop enforcing anything:
// revoking a credential must not double as a remote off-switch for local
// protection, or central revocation becomes an attack on the thing Airlock
// exists to do. See progress.md's Prompt 14B handoff for the full semantics.
func (s *AuthStore) RevokeSentinel(sentinelID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.credentialForLocked(sentinelID)
	if rec == nil {
		return fmt.Errorf("sentinel %s has no credential to revoke", sentinelID)
	}
	if rec.RevokedAt == nil {
		now := time.Now().UTC()
		rec.RevokedAt = &now
		rec.RevokedReason = reason
	}
	return s.saveLocked()
}

// HasCredentials reports whether any credential has ever been issued.
func (s *AuthStore) HasCredentials() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Credentials) > 0
}

func (s *AuthStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	// 0600: every value in this file is security-sensitive (secret hashes and
	// their bindings), unlike the inventory/policy stores next to it.
	return os.WriteFile(s.path, b, 0o600)
}

// PrincipalType distinguishes who is making a request.
type PrincipalType string

const (
	// PrincipalAnonymous presented nothing usable.
	PrincipalAnonymous PrincipalType = "anonymous"
	// PrincipalOperator presented the control plane's operator token (or the
	// control plane has no operator token configured -- the documented
	// development posture).
	PrincipalOperator PrincipalType = "operator"
	// PrincipalSentinel presented a valid per-Sentinel credential. SentinelID
	// is then the identity the credential was issued to -- resolved from the
	// credential, never read from the request body.
	PrincipalSentinel PrincipalType = "sentinel"
)

// Principal is the authenticated identity behind one request. It replaces
// Prompt 14's authorized(req) bool: a plain boolean cannot express "which
// Sentinel is this," and without that, any valid credential would be able to
// act as any sentinel_id -- precisely the impersonation this release exists
// to close.
type Principal struct {
	Type       PrincipalType
	SentinelID string
	Revoked    bool
}

// IsOperator reports whether this principal may perform operator actions
// (managing policies, assignments, tokens, revocation).
func (p Principal) IsOperator() bool { return p.Type == PrincipalOperator }

// CanActAs reports whether this principal is allowed to submit data on behalf
// of sentinelID. Only the Sentinel itself can -- an operator credential is
// for managing the fleet, not for impersonating members of it.
func (p Principal) CanActAs(sentinelID string) bool {
	return p.Type == PrincipalSentinel && p.SentinelID != "" && p.SentinelID == sentinelID
}
