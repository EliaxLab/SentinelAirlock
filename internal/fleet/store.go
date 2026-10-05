package fleet

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// MinSentinelPrefix is the shortest ID prefix Resolve accepts. `fleet list`
// displays the first 8 characters; anything shorter than this is refused so a
// typo cannot target an unintended Sentinel.
const MinSentinelPrefix = 4

// ErrSentinelNotFound is returned when an ID matches no enrolled Sentinel.
var ErrSentinelNotFound = errors.New("sentinel not found")

// AmbiguousSentinelError is returned when a prefix matches more than one
// enrolled Sentinel; Matches holds the full IDs so the operator can retry.
type AmbiguousSentinelError struct {
	Prefix  string
	Matches []string
}

func (e *AmbiguousSentinelError) Error() string {
	return fmt.Sprintf("sentinel ID %q is ambiguous; it matches %d sentinels (%s): use a longer prefix or the full ID",
		e.Prefix, len(e.Matches), strings.Join(e.Matches, ", "))
}

// Resolve maps what an operator typed to the canonical SentinelID of an
// already-enrolled Sentinel. An exact ID always wins; otherwise a prefix (at
// least MinSentinelPrefix long, e.g. the short ID `fleet list` shows) must
// match exactly one record. It never creates or modifies anything:
// enrollment is the only path that creates an identity.
func (s *Store) Resolve(idOrPrefix string) (string, error) {
	idOrPrefix = strings.TrimSpace(idOrPrefix)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.records[idOrPrefix]; ok && idOrPrefix != "" {
		return idOrPrefix, nil
	}
	if len(idOrPrefix) < MinSentinelPrefix {
		return "", ErrSentinelNotFound
	}
	var matches []string
	for id := range s.records {
		if strings.HasPrefix(id, idOrPrefix) {
			matches = append(matches, id)
		}
	}
	switch len(matches) {
	case 0:
		return "", ErrSentinelNotFound
	case 1:
		return matches[0], nil
	}
	sort.Strings(matches)
	return "", &AmbiguousSentinelError{Prefix: idOrPrefix, Matches: matches}
}

// Store is the control plane's durable inventory: a single JSON file
// guarded by an in-memory mutex, following the same plain-JSON-file
// convention already used throughout this project for local state
// (.airlock/index.json, .airlock/sentinel.json, .airlock/viewer.json) --
// see progress.md's Prompt 14 handoff for why SQLite was evaluated and not
// chosen for v0. Write volume is bounded by one heartbeat per Sentinel per
// DefaultHeartbeatInterval (not per filesystem event), so a whole-file
// rewrite per update is not a bottleneck at the fleet sizes this control
// plane targets.
type Store struct {
	mu      sync.RWMutex
	path    string
	records map[string]Record
}

// OpenStore loads path if it exists, or starts an empty, durable store that
// will create path on first write. A missing file is not an error -- it is
// simply an empty fleet.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, records: map[string]Record{}}
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
	var recs map[string]Record
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, err
	}
	if recs != nil {
		s.records = recs
	}
	return s, nil
}

// UpsertEnroll records or refreshes a Sentinel's full identity at (re)start.
// rec should be fully populated by the caller (the HTTP handler) with
// identity/actual-state fields; EnrolledAt is preserved from the first time
// this SentinelID was ever seen, overriding whatever rec.EnrolledAt was set
// to, so restarting a Sentinel does not reset "how long has this
// installation existed."
//
// Desired*/Reconcile* fields (Prompt 14A) are likewise carried over from any
// existing record rather than being wiped by an enroll: an operator may
// assign a desired policy to a Sentinel before it has ever enrolled, or
// while it is offline, and re-enrolling (which happens on every Sentinel
// restart) must not discard that assignment -- the enroll request has no
// opinion on desired state at all, so it must never be able to clear it.
func (s *Store) UpsertEnroll(rec Record) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[rec.SentinelID]; ok {
		if !existing.EnrolledAt.IsZero() {
			rec.EnrolledAt = existing.EnrolledAt
		}
		rec.DesiredPolicyID = existing.DesiredPolicyID
		rec.DesiredPolicyVersion = existing.DesiredPolicyVersion
		rec.DesiredPolicyHash = existing.DesiredPolicyHash
		rec.DesiredPolicyDigest = existing.DesiredPolicyDigest
		rec.RollbackGrant = existing.RollbackGrant
		rec.ReconcileStatus = existing.ReconcileStatus
		rec.ReconcileError = existing.ReconcileError
		rec.ReconcileForHash = existing.ReconcileForHash
		rec.LastReconcileAt = existing.LastReconcileAt
	}
	s.records[rec.SentinelID] = rec
	if err := s.saveLocked(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// UpsertHeartbeat applies apply to the existing record for id, or to a new,
// mostly-empty record if id has never been seen (e.g. the control plane's
// state was reset, or a heartbeat arrives before its own enrollment call
// completes). This keeps a Sentinel visible in inventory -- even if
// incompletely described until its next successful enrollment -- rather
// than dropping heartbeats for an unrecognized identity.
func (s *Store) UpsertHeartbeat(id string, apply func(*Record)) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.records[id]
	if rec.SentinelID == "" {
		rec.SentinelID = id
	}
	apply(&rec)
	s.records[id] = rec
	if err := s.saveLocked(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// AssignPolicy sets the desired policy ref for an already-enrolled sentinelID
// (Prompt 14A). It requires an exact, existing ID and returns
// ErrSentinelNotFound otherwise: assignment must never create an identity (a
// phantom OFFLINE/DRIFTED record), so callers resolve what the operator typed
// with Resolve first. Enrollment stays the one explicit identity-creation
// path, and a desired policy assigned to an enrolled Sentinel survives
// re-enrollment. Assigning does not touch ReconcileStatus/Error: a fresh
// assignment naturally reads as DRIFTED (via ReconcileState) until the
// Sentinel next reconciles, which is the correct, honest transition.
// digest is the full canonical digest of the assigned version and grant is an
// optional signed downgrade authorization (Prompt 14B); grant is cleared on
// every assignment that does not supply one, so a rollback authorization can
// never linger and silently authorize a later, unrelated downgrade.
func (s *Store) AssignPolicy(sentinelID string, ref PolicyRef, digest string, grant *RollbackGrant) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[sentinelID]
	if !ok {
		return Record{}, ErrSentinelNotFound
	}
	rec.DesiredPolicyID = ref.PolicyID
	rec.DesiredPolicyVersion = ref.Version
	rec.DesiredPolicyHash = ref.Hash
	rec.DesiredPolicyDigest = digest
	rec.RollbackGrant = grant
	s.records[sentinelID] = rec
	if err := s.saveLocked(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Get returns the record for id, if known.
func (s *Store) Get(id string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[id]
	return rec, ok
}

// List returns every known Sentinel record, sorted by SentinelID for stable
// output. Offline Sentinels are included -- List never expires entries;
// only Health() (computed by the caller against the current time) reports
// staleness.
func (s *Store) List() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SentinelID < out[j].SentinelID })
	return out
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}
