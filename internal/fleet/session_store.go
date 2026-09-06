package fleet

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// SessionStore is the control plane's durable governance-session history:
// one JSON file guarded by a mutex, following the same one-store-per-concern
// convention as Store, PolicyStore, AuthStore, and AlertStore. Adding it
// required no migration of any existing fleet.json, and future stores should
// be added the same way rather than by widening an existing schema.
type SessionStore struct {
	mu        sync.RWMutex
	path      string
	retention RetentionPolicy
	sessions  map[string]FleetSession // session_id -> session
}

// ErrSessionOwnedByAnotherSentinel is returned when a Sentinel tries to
// mutate a session that belongs to a different Sentinel. This is the
// server-side half of session ownership: a session belongs to exactly one
// Sentinel for its whole life, and no authenticated identity can reach across
// into another's history.
var ErrSessionOwnedByAnotherSentinel = errors.New("session belongs to a different sentinel")

// OpenSessionStore loads path if it exists, or starts an empty store that
// creates path on first write. A missing file is not an error -- it is simply
// a fleet with no recorded history yet.
func OpenSessionStore(path string, retention RetentionPolicy) (*SessionStore, error) {
	s := &SessionStore{path: path, retention: retention, sessions: map[string]FleetSession{}}
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
	var sessions map[string]FleetSession
	if err := json.Unmarshal(b, &sessions); err != nil {
		return nil, err
	}
	if sessions != nil {
		s.sessions = sessions
	}
	return s, nil
}

// Retention returns the configured metadata retention policy.
func (s *SessionStore) Retention() RetentionPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.retention
}

// SessionUpdate is one Sentinel's report about its own current session. It
// carries no ownership claim of its own: the caller supplies the
// AUTHENTICATED sentinel id separately (see Upsert), so a value in a JSON
// body can never decide whose history gets written.
type SessionUpdate struct {
	SessionID       string
	MachineID       string
	RepoPath        string
	Hostname        string
	SentinelVersion string
	StartedAt       time.Time
	PolicyID        string
	PolicyVersion   string
	PolicyHash      string
	SignatureState  string
	SignerKeyID     string

	AllowCount        int
	DenyCount         int
	RevertedCount     int
	RevertFailedCount int
	LastEventAt       *time.Time
}

// Upsert creates or updates sentinelID's record of one session.
//
// sentinelID is the authenticated principal, and it is checked against any
// existing row: a session that already belongs to another Sentinel is refused
// outright rather than silently reassigned. Combined with the handler-level
// requireSentinel gate, that gives the invariant "authenticated Sentinel A
// cannot modify Sentinel B's session history" two independent enforcement
// points.
//
// The operation is idempotent: replaying the same update produces the same
// stored row (StartedAt and CreatedAt are sticky from first write), so a
// retried or duplicated delivery never forks history.
func (s *SessionStore) Upsert(sentinelID string, u SessionUpdate, now time.Time) (FleetSession, error) {
	if sentinelID == "" || u.SessionID == "" {
		return FleetSession{}, errors.New("sentinel_id and session_id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, existed := s.sessions[u.SessionID]
	if existed && sess.SentinelID != "" && sess.SentinelID != sentinelID {
		return FleetSession{}, ErrSessionOwnedByAnotherSentinel
	}
	if !existed {
		sess = FleetSession{
			SessionID:  u.SessionID,
			SentinelID: sentinelID,
			CreatedAt:  now,
		}
		// StartedAt is sticky from the first thing that established this
		// session. A later heartbeat that omits it must never blank it.
		sess.StartedAt = u.StartedAt
		if sess.StartedAt.IsZero() {
			sess.StartedAt = now
		}
	}
	sess.SentinelID = sentinelID
	if u.MachineID != "" {
		sess.MachineID = u.MachineID
	}
	if u.RepoPath != "" {
		sess.RepoPath = u.RepoPath
	}
	if u.Hostname != "" {
		sess.Hostname = u.Hostname
	}
	if u.SentinelVersion != "" {
		sess.SentinelVersion = u.SentinelVersion
	}
	// Policy/trust state is recorded as THIS session reported it and is never
	// joined against the Sentinel's current desired policy -- that is what
	// keeps an old session's history stable after later policy changes.
	if u.PolicyID != "" {
		sess.PolicyID = u.PolicyID
	}
	if u.PolicyVersion != "" {
		sess.PolicyVersion = u.PolicyVersion
	}
	if u.PolicyHash != "" {
		sess.PolicyHash = u.PolicyHash
	}
	if u.SignatureState != "" {
		sess.SignatureState = u.SignatureState
	}
	if u.SignerKeyID != "" {
		sess.SignerKeyID = u.SignerKeyID
	}
	sess.AllowCount = u.AllowCount
	sess.DenyCount = u.DenyCount
	sess.RevertedCount = u.RevertedCount
	sess.RevertFailedCount = u.RevertFailedCount
	if u.LastEventAt != nil {
		sess.LastEventAt = u.LastEventAt
	}
	sess.LastSeenAt = now
	sess.UpdatedAt = now

	s.sessions[u.SessionID] = sess
	s.pruneLocked(now, sentinelID, u.SessionID)
	if err := s.saveLocked(); err != nil {
		return FleetSession{}, err
	}
	return sess, nil
}

// MarkStopped records a clean shutdown for a session.
//
// First write wins: a stop that arrives twice (a live final heartbeat plus
// the buffered copy a later session flushes) records one stopped_at, not two
// different ones. StoppedAt is only ever set here, from an actual report --
// nothing infers it.
func (s *SessionStore) MarkStopped(sentinelID, sessionID string, stoppedAt, now time.Time) (FleetSession, error) {
	if sentinelID == "" || sessionID == "" {
		return FleetSession{}, errors.New("sentinel_id and session_id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		// A stop for a session we never recorded (history sync was off while
		// it ran, or retention already aged it out). Nothing to correct, and
		// inventing a row from a stop notice alone would manufacture a
		// session whose actual governance activity we never saw.
		return FleetSession{}, nil
	}
	if sess.SentinelID != "" && sess.SentinelID != sentinelID {
		return FleetSession{}, ErrSessionOwnedByAnotherSentinel
	}
	if sess.StoppedAt == nil {
		when := stoppedAt
		if when.IsZero() {
			when = now
		}
		sess.StoppedAt = &when
		sess.UpdatedAt = now
		if sess.LastSeenAt.Before(when) {
			sess.LastSeenAt = when
		}
		s.sessions[sessionID] = sess
		if err := s.saveLocked(); err != nil {
			return FleetSession{}, err
		}
	}
	return sess, nil
}

// Get returns one session by id.
func (s *SessionStore) Get(sessionID string) (FleetSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	return sess, ok
}

// ForSentinel returns a Sentinel's retained sessions, newest first.
func (s *SessionStore) ForSentinel(sentinelID string) []FleetSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []FleetSession{}
	for _, sess := range s.sessions {
		if sess.SentinelID == sentinelID {
			out = append(out, sess)
		}
	}
	sortSessionsNewestFirst(out)
	return out
}

// List returns every retained session, newest first.
func (s *SessionStore) List() []FleetSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FleetSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	sortSessionsNewestFirst(out)
	return out
}

// sortSessionsNewestFirst orders by start time, with session id as a
// deterministic tie-break so output is stable when timestamps collide (which
// they can, at test speed).
func sortSessionsNewestFirst(out []FleetSession) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].SessionID > out[j].SessionID
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})
}

// Prune applies the retention policy across every Sentinel. protectedByOwner
// maps sentinel id -> the session id that must never be removed (its current
// one), so retention can never delete the session an operator is actively
// watching.
func (s *SessionStore) Prune(now time.Time, protectedByOwner map[string]string) (removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owners := map[string]struct{}{}
	for _, sess := range s.sessions {
		owners[sess.SentinelID] = struct{}{}
	}
	for owner := range owners {
		removed += s.pruneLocked(now, owner, protectedByOwner[owner])
	}
	if removed > 0 {
		if err := s.saveLocked(); err != nil {
			return 0, err
		}
	}
	return removed, nil
}

// pruneLocked enforces retention for one Sentinel. protectedSessionID is
// never removed regardless of age or count.
//
// Only Fleet's own metadata rows are affected. There is deliberately no code
// path from here to a Sentinel's machine: local .airlock/runs/ evidence,
// last-known-good policy, credentials, and durable identity are all untouched
// and untouchable by retention.
func (s *SessionStore) pruneLocked(now time.Time, sentinelID, protectedSessionID string) int {
	if !s.retention.Enabled || sentinelID == "" {
		return 0
	}
	owned := []FleetSession{}
	for _, sess := range s.sessions {
		if sess.SentinelID == sentinelID {
			owned = append(owned, sess)
		}
	}
	sortSessionsNewestFirst(owned)

	removed := 0
	remove := func(sess FleetSession) bool {
		if sess.SessionID == protectedSessionID {
			return false
		}
		delete(s.sessions, sess.SessionID)
		removed++
		return true
	}

	if s.retention.MaxAge > 0 {
		for _, sess := range owned {
			ref := sess.LastSeenAt
			if ref.IsZero() {
				ref = sess.StartedAt
			}
			if !ref.IsZero() && now.Sub(ref) > s.retention.MaxAge {
				remove(sess)
			}
		}
	}
	if s.retention.MaxSessionsPerSentinel > 0 {
		kept := 0
		for _, sess := range owned {
			if _, still := s.sessions[sess.SessionID]; !still {
				continue // already aged out above
			}
			kept++
			if kept > s.retention.MaxSessionsPerSentinel {
				remove(sess)
			}
		}
	}
	return removed
}

func (s *SessionStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.sessions, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}
