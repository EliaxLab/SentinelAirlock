package fleet

import "time"

// Fleet governance session history (Prompt 14C).
//
// This is GOVERNANCE SESSION HISTORY -- the record that a Sentinel monitoring
// session existed, when it ran, what policy it actually enforced, and what
// governance activity it observed. It is emphatically NOT conversational or
// model memory of any kind: no prompts, no agent messages, no reasoning, no
// conversation identifiers, and no file contents ever enter these types. The
// word "context" is deliberately absent from this package for that reason.
//
// The identity hierarchy from Prompt 14 is what makes history meaningful, and
// 14C preserves it exactly:
//
//	machine_id            one machine
//	  sentinel_id         one durable Sentinel governing one repository
//	    session_id        one monitoring process lifetime  <- history is here
//
// Restarting a Sentinel mints a new session_id, keeps the same sentinel_id,
// and must never erase what earlier sessions recorded.
//
// Authoritative raw evidence stays on the Sentinel's own machine under
// <repo>/.airlock/runs/<session-id>/. Fleet keeps only the metadata needed to
// know that a session existed and what its governance state was -- see
// EvidenceRef for how that boundary is represented rather than blurred.

const (
	// DefaultMaxSessionsPerSentinel bounds retained history per Sentinel.
	// 100 sessions is roughly a quarter of a year of daily restarts -- deep
	// enough to answer "what was this machine enforcing last month," shallow
	// enough that the metadata store stays a small JSON file.
	DefaultMaxSessionsPerSentinel = 100

	// DefaultMaxSessionAge bounds retained history by time, so a Sentinel
	// that restarts constantly and one that restarts rarely both age out.
	DefaultMaxSessionAge = 90 * 24 * time.Hour
)

// Session lifecycle states. All three are COMPUTED from stored facts (see
// SessionStatus), never stored as a standing flag -- the same
// "compute, don't trust" principle Health, ReconcileState, and IdentityState
// already follow.
const (
	// SessionActive: this is the Sentinel's current session and its heartbeat
	// is fresh.
	SessionActive = "ACTIVE"

	// SessionStopped: the Sentinel told us this session ended. Only ever set
	// from an actual stop report -- never inferred.
	SessionStopped = "STOPPED"

	// SessionInterrupted: the session stopped being heard from without ever
	// reporting a clean stop. This covers a killed process, a crashed
	// machine, a superseded session whose stop never arrived, and a Sentinel
	// whose Fleet credential was revoked mid-session.
	//
	// Note carefully what this does NOT mean: it does not mean local
	// governance stopped. Fleet only knows it stopped hearing. A revoked or
	// network-partitioned Sentinel is still governing its repository. UI and
	// CLI wording must preserve that distinction.
	SessionInterrupted = "INTERRUPTED"
)

// EvidenceRef is a logical pointer to where a session's authoritative
// evidence actually lives. It is deliberately NOT a path.
//
// A control plane cannot open /Users/alice/project/.airlock/runs/<id>/ -- that
// directory is on someone else's laptop. Presenting a machine-local path as
// though Fleet could follow it would be a lie the UI then has to keep telling,
// so the reference carries only what is true anywhere: the evidence is local
// to the Sentinel, and this is the session id to look it up by (with
// `airlock inspect/replay/verify <session-id>` on that machine).
type EvidenceRef struct {
	// Location is "LOCAL" in this release, and is a field rather than a
	// constant so a future release that genuinely does centralize evidence
	// has somewhere honest to say so.
	Location string `json:"location"`

	// Kind names the evidence format so a reader knows what tooling applies.
	Kind string `json:"kind"`

	// SessionID is the lookup key on the owning machine.
	SessionID string `json:"session_id"`
}

// LocalEvidenceRef builds the reference for evidence that lives on the
// Sentinel's own machine -- the only kind this release produces.
func LocalEvidenceRef(sessionID string) EvidenceRef {
	return EvidenceRef{Location: "LOCAL", Kind: "airlock-session", SessionID: sessionID}
}

// FleetSession is Fleet's durable metadata record of one Sentinel monitoring
// session.
//
// Every policy/trust field here describes what THIS session actually reported
// enforcing, captured as it ran. Nothing in this struct is ever recomputed
// against the Sentinel's current desired policy: if a Sentinel later moves to
// v13, the session that ran v10 must still say v10 forever. History that
// changes underneath an operator is worse than no history.
type FleetSession struct {
	SessionID  string `json:"session_id"`
	SentinelID string `json:"sentinel_id"`
	MachineID  string `json:"machine_id,omitempty"`

	// RepoPath is the governed repository as the Sentinel reported it, kept
	// for display and correlation only. It is a label, not something Fleet
	// can open -- see EvidenceRef.
	RepoPath        string `json:"repo_path,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	SentinelVersion string `json:"sentinel_version,omitempty"`

	StartedAt  time.Time `json:"started_at"`
	LastSeenAt time.Time `json:"last_seen_at"`

	// StoppedAt is set ONLY from an actual stop report. A session that
	// vanished without one keeps a nil StoppedAt forever: fabricating a
	// timestamp for a process that never reported stopping would turn a crash
	// into a clean shutdown in the record, which is precisely the kind of
	// quiet inaccuracy a governance audit trail cannot afford.
	StoppedAt *time.Time `json:"stopped_at,omitempty"`

	// Policy state AS THIS SESSION REPORTED IT. Immutable history.
	PolicyID       string `json:"policy_id,omitempty"`
	PolicyVersion  string `json:"policy_version,omitempty"`
	PolicyHash     string `json:"policy_hash,omitempty"`
	SignatureState string `json:"signature_state,omitempty"`
	SignerKeyID    string `json:"signer_key_id,omitempty"`

	// Governance counters, SESSION-SCOPED. Sentinel-level totals are derived
	// by summing sessions (see SentinelTotals), never maintained as a second
	// independently-mutable counter that could drift from its own inputs.
	AllowCount        int        `json:"allow_count"`
	DenyCount         int        `json:"deny_count"`
	RevertedCount     int        `json:"reverted_count"`
	RevertFailedCount int        `json:"revert_failed_count"`
	LastEventAt       *time.Time `json:"last_event_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SessionStatus derives a session's lifecycle state.
//
// currentSessionID is the session the Sentinel's own authenticated heartbeat
// most recently claimed as its own (Record.SessionID) -- NOT simply the
// newest row. That distinction is the whole point: a session is active
// because the Sentinel is currently reporting it and is being heard from, not
// because it once said "running" and happens to sort last.
func SessionStatus(s FleetSession, currentSessionID string, now time.Time) string {
	if s.StoppedAt != nil {
		return SessionStopped
	}
	if s.SessionID == currentSessionID && !s.LastSeenAt.IsZero() && now.Sub(s.LastSeenAt) <= OfflineThreshold {
		return SessionActive
	}
	return SessionInterrupted
}

// SessionView is a FleetSession plus its computed lifecycle state, as
// returned by the history APIs and rendered by the UI.
type SessionView struct {
	FleetSession
	Status string `json:"status"`

	// Current marks the one session an operator should read as "what this
	// Sentinel is doing right now." It is true only for a session that is
	// genuinely ACTIVE -- a Sentinel that was killed has no current session
	// until it restarts, which is the honest answer rather than leaving its
	// last session labelled current indefinitely.
	Current bool `json:"current"`

	// Evidence states where the authoritative record actually lives.
	Evidence EvidenceRef `json:"evidence"`

	// OwnerIdentity is the owning Sentinel's computed Fleet identity state
	// (see IdentityState). It is carried here so a session view can be
	// precise about revocation: REVOKED means the Sentinel is out of the
	// fleet, NOT that it stopped governing its repository, and any surface
	// showing a session needs to be able to say so.
	OwnerIdentity string `json:"owner_identity,omitempty"`
}

func newSessionView(s FleetSession, currentSessionID string, now time.Time) SessionView {
	status := SessionStatus(s, currentSessionID, now)
	return SessionView{
		FleetSession: s,
		Status:       status,
		Current:      status == SessionActive,
		Evidence:     LocalEvidenceRef(s.SessionID),
	}
}

// SentinelTotals is governance activity summed across a Sentinel's retained
// session history. It is always derived on read from the same per-session
// values the history displays, so a total can never disagree with the rows it
// came from.
//
// SessionCount reflects RETAINED sessions: once retention ages metadata out,
// totals describe the retained window rather than all time. That is stated in
// the UI rather than presented as an all-time figure it is not.
type SentinelTotals struct {
	SessionCount      int `json:"session_count"`
	AllowCount        int `json:"allow_count"`
	DenyCount         int `json:"deny_count"`
	RevertedCount     int `json:"reverted_count"`
	RevertFailedCount int `json:"revert_failed_count"`
}

// Totals sums sessions into a Sentinel-level rollup.
func Totals(sessions []FleetSession) SentinelTotals {
	t := SentinelTotals{SessionCount: len(sessions)}
	for _, s := range sessions {
		t.AllowCount += s.AllowCount
		t.DenyCount += s.DenyCount
		t.RevertedCount += s.RevertedCount
		t.RevertFailedCount += s.RevertFailedCount
	}
	return t
}

// RetentionPolicy bounds how much session METADATA the control plane keeps.
//
// This is Fleet's own copy and nothing else. Applying retention never touches
// a Sentinel's local .airlock/runs/ evidence, its last-known-good policy, its
// credential, or its durable identity -- Fleet has no mechanism to delete any
// of those, by design (there is no remote-delete operation in the protocol at
// all). Local evidence retention remains entirely the operator's own decision
// via `airlock cleanup` on that machine.
type RetentionPolicy struct {
	Enabled bool `json:"enabled"`

	// MaxSessionsPerSentinel keeps the newest N sessions per Sentinel. 0
	// disables the count bound.
	MaxSessionsPerSentinel int `json:"max_sessions_per_sentinel"`

	// MaxAge drops sessions last seen longer ago than this. 0 disables the
	// age bound.
	MaxAge time.Duration `json:"max_age"`
}

// DefaultRetention is bounded by default -- history that grows forever is a
// disk-exhaustion bug with a long fuse, not a feature.
func DefaultRetention() RetentionPolicy {
	return RetentionPolicy{
		Enabled:                true,
		MaxSessionsPerSentinel: DefaultMaxSessionsPerSentinel,
		MaxAge:                 DefaultMaxSessionAge,
	}
}
