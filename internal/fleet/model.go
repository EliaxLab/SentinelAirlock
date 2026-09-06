// Package fleet implements the Airlock Fleet control plane: a minimal
// coordination/inventory service that tracks which Sentinels exist, what
// they govern, whether they are alive, and their recently-reported policy
// and governance health.
//
// The control plane is explicitly NOT in the filesystem-policy decision
// path. A Sentinel allows/denies/reverts filesystem mutations entirely from
// its own local policy engine (internal/recorder + internal/governance);
// enrollment and heartbeats are asynchronous, best-effort management
// traffic layered on top, and their failure must never affect local
// enforcement. See internal/cli/sentinel.go's fleet integration for how
// that boundary is enforced (a goroutine independent of the recorder).
package fleet

import "time"

const (
	// DefaultHeartbeatInterval is how often a healthy, reachable Sentinel
	// sends a heartbeat to an enrolled control plane. Within the 5-15s
	// range called for by the fleet-foundation design: frequent enough for
	// the UI to feel live, infrequent enough to never be mistaken for a
	// per-filesystem-event reporting channel (it is not one).
	DefaultHeartbeatInterval = 10 * time.Second

	// OfflineThreshold is how stale a Sentinel's last heartbeat must be
	// before the control plane reports it as OFFLINE instead of ACTIVE.
	// Set to 3x the heartbeat interval so a single delayed/dropped
	// heartbeat (GC pause, transient network blip) does not flap a healthy
	// Sentinel to OFFLINE and back.
	OfflineThreshold = 3 * DefaultHeartbeatInterval

	// MaxEnrollAttempts bounds the Sentinel-side enrollment retry burst at
	// startup so an unreachable control plane never becomes an unbounded
	// retry storm. After this burst, the Sentinel keeps retrying
	// enrollment at the (much slower) heartbeat-tick cadence indefinitely
	// -- see internal/cli/sentinel.go's fleetLoop -- which is how a
	// Sentinel reconnects to a control plane that comes back later without
	// needing to be restarted.
	MaxEnrollAttempts = 5

	// MaxEnrollBackoff caps exponential backoff between the bounded burst
	// of startup enrollment attempts.
	MaxEnrollBackoff = 30 * time.Second

	// ClientTimeout bounds every single fleet HTTP call. It exists so a
	// hung or slow-to-respond control plane can never stall a Sentinel's
	// fleet-reporting goroutine for long, let alone its (entirely separate)
	// local enforcement loop.
	ClientTimeout = 3 * time.Second
)

// EnrollRequest establishes a Sentinel's identity with the control plane.
// It intentionally carries no repository contents and no raw evidence --
// only identity, version, and reported-policy metadata. Fleet v0 is
// inventory/health, not centralized data exfiltration.
type EnrollRequest struct {
	SentinelID      string    `json:"sentinel_id"`
	MachineID       string    `json:"machine_id"`
	Hostname        string    `json:"hostname"`
	Platform        string    `json:"platform"`
	RepoPath        string    `json:"repo_path"`
	SentinelVersion string    `json:"sentinel_version"`
	SessionID       string    `json:"session_id"`
	StartedAt       time.Time `json:"started_at"`
	PolicyID        string    `json:"policy_id,omitempty"`
	PolicyVersion   string    `json:"policy_version,omitempty"`
	PolicyHash      string    `json:"policy_hash,omitempty"`

	// EnrollToken is a one-time operator-issued enrollment token (Prompt
	// 14B). It is presented only on a Sentinel's *first* enrollment; every
	// later enrollment and heartbeat authenticates with the durable
	// credential the control plane issues in exchange. See internal/fleet/
	// auth.go for the full trust flow.
	EnrollToken string `json:"enroll_token,omitempty"`
}

// EnrollResponse acknowledges enrollment and, on a first enrollment, hands
// back the two pieces of trust material a Sentinel needs for the rest of its
// life: its own durable credential, and the control plane's policy-signing
// public key.
//
// Credential is returned exactly once, at the moment it is created. The
// control plane stores only its hash and can never show it again -- if it is
// lost, the credential must be revoked and the Sentinel re-enrolled.
type EnrollResponse struct {
	SentinelID string `json:"sentinel_id"`
	Enrolled   bool   `json:"enrolled"`
	Credential string `json:"credential,omitempty"`

	// SigningKeyID/SigningPublicKey advertise the key this control plane
	// signs policy with. A Sentinel pins them at enrollment -- the moment
	// authorized by an out-of-band enrollment token -- and thereafter refuses
	// policy signed by anything else. See internal/cli/sentinel.go's
	// fleetTrustFile.
	SigningKeyID     string `json:"signing_key_id,omitempty"`
	SigningPublicKey string `json:"signing_public_key,omitempty"`

	// RequireEnrollment tells a Sentinel whether this control plane is
	// running the authenticated production posture or the documented
	// development posture, so the Sentinel can say so in its own local status
	// rather than leaving an operator to guess.
	RequireEnrollment bool `json:"require_enrollment"`
}

// HeartbeatRequest is small, frequent, and carries no file contents, diffs,
// or raw evidence -- only counters and a reference (SessionID) to evidence
// that stays local to the Sentinel's own machine and remains inspectable
// there with the existing `airlock inspect/replay/verify` commands. Central
// evidence aggregation is out of scope for the fleet foundation.
type HeartbeatRequest struct {
	SentinelID        string     `json:"sentinel_id"`
	SessionID         string     `json:"session_id"`
	Status            string     `json:"status"`
	Timestamp         time.Time  `json:"timestamp"`
	SentinelVersion   string     `json:"sentinel_version"`
	PolicyID          string     `json:"policy_id,omitempty"`
	PolicyVersion     string     `json:"policy_version,omitempty"`
	PolicyHash        string     `json:"policy_hash,omitempty"`
	LastEventAt       *time.Time `json:"last_event_at,omitempty"`
	AllowCount        int        `json:"allow_count"`
	DenyCount         int        `json:"deny_count"`
	RevertedCount     int        `json:"reverted_count"`
	RevertFailedCount int        `json:"revert_failed_count"`

	// Reconcile self-report (Prompt 14A). ReconcileStatus is "" (nothing to
	// report -- IN_SYNC/DRIFTED are derived server-side from desired vs
	// actual instead), "RECONCILING" (actively fetching/applying right now),
	// or "RECONCILE_FAILED" (the attempt for ReconcileForHash failed;
	// ReconcileError explains why, and the Sentinel kept its previous
	// last-known-good policy -- see internal/cli/sentinel.go's
	// reconcileFleetPolicy).
	ReconcileStatus  string `json:"reconcile_status,omitempty"`
	ReconcileError   string `json:"reconcile_error,omitempty"`
	ReconcileForHash string `json:"reconcile_for_hash,omitempty"`

	// Trust self-report (Prompt 14B): how the Sentinel verified the policy it
	// is currently enforcing ("VERIFIED", "UNSIGNED", or "" if it is not
	// running a Fleet-managed policy), which key it verified against, and how
	// many reports it currently has buffered undelivered. These are
	// descriptive, not authoritative -- the control plane displays them, and
	// never uses a Sentinel's own claim as evidence about that Sentinel.
	SignatureState  string `json:"signature_state,omitempty"`
	SignerKeyID     string `json:"signer_key_id,omitempty"`
	BufferedReports int    `json:"buffered_reports,omitempty"`

	// Governance session history (Prompt 14C). The heartbeat already carried
	// everything a session record needs except when the session began, so
	// history rides the existing authenticated loop rather than adding a
	// second synchronization channel.
	//
	// SessionStartedAt is this monitoring session's start. It is sticky
	// server-side: a later heartbeat that omits it never blanks it.
	SessionStartedAt time.Time `json:"session_started_at,omitempty"`

	// HistorySyncDisabled suppresses governance-history metadata only. It is
	// phrased negatively on purpose: the zero value means history sync is ON,
	// so a pre-14C Sentinel and a default-configured one behave identically.
	//
	// Operational heartbeat is deliberately NOT affected by this flag --
	// health, drift, and policy state keep working. Turning off history must
	// not quietly turn off fleet health monitoring; those are different
	// concerns and this is the line between them.
	HistorySyncDisabled bool `json:"history_sync_disabled,omitempty"`
}

// SessionStoppedStatus is the Status value a Sentinel sends on its final
// heartbeat to report a clean shutdown. Anything else leaves the session's
// stopped_at unset -- Fleet never infers a clean stop it was not told about.
const SessionStoppedStatus = "stopped"

// HeartbeatResponse acknowledges a heartbeat and carries the Sentinel's
// current desired policy, if one has been assigned (Prompt 14A). An empty
// DesiredPolicyID means this Sentinel is not Fleet-policy-managed: it
// should keep enforcing whatever it already has (its local airlock.yaml, or
// a previously-applied Fleet policy) and not treat the absence of an
// assignment as "clear my policy."
type HeartbeatResponse struct {
	Accepted             bool   `json:"accepted"`
	DesiredPolicyID      string `json:"desired_policy_id,omitempty"`
	DesiredPolicyVersion int    `json:"desired_policy_version,omitempty"`
	DesiredPolicyHash    string `json:"desired_policy_hash,omitempty"`

	// DesiredPolicyDigest is the full canonical SHA-256 of the desired
	// version (Prompt 14B). The short hash above remains the drift
	// fingerprint; this is what a rollback grant binds to.
	DesiredPolicyDigest string `json:"desired_policy_digest,omitempty"`

	// RollbackGrant, when present, is a signed authorization for this
	// specific Sentinel to move backwards to the desired version. It is
	// carried in the response body rather than being implied by a flag
	// precisely because the response channel is not itself trusted: the
	// grant's signature is what authorizes the downgrade, so an attacker who
	// can rewrite this response still cannot manufacture one. See
	// VerifyRollbackGrant.
	RollbackGrant *RollbackGrant `json:"rollback_grant,omitempty"`
}

// Record is the control plane's durable view of one Sentinel installation.
//
// Identity vs session, made explicit:
//   - SentinelID is a durable identity for "the Sentinel governing this
//     repository on this machine." It survives Sentinel restarts (stop/
//     start, background/foreground toggling, crash recovery) -- see
//     internal/fleet/identity.go. Restarting Sentinel does not create a new
//     fleet inventory entry.
//   - SessionID is the existing per-run monitoring-session identity
//     (internal/cli/sentinel.go), already used to name each session's
//     evidence directory (.airlock/runs/<session-id>/). It intentionally
//     changes every time Sentinel (re)starts, independent of SentinelID.
//
// EnrolledAt is sticky: it is set the first time this SentinelID is ever
// seen and preserved across every later re-enrollment. StartedAt reflects
// the current/most recent process start and is refreshed on every
// enrollment (i.e. every Sentinel start).
type Record struct {
	SentinelID      string `json:"sentinel_id"`
	MachineID       string `json:"machine_id"`
	Hostname        string `json:"hostname"`
	Platform        string `json:"platform"`
	RepoPath        string `json:"repo_path"`
	SentinelVersion string `json:"sentinel_version"`
	SessionID       string `json:"session_id"`
	Status          string `json:"status"`

	// PolicyID/PolicyVersion/PolicyHash are ACTUAL state: whatever the
	// Sentinel most recently reported it is really enforcing (a local
	// policy pack, "local" for a plain airlock.yaml, or a Fleet-managed
	// PolicyRef's id/stringified-version/hash once one has been
	// successfully applied). PolicyVersion is a string for backward
	// compatibility with Prompt 14 (a policy-pack version like "1.0.0" is
	// not an integer) -- compare against DesiredPolicyVersion via
	// ReconcileState, not by direct type equality.
	PolicyID      string `json:"policy_id,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	PolicyHash    string `json:"policy_hash,omitempty"`

	// DesiredPolicy{ID,Version,Hash} are DESIRED state: set only by an
	// operator via Store.AssignPolicy (Prompt 14A), never by a Sentinel's
	// own heartbeat. Empty DesiredPolicyID means "not Fleet-policy-managed"
	// -- see ReconcileState.
	DesiredPolicyID      string `json:"desired_policy_id,omitempty"`
	DesiredPolicyVersion int    `json:"desired_policy_version,omitempty"`
	DesiredPolicyHash    string `json:"desired_policy_hash,omitempty"`

	// ReconcileStatus/ReconcileError/ReconcileForHash are the Sentinel's own
	// self-report of an in-progress or failed reconciliation attempt (see
	// HeartbeatRequest). IN_SYNC/DRIFTED are never stored here -- they are
	// always derived fresh by ReconcileState from Desired* vs actual
	// PolicyID/PolicyVersion/PolicyHash, the same "compute, don't trust"
	// principle Health() already uses for liveness.
	ReconcileStatus  string     `json:"reconcile_status,omitempty"`
	ReconcileError   string     `json:"reconcile_error,omitempty"`
	ReconcileForHash string     `json:"reconcile_for_hash,omitempty"`
	LastReconcileAt  *time.Time `json:"last_reconcile_at,omitempty"`

	// Trust state (Prompt 14B). CredentialIssued/Revoked are set by the
	// control plane from its own auth store -- never from anything a Sentinel
	// says about itself -- and are what IdentityState computes from.
	// SignatureState/SignerKeyID are the Sentinel's descriptive self-report
	// of how it verified the policy it is enforcing.
	CredentialIssued bool       `json:"credential_issued,omitempty"`
	Revoked          bool       `json:"revoked,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedReason    string     `json:"revoked_reason,omitempty"`
	SignatureState   string     `json:"signature_state,omitempty"`
	SignerKeyID      string     `json:"signer_key_id,omitempty"`
	BufferedReports  int        `json:"buffered_reports,omitempty"`

	// DesiredPolicyDigest is the full canonical digest of the desired
	// version, carried alongside the short DesiredPolicyHash so a rollback
	// grant can be bound to content rather than to a truncated fingerprint.
	DesiredPolicyDigest string `json:"desired_policy_digest,omitempty"`

	// RollbackGrant is a signed, expiring authorization for this Sentinel to
	// accept the currently-desired version even though it is older than one
	// it has already run. Set only by an explicit operator rollback.
	RollbackGrant *RollbackGrant `json:"rollback_grant,omitempty"`

	EnrolledAt        time.Time  `json:"enrolled_at"`
	StartedAt         time.Time  `json:"started_at"`
	LastHeartbeat     time.Time  `json:"last_heartbeat"`
	LastEventAt       *time.Time `json:"last_event_at,omitempty"`
	AllowCount        int        `json:"allow_count"`
	DenyCount         int        `json:"deny_count"`
	RevertedCount     int        `json:"reverted_count"`
	RevertFailedCount int        `json:"revert_failed_count"`
}

// Health derives ACTIVE/OFFLINE from heartbeat freshness against now, rather
// than trusting a Sentinel's self-reported Status forever once it has
// reported in -- the fleet-foundation's explicit inventory requirement.
// There is no DEGRADED state in v0: it was left out rather than invented
// without a concrete signal to justify it (see progress.md's Prompt 14
// handoff for what a future DEGRADED signal could be based on).
func Health(rec Record, now time.Time) string {
	if rec.LastHeartbeat.IsZero() || now.Sub(rec.LastHeartbeat) > OfflineThreshold {
		return "OFFLINE"
	}
	return "ACTIVE"
}

// SentinelView is a Record plus its computed Health and policy
// ReconcileState, as returned by the inventory APIs. PolicyState/
// PolicyStateError are always computed fresh from Record's stored fields
// (see ReconcileState) -- never trusted as a standing flag, the same
// "compute, don't trust" principle Health already applies to liveness.
type SentinelView struct {
	Record
	Health           string `json:"health"`
	PolicyState      string `json:"policy_state,omitempty"`
	PolicyStateError string `json:"policy_state_error,omitempty"`

	// Identity is the computed AUTHENTICATED/UNAUTHENTICATED/REVOKED trust
	// state (Prompt 14B) -- see IdentityState.
	Identity string `json:"identity"`
}

func newSentinelView(rec Record, now time.Time) SentinelView {
	status, errMsg := ReconcileState(rec)
	return SentinelView{
		Record:           rec,
		Health:           Health(rec, now),
		PolicyState:      status,
		PolicyStateError: errMsg,
		Identity:         IdentityState(rec),
	}
}

// Snapshot is the fleet inventory at a point in time: summary counts plus
// every known Sentinel (offline ones are retained with last-seen
// information, never silently dropped).
type Snapshot struct {
	Now     time.Time `json:"now"`
	Active  int       `json:"active"`
	Offline int       `json:"offline"`

	// Drifted and Revoked (Prompt 14B) are computed the same way Active/
	// Offline are -- counted fresh from the same computed per-Sentinel states
	// shown in the table, never stored. Drifted counts anything not IN_SYNC
	// among Fleet-policy-managed Sentinels, including reconciliation
	// failures, since from an operator's point of view all of those mean "not
	// running what I asked for."
	Drifted int `json:"drifted"`
	Revoked int `json:"revoked"`

	Sentinels []SentinelView `json:"sentinels"`
}
