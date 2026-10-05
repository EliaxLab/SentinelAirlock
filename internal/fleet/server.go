package fleet

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Server is the Airlock Fleet control plane's HTTP surface: Sentinel
// enrollment/heartbeat ingestion, inventory APIs, policy resource/assignment
// APIs (Prompt 14A), signed-policy and credential trust (Prompt 14B), and a
// small operator UI.
//
// Deliberately absent, by design (see progress.md's Prompt 14B handoff for
// the full list of what is explicitly deferred):
//   - no remote command execution of any kind, and no channel that could
//     become one: the protocol carries desired policy, desired configuration,
//     and identity status -- never a command string
//   - no OAuth/OIDC/SAML, no RBAC beyond the operator/Sentinel split, no
//     HSM/KMS, no certificate authority
type Server struct {
	store        *Store
	policyStore  *PolicyStore
	authStore    *AuthStore
	alertStore   *AlertStore
	sessionStore *SessionStore
	signingKey   *SigningKey
	token        string

	// requireEnrollment selects the trust posture. See ServerOptions.
	requireEnrollment bool
}

// ServerOptions carries the Prompt 14B trust machinery. Every field is
// optional: a Server built without them behaves exactly as the Prompt 14/14A
// control plane did, which is what lets an existing deployment (and the
// existing test suite) keep working unchanged.
type ServerOptions struct {
	// AuthStore holds enrollment tokens and per-Sentinel credentials. With
	// no AuthStore, no credentials can exist, so nothing can be
	// authenticated as a Sentinel.
	AuthStore *AuthStore

	// AlertStore retains the fleet-wide alert feed fed by Sentinel report
	// batches. With no AlertStore, report ingestion is refused rather than
	// silently accepted and dropped.
	AlertStore *AlertStore

	// SigningKey signs policy versions and rollback grants.
	SigningKey *SigningKey

	// SessionStore retains governance session history (Prompt 14C). With no
	// SessionStore, heartbeats still work exactly as before and no history is
	// recorded -- history is additive, never a precondition for health.
	SessionStore *SessionStore

	// RequireEnrollment is the production posture: every Sentinel endpoint
	// demands a valid per-Sentinel credential, and first enrollment demands a
	// valid one-time enrollment token.
	//
	// With it off (the development posture), a Sentinel that has never been
	// issued a credential may still enroll and heartbeat unauthenticated --
	// but a Sentinel that HAS a credential always must present it. That
	// second half is not a posture, it is unconditional: once an identity is
	// enrolled, nothing can act as it without its credential, in either
	// posture. See requireSentinel.
	RequireEnrollment bool
}

// NewServer builds a Server with no trust machinery configured -- the
// Prompt 14/14A behavior, where token is an optional shared secret and an
// empty token means every endpoint is open. Retained as-is so existing
// callers and tests are unaffected; production deployments go through
// NewServerWithOptions (which is what `airlock fleet serve` uses).
func NewServer(store *Store, policyStore *PolicyStore, token string) *Server {
	return NewServerWithOptions(store, policyStore, token, ServerOptions{})
}

// NewServerWithOptions builds a Server with Prompt 14B trust machinery.
func NewServerWithOptions(store *Store, policyStore *PolicyStore, token string, opts ServerOptions) *Server {
	s := &Server{
		store:             store,
		policyStore:       policyStore,
		authStore:         opts.AuthStore,
		alertStore:        opts.AlertStore,
		sessionStore:      opts.SessionStore,
		signingKey:        opts.SigningKey,
		token:             strings.TrimSpace(token),
		requireEnrollment: opts.RequireEnrollment,
	}
	if s.signingKey != nil && s.policyStore != nil {
		s.policyStore.SetSigner(s.signingKey)
	}
	return s
}

// Handler returns the complete fleet control-plane HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/fleet/enroll", s.handleEnroll)
	mux.HandleFunc("/api/fleet/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/fleet/reports", s.handleReports)
	mux.HandleFunc("/api/fleet/alerts", s.handleAlerts)
	mux.HandleFunc("/api/fleet/trust", s.handleTrust)
	mux.HandleFunc("/api/fleet/enroll-tokens", s.handleEnrollTokens)
	mux.HandleFunc("/api/fleet/enroll-tokens/", s.handleEnrollTokenSub)
	mux.HandleFunc("/api/fleet/sessions", s.handleSessionsList)
	mux.HandleFunc("/api/fleet/sessions/", s.handleSessionDetail)
	mux.HandleFunc("/api/fleet/sentinels", s.handleList)
	mux.HandleFunc("/api/fleet/sentinels/", s.handleDetailAPI)
	mux.HandleFunc("/fleet/sessions/", s.handleSessionPage)
	mux.HandleFunc("/api/fleet/policies", s.handlePoliciesRoot)
	mux.HandleFunc("/api/fleet/policies/", s.handlePoliciesSub)
	mux.HandleFunc("/fleet/sentinels/", s.handleDetailPage)
	return mux
}

// --- Authentication (Prompt 14B) --------------------------------------------
//
// Prompt 14's handoff suggested a stronger scheme could replace the body of
// authorized(req) bool without touching call sites. It could not, and the
// boolean is gone: "is this request allowed" cannot express "and who is it,"
// and without the second half any valid credential in the fleet would be able
// to submit data as any sentinel_id. Handlers now resolve a Principal and
// check what that principal may act as.

// CredentialHeader is where a Sentinel presents its durable credential.
const CredentialHeader = "X-Airlock-Sentinel-Credential"

// authenticate resolves the identity behind r. A Sentinel credential is
// checked first and is authoritative: the sentinel_id in a request body is
// never consulted here, only compared against the resolved identity later
// (see requireSentinel).
func (s *Server) authenticate(r *http.Request) Principal {
	if s.authStore != nil {
		if cred := strings.TrimSpace(r.Header.Get(CredentialHeader)); cred != "" {
			id, err := s.authStore.Authenticate(cred)
			switch {
			case err == nil:
				return Principal{Type: PrincipalSentinel, SentinelID: id}
			case errors.Is(err, ErrCredentialRevoked):
				return Principal{Type: PrincipalAnonymous, SentinelID: id, Revoked: true}
			default:
				return Principal{Type: PrincipalAnonymous}
			}
		}
	}
	if s.token == "" {
		// Documented development posture: no operator token configured means
		// operator endpoints are open. `airlock fleet serve` says so loudly
		// at startup rather than letting it pass unnoticed.
		return Principal{Type: PrincipalOperator}
	}
	if constantTimeEqual(bearerToken(r.Header.Get("Authorization")), s.token) ||
		constantTimeEqual(strings.TrimSpace(r.Header.Get("X-Airlock-Fleet-Token")), s.token) {
		return Principal{Type: PrincipalOperator}
	}
	return Principal{Type: PrincipalAnonymous}
}

func bearerToken(h string) string {
	h = strings.TrimSpace(h)
	if rest, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(rest)
	}
	return ""
}

// constantTimeEqual compares two secrets without leaking their contents
// through timing. The length check is unavoidable and not itself sensitive.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) || a == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// requireOperator gates operator-only endpoints (policy management,
// assignment, enrollment tokens, revocation, alert viewing).
func (s *Server) requireOperator(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	p := s.authenticate(r)
	if !p.IsOperator() {
		writeAuthError(w, p)
		return p, false
	}
	return p, true
}

// requireSentinel gates endpoints where a Sentinel submits data about
// itself, and is where impersonation is actually stopped: a request is only
// treated as claimedID if the credential it presented was issued to
// claimedID.
//
// The unauthenticated fallback exists only for a Sentinel that has never been
// issued a credential, and only in the development posture. An identity that
// holds a credential can never be acted as without it, regardless of posture
// -- so "enroll a Sentinel, then send heartbeats claiming its id with no
// credential" is rejected in every configuration.
func (s *Server) requireSentinel(w http.ResponseWriter, r *http.Request, claimedID string) (Principal, bool) {
	p := s.authenticate(r)
	if p.CanActAs(claimedID) {
		return p, true
	}
	if p.Revoked {
		writeAuthError(w, p)
		return p, false
	}
	if s.requireEnrollment || s.hasCredential(claimedID) {
		http.Error(w, "unauthorized: this sentinel identity requires its own credential", http.StatusUnauthorized)
		return p, false
	}
	// Development posture, unenrolled identity: Prompt 14's shared operator
	// token remains the outer gate. It is not an identity -- it cannot say
	// *which* Sentinel this is -- but where one is configured it still has to
	// be presented, so 14B never loosens what 14 already required.
	if !p.IsOperator() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return p, false
	}
	return Principal{Type: PrincipalSentinel, SentinelID: claimedID}, true
}

// hasCredential reports whether claimedID has ever been issued a credential
// (revoked or not). A revoked credential still counts: revocation must not
// downgrade an identity back to "anyone may speak for it."
func (s *Server) hasCredential(sentinelID string) bool {
	if s.authStore == nil || sentinelID == "" {
		return false
	}
	_, ok := s.authStore.CredentialFor(sentinelID)
	return ok
}

// writeAuthError distinguishes revocation from ordinary rejection, because a
// revoked Sentinel needs to be able to tell the difference: "my identity was
// revoked" is a state it should report locally and stop retrying as if it
// were a network problem. The body is a stable machine-readable token.
func writeAuthError(w http.ResponseWriter, p Principal) {
	if p.Revoked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": ErrorCredentialRevoked})
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// ErrorCredentialRevoked is the stable error token a control plane returns to
// a Sentinel whose credential has been revoked.
const ErrorCredentialRevoked = "credential_revoked"

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req EnrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid enrollment payload", http.StatusBadRequest)
		return
	}
	req.SentinelID = strings.TrimSpace(req.SentinelID)
	req.MachineID = strings.TrimSpace(req.MachineID)
	if req.SentinelID == "" || req.MachineID == "" {
		http.Error(w, "sentinel_id and machine_id are required", http.StatusBadRequest)
		return
	}

	// Enrollment is the one endpoint where a Sentinel may not yet have a
	// credential -- establishing one is what it is for. Three ways in, in
	// order of preference:
	//
	//  1. an existing credential for this identity (an ordinary restart)
	//  2. a valid one-time enrollment token (first enrollment)
	//  3. nothing, if this control plane runs the development posture AND
	//     this identity has never held a credential
	issuedCredential := ""
	p := s.authenticate(r)
	switch {
	case p.CanActAs(req.SentinelID):
		// Re-enrollment by the enrolled Sentinel itself. Nothing to issue.
	case p.Revoked:
		writeAuthError(w, p)
		return
	case strings.TrimSpace(req.EnrollToken) != "":
		if s.authStore == nil {
			http.Error(w, "this control plane does not issue credentials", http.StatusBadRequest)
			return
		}
		cred, _, err := s.authStore.ConsumeEnrollToken(req.EnrollToken, req.SentinelID)
		if err != nil {
			if errors.Is(err, ErrSentinelAlreadyEnrolled) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			// Unknown, used, expired, and revoked tokens are all answered
			// identically, so a caller cannot use this endpoint to learn
			// which tokens exist or what state they are in.
			http.Error(w, "enrollment token is not valid", http.StatusUnauthorized)
			return
		}
		issuedCredential = cred
	case s.requireEnrollment:
		http.Error(w, "an enrollment token is required to enroll with this control plane", http.StatusUnauthorized)
		return
	case s.hasCredential(req.SentinelID):
		http.Error(w, "unauthorized: this sentinel identity requires its own credential", http.StatusUnauthorized)
		return
	case !p.IsOperator():
		// Development posture with a shared operator token configured: that
		// token is still required, exactly as in Prompt 14.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	now := time.Now().UTC()
	rec := Record{
		SentinelID:      req.SentinelID,
		MachineID:       req.MachineID,
		Hostname:        req.Hostname,
		Platform:        req.Platform,
		RepoPath:        req.RepoPath,
		SentinelVersion: req.SentinelVersion,
		SessionID:       req.SessionID,
		Status:          "running",
		PolicyID:        req.PolicyID,
		PolicyVersion:   req.PolicyVersion,
		PolicyHash:      req.PolicyHash,
		StartedAt:       req.StartedAt,
		LastHeartbeat:   now,
		EnrolledAt:      now,
	}
	if _, err := s.store.UpsertEnroll(rec); err != nil {
		http.Error(w, "could not persist enrollment", http.StatusInternalServerError)
		return
	}
	resp := EnrollResponse{
		SentinelID:        req.SentinelID,
		Enrolled:          true,
		Credential:        issuedCredential,
		RequireEnrollment: s.requireEnrollment,
	}
	// Advertise the policy-signing public key on every enrollment. It is
	// public verification material, not a secret; the Sentinel pins it the
	// first time (the moment authorized by the out-of-band enrollment token)
	// and refuses a different one afterwards.
	if s.signingKey != nil {
		resp.SigningKeyID = s.signingKey.KeyID
		resp.SigningPublicKey = s.signingKey.PublicKeyHex()
	}
	writeJSON(w, resp)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req HeartbeatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid heartbeat payload", http.StatusBadRequest)
		return
	}
	req.SentinelID = strings.TrimSpace(req.SentinelID)
	if req.SentinelID == "" {
		http.Error(w, "sentinel_id is required", http.StatusBadRequest)
		return
	}
	if _, ok := s.requireSentinel(w, r, req.SentinelID); !ok {
		return
	}
	now := time.Now().UTC()
	rec, err := s.store.UpsertHeartbeat(req.SentinelID, func(rec *Record) {
		rec.LastHeartbeat = now
		if req.SessionID != "" {
			rec.SessionID = req.SessionID
		}
		if req.Status != "" {
			rec.Status = req.Status
		}
		if req.SentinelVersion != "" {
			rec.SentinelVersion = req.SentinelVersion
		}
		if req.PolicyID != "" {
			rec.PolicyID = req.PolicyID
		}
		if req.PolicyVersion != "" {
			rec.PolicyVersion = req.PolicyVersion
		}
		if req.PolicyHash != "" {
			rec.PolicyHash = req.PolicyHash
		}
		if req.LastEventAt != nil {
			rec.LastEventAt = req.LastEventAt
		}
		rec.AllowCount = req.AllowCount
		rec.DenyCount = req.DenyCount
		rec.RevertedCount = req.RevertedCount
		rec.RevertFailedCount = req.RevertFailedCount

		// Reconcile self-report (Prompt 14A). An empty ReconcileStatus means
		// "nothing new to report" and must not erase a still-relevant
		// RECONCILE_FAILED from an earlier heartbeat -- only overwrite when
		// the Sentinel is actually telling us something.
		if req.ReconcileStatus != "" {
			rec.ReconcileStatus = req.ReconcileStatus
			rec.ReconcileError = req.ReconcileError
			rec.ReconcileForHash = req.ReconcileForHash
			rec.LastReconcileAt = &now
		}
		// Trust self-report (Prompt 14B): descriptive only. It says how the
		// Sentinel verified what it is running; it never affects what the
		// control plane will authorize.
		if req.SignatureState != "" {
			rec.SignatureState = req.SignatureState
			rec.SignerKeyID = req.SignerKeyID
		}
		rec.BufferedReports = req.BufferedReports
	})
	if err != nil {
		http.Error(w, "could not persist heartbeat", http.StatusInternalServerError)
		return
	}

	// Governance session history (Prompt 14C). Recorded from the same
	// authenticated heartbeat that already carries everything a session row
	// needs -- no second synchronization loop, and no extra round trip.
	//
	// A failure here is deliberately NOT fatal to the heartbeat: history is
	// valuable, but fleet health is what an operator depends on minute to
	// minute, and losing liveness because a metadata write failed would be
	// the wrong trade.
	if err := s.recordSessionHistory(req, rec, now); err != nil {
		if errors.Is(err, ErrSessionOwnedByAnotherSentinel) {
			http.Error(w, "session belongs to a different sentinel", http.StatusForbidden)
			return
		}
	}

	writeJSON(w, HeartbeatResponse{
		Accepted:             true,
		DesiredPolicyID:      rec.DesiredPolicyID,
		DesiredPolicyVersion: rec.DesiredPolicyVersion,
		DesiredPolicyHash:    rec.DesiredPolicyHash,
		DesiredPolicyDigest:  rec.DesiredPolicyDigest,
		RollbackGrant:        rec.RollbackGrant,
	})
}

// recordSessionHistory upserts the reporting Sentinel's current session, and
// records a clean stop when the heartbeat says so.
//
// req.SentinelID is safe to use here only because handleHeartbeat has already
// run requireSentinel against it -- the value has been proven to match the
// authenticated principal. The session store checks ownership again on the
// row itself, so the invariant survives even if a future caller forgets the
// first gate.
func (s *Server) recordSessionHistory(req HeartbeatRequest, rec Record, now time.Time) error {
	if s.sessionStore == nil || req.SessionID == "" {
		return nil
	}
	if req.HistorySyncDisabled {
		// The Sentinel has history sync turned off. Its heartbeat still
		// maintains present state above (health, drift, policy) -- only the
		// historical record is suppressed, which is exactly the split the
		// operator asked for.
		return nil
	}
	if _, err := s.sessionStore.Upsert(req.SentinelID, SessionUpdate{
		SessionID:       req.SessionID,
		MachineID:       rec.MachineID,
		RepoPath:        rec.RepoPath,
		Hostname:        rec.Hostname,
		SentinelVersion: req.SentinelVersion,
		StartedAt:       req.SessionStartedAt,
		// Policy/trust state as THIS session reports it, frozen into this
		// session's row -- never re-derived later from desired state.
		PolicyID:          req.PolicyID,
		PolicyVersion:     req.PolicyVersion,
		PolicyHash:        req.PolicyHash,
		SignatureState:    req.SignatureState,
		SignerKeyID:       req.SignerKeyID,
		AllowCount:        req.AllowCount,
		DenyCount:         req.DenyCount,
		RevertedCount:     req.RevertedCount,
		RevertFailedCount: req.RevertFailedCount,
		LastEventAt:       req.LastEventAt,
	}, now); err != nil {
		return err
	}
	if req.Status == SessionStoppedStatus {
		if _, err := s.sessionStore.MarkStopped(req.SentinelID, req.SessionID, now, now); err != nil {
			return err
		}
	}
	return nil
}

// handleReports ingests a batch of buffered Sentinel reports (Prompt 14B).
// Every stored alert is attributed to the *authenticated* identity, not to
// the sentinel_id in the batch, so a Sentinel cannot file alerts as another.
// Ingestion is idempotent by report id, which is what makes a Sentinel's
// retry-until-acknowledged flush safe.
func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var batch ReportBatch
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&batch); err != nil {
		http.Error(w, "invalid report batch", http.StatusBadRequest)
		return
	}
	batch.SentinelID = strings.TrimSpace(batch.SentinelID)
	if batch.SentinelID == "" {
		http.Error(w, "sentinel_id is required", http.StatusBadRequest)
		return
	}
	p, ok := s.requireSentinel(w, r, batch.SentinelID)
	if !ok {
		return
	}
	if s.alertStore == nil {
		http.Error(w, "this control plane does not accept fleet reports", http.StatusNotFound)
		return
	}
	if len(batch.Reports) > MaxReportsPerFlush {
		http.Error(w, "report batch too large", http.StatusRequestEntityTooLarge)
		return
	}
	// A buffered SESSION_STOPPED is how a clean shutdown that happened during
	// a control-plane outage reaches Fleet (Prompt 14C). It is applied to
	// session history here, under the authenticated principal, before the
	// batch is stored as alerts -- so a Sentinel that stopped while Fleet was
	// down ends up STOPPED rather than permanently INTERRUPTED.
	//
	// MarkStopped is first-write-wins, so this and a live final heartbeat
	// reporting the same stop converge on one stopped_at.
	if s.sessionStore != nil {
		for _, r := range batch.Reports {
			if r.Type != ReportSessionStopped || r.SessionID == "" {
				continue
			}
			if _, err := s.sessionStore.MarkStopped(p.SentinelID, r.SessionID, r.At, time.Now().UTC()); err != nil {
				if errors.Is(err, ErrSessionOwnedByAnotherSentinel) {
					http.Error(w, "session belongs to a different sentinel", http.StatusForbidden)
					return
				}
			}
		}
	}

	resp, err := s.alertStore.Ingest(p.SentinelID, batch.Reports)
	if err != nil {
		http.Error(w, "could not persist reports", http.StatusInternalServerError)
		return
	}
	writeJSON(w, resp)
}

// --- Governance session history APIs (Prompt 14C) ---------------------------
//
// Read-only and operator-authenticated. Sessions are mutated only by their
// own Sentinel, through the authenticated heartbeat and report paths above --
// there is no operator write path into history, and no endpoint anywhere that
// returns evidence contents or a filesystem path Fleet could open.

// SessionListResponse is the history listing, newest first.
type SessionListResponse struct {
	Now      time.Time     `json:"now"`
	Sessions []SessionView `json:"sessions"`

	// Totals is present when the listing is scoped to one Sentinel, and is
	// always derived by summing the rows returned -- never stored separately.
	Totals *SentinelTotals `json:"totals,omitempty"`

	// Retention describes what bounds this history, so an operator reading a
	// short list can tell "nothing happened" from "older metadata aged out."
	Retention RetentionPolicy `json:"retention"`
}

// handleSessionsList serves GET /api/fleet/sessions[?sentinel=<id>].
func (s *Server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	writeJSON(w, s.sessionsFor(strings.TrimSpace(r.URL.Query().Get("sentinel"))))
}

// sessionsFor builds the history listing, optionally scoped to one Sentinel.
func (s *Server) sessionsFor(sentinelID string) SessionListResponse {
	now := time.Now().UTC()
	resp := SessionListResponse{Now: now, Sessions: []SessionView{}}
	if s.sessionStore == nil {
		return resp
	}
	resp.Retention = s.sessionStore.Retention()

	var sessions []FleetSession
	if sentinelID != "" {
		sessions = s.sessionStore.ForSentinel(sentinelID)
		totals := Totals(sessions)
		resp.Totals = &totals
	} else {
		sessions = s.sessionStore.List()
	}
	// The "current" session is whichever one each owning Sentinel's own
	// authenticated heartbeat most recently claimed -- looked up per owner,
	// never inferred from ordering.
	current := map[string]string{}
	for _, sess := range sessions {
		if _, seen := current[sess.SentinelID]; seen {
			continue
		}
		if rec, ok := s.store.Get(sess.SentinelID); ok {
			current[sess.SentinelID] = rec.SessionID
		} else {
			current[sess.SentinelID] = ""
		}
	}
	for _, sess := range sessions {
		resp.Sessions = append(resp.Sessions, newSessionView(sess, current[sess.SentinelID], now))
	}
	return resp
}

// handleSessionDetail serves GET /api/fleet/sessions/<session-id>, including
// the metadata alerts already correlated to that session by Prompt 14B's
// alert store -- correlation over existing metadata, not a second event
// system.
func (s *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/fleet/sessions/"), "/")
	if id == "" {
		s.handleSessionsList(w, r)
		return
	}
	view, alerts, ok := s.sessionDetail(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, struct {
		SessionView
		Alerts []Report `json:"alerts"`
	}{SessionView: view, Alerts: alerts})
}

func (s *Server) sessionDetail(sessionID string) (SessionView, []Report, bool) {
	if s.sessionStore == nil {
		return SessionView{}, nil, false
	}
	sess, ok := s.sessionStore.Get(sessionID)
	if !ok {
		return SessionView{}, nil, false
	}
	currentSessionID := ""
	rec, found := s.store.Get(sess.SentinelID)
	if found {
		currentSessionID = rec.SessionID
	}
	// Carry the owning Sentinel's computed identity state onto the session so
	// the page can be precise about revocation: a revoked Sentinel is out of
	// the fleet but is still governing its repository, and that must be said
	// wherever an operator might otherwise read "revoked" as "stopped."
	identity := IdentityState(s.viewOf(rec, time.Now().UTC()).Record)
	alerts := []Report{}
	if s.alertStore != nil {
		for _, a := range s.alertStore.Recent(MaxStoredAlerts) {
			if a.SessionID == sessionID {
				alerts = append(alerts, a)
			}
		}
	}
	view := newSessionView(sess, currentSessionID, time.Now().UTC())
	view.OwnerIdentity = identity
	return view, alerts, true
}

// handleAlerts serves the recent fleet-wide alert feed to operators.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	if s.alertStore == nil {
		writeJSON(w, []Report{})
		return
	}
	limit := 50
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= MaxStoredAlerts {
			limit = n
		}
	}
	writeJSON(w, s.alertStore.Recent(limit))
}

// trustInfo is the control plane's public trust material.
type trustInfo struct {
	SigningKeyID      string `json:"signing_key_id,omitempty"`
	SigningPublicKey  string `json:"signing_public_key,omitempty"`
	RequireEnrollment bool   `json:"require_enrollment"`
}

// handleTrust publishes the policy-signing PUBLIC key and the trust posture.
// Only public verification material is ever exposed here -- the private
// signing key has no code path to any HTTP response, by construction:
// SigningKey does not serialize it and exposes only KeyID and PublicKeyHex.
func (s *Server) handleTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	info := trustInfo{RequireEnrollment: s.requireEnrollment}
	if s.signingKey != nil {
		info.SigningKeyID = s.signingKey.KeyID
		info.SigningPublicKey = s.signingKey.PublicKeyHex()
	}
	writeJSON(w, info)
}

type createEnrollTokenRequest struct {
	Description string `json:"description,omitempty"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
}

type createEnrollTokenResponse struct {
	ID    string    `json:"id"`
	Token string    `json:"token"` // returned exactly once, never stored
	Note  string    `json:"note"`
	Ends  time.Time `json:"expires_at"`
}

// handleEnrollTokens creates (POST) and lists (GET) one-time enrollment
// tokens. The plaintext token is in the creation response and nowhere else:
// the store holds only its SHA-256, and the listing returns records without
// any token material at all.
func (s *Server) handleEnrollTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	if s.authStore == nil {
		http.Error(w, "this control plane does not issue enrollment tokens", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.authStore.ListEnrollTokens())
	case http.MethodPost:
		var req createEnrollTokenRequest
		// An empty body is fine -- all fields are optional.
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req)
		plaintext, rec, err := s.authStore.CreateEnrollToken(req.Description, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			http.Error(w, "could not create enrollment token", http.StatusInternalServerError)
			return
		}
		writeJSON(w, createEnrollTokenResponse{
			ID:    rec.ID,
			Token: plaintext,
			Ends:  rec.ExpiresAt,
			Note:  "This token is shown once and cannot be retrieved again. It is single-use and expires.",
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEnrollTokenSub serves POST /api/fleet/enroll-tokens/<id>/revoke.
func (s *Server) handleEnrollTokenSub(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	if s.authStore == nil {
		http.Error(w, "this control plane does not issue enrollment tokens", http.StatusNotFound)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/fleet/enroll-tokens/"), "/")
	id, ok := strings.CutSuffix(rest, "/revoke")
	if !ok || id == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.authStore.RevokeEnrollToken(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"id": id, "revoked": true})
}

type revokeSentinelRequest struct {
	Reason string `json:"reason,omitempty"`
}

// handleRevokeSentinel revokes a Sentinel's Fleet credential.
//
// Precise semantics, deliberately: this removes the Sentinel from the fleet.
// It does NOT stop that Sentinel from governing its repository. There is no
// message here that tells a Sentinel to stand down, and adding one would turn
// central revocation into a remote off-switch for the protection Airlock
// exists to provide. A revoked Sentinel keeps enforcing its last-known-good
// policy locally and reports its revoked identity in its own local status.
func (s *Server) handleRevokeSentinel(w http.ResponseWriter, r *http.Request, sentinelID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	if s.authStore == nil {
		http.Error(w, "this control plane does not manage credentials", http.StatusNotFound)
		return
	}
	var req revokeSentinelRequest
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req)
	if err := s.authStore.RevokeSentinel(sentinelID, req.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	rec, _ := s.store.Get(sentinelID)
	rec.SentinelID = sentinelID
	writeJSON(w, s.viewOf(rec, time.Now().UTC()))
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	writeJSON(w, s.snapshot())
}

func (s *Server) handleDetailAPI(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/fleet/sentinels/")
	if rest == "" {
		s.handleList(w, r)
		return
	}
	if id, ok := strings.CutSuffix(rest, "/assign"); ok {
		s.handleAssignPolicy(w, r, id)
		return
	}
	if id, ok := strings.CutSuffix(rest, "/revoke"); ok {
		s.handleRevokeSentinel(w, r, id)
		return
	}
	if id, ok := strings.CutSuffix(rest, "/sessions"); ok {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, authed := s.requireOperator(w, r); !authed {
			return
		}
		writeJSON(w, s.sessionsFor(id))
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	rec, ok := s.store.Get(rest)
	if !ok {
		http.Error(w, "sentinel not found", http.StatusNotFound)
		return
	}
	writeJSON(w, s.viewOf(rec, time.Now().UTC()))
}

// assignPolicyRequest is the body of POST /api/fleet/sentinels/<id>/assign.
//
// AllowRollback is what makes a downgrade an explicit, modeled operation:
// without it, assigning an older version than a Sentinel has already run is
// simply refused by that Sentinel. With it, the control plane issues a signed,
// expiring, Sentinel-bound RollbackGrant -- so the authorization travels as a
// verifiable statement rather than as a flag on an untrusted channel.
type assignPolicyRequest struct {
	PolicyID      string `json:"policy_id"`
	Version       int    `json:"version"`
	AllowRollback bool   `json:"allow_rollback,omitempty"`
}

// handleAssignPolicy sets sentinelID's desired policy to a specific,
// already-existing version of a named policy (Prompt 14A). It never accepts
// raw policy content directly -- only a reference to a version created via
// POST /api/fleet/policies(/<id>/versions) -- so assignment can never bypass
// the validate-before-store step those endpoints already perform.
func (s *Server) handleAssignPolicy(w http.ResponseWriter, r *http.Request, sentinelID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	var req assignPolicyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "invalid assignment payload", http.StatusBadRequest)
		return
	}
	req.PolicyID = strings.TrimSpace(req.PolicyID)
	if req.PolicyID == "" || req.Version <= 0 {
		http.Error(w, "policy_id and a positive version are required", http.StatusBadRequest)
		return
	}
	// Resolve what the operator typed (full ID or the short ID `fleet list`
	// shows) to an enrolled Sentinel before doing anything else, so an unknown
	// or ambiguous ID fails without creating a record, issuing a grant, or
	// changing any assignment. Everything below uses the canonical full ID.
	sentinelID, err := s.store.Resolve(sentinelID)
	if err != nil {
		var amb *AmbiguousSentinelError
		switch {
		case errors.As(err, &amb):
			http.Error(w, amb.Error(), http.StatusConflict)
		default:
			http.Error(w, "sentinel not found: no enrolled sentinel matches that ID (enroll it first; see 'airlock fleet list')", http.StatusNotFound)
		}
		return
	}
	pv, ok := s.policyStore.GetVersion(req.PolicyID, req.Version)
	if !ok {
		http.Error(w, fmt.Sprintf("policy %s version %d does not exist", req.PolicyID, req.Version), http.StatusNotFound)
		return
	}
	ref := PolicyRef{PolicyID: pv.PolicyID, Version: pv.Version, Hash: pv.Hash}

	var grant *RollbackGrant
	if req.AllowRollback {
		if s.signingKey == nil {
			http.Error(w, "this control plane cannot authorize a rollback: no signing key is configured", http.StatusBadRequest)
			return
		}
		g, err := s.signingKey.IssueRollbackGrant(sentinelID, ref, pv.Digest, time.Now().UTC(), DefaultRollbackGrantTTL)
		if err != nil {
			http.Error(w, "could not issue rollback authorization", http.StatusInternalServerError)
			return
		}
		grant = g
	}

	rec, err := s.store.AssignPolicy(sentinelID, ref, pv.Digest, grant)
	if err != nil {
		http.Error(w, "could not persist assignment", http.StatusInternalServerError)
		return
	}
	writeJSON(w, s.viewOf(rec, time.Now().UTC()))
}

// viewOf builds a SentinelView with trust state filled in from the auth store
// rather than from anything persisted on the record. Credential existence and
// revocation are facts the control plane owns, so they are read from where
// they actually live at display time -- the same "compute, don't trust"
// principle Health and ReconcileState follow, applied to identity.
func (s *Server) viewOf(rec Record, now time.Time) SentinelView {
	if s.authStore != nil {
		if cred, ok := s.authStore.CredentialFor(rec.SentinelID); ok {
			rec.CredentialIssued = true
			rec.Revoked = !cred.Active()
			rec.RevokedAt = cred.RevokedAt
			rec.RevokedReason = cred.RevokedReason
		}
	}
	return newSentinelView(rec, now)
}

func (s *Server) snapshot() Snapshot {
	now := time.Now().UTC()
	recs := s.store.List()
	resp := Snapshot{Now: now, Sentinels: make([]SentinelView, 0, len(recs))}
	for _, r := range recs {
		view := s.viewOf(r, now)
		if view.Health == "ACTIVE" {
			resp.Active++
		} else {
			resp.Offline++
		}
		if view.PolicyState != "" && view.PolicyState != "IN_SYNC" {
			resp.Drifted++
		}
		if view.Identity == "REVOKED" {
			resp.Revoked++
		}
		resp.Sentinels = append(resp.Sentinels, view)
	}
	sort.Slice(resp.Sentinels, func(i, j int) bool {
		return resp.Sentinels[i].SentinelID < resp.Sentinels[j].SentinelID
	})
	return resp
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- Policy resource APIs (Prompt 14A) --------------------------------------
//
// Policy content always arrives as a YAML string in a JSON request body --
// never as a filesystem path -- so the control plane can never be asked to
// read an arbitrary local file. Every write validates by attempting to
// parse the content (ComputePolicyHash) before it is ever stored; invalid
// content is rejected with 400 and never becomes a version.

// policyVersionSummary omits YAML content, for list views. It reports whether
// a version is signed and by which key, so an operator can see at a glance
// that what they are about to assign carries trust material -- without the
// summary ever carrying the signature itself.
type policyVersionSummary struct {
	PolicyID    string    `json:"policy_id"`
	Version     int       `json:"version"`
	Hash        string    `json:"hash"`
	Digest      string    `json:"digest,omitempty"`
	Signed      bool      `json:"signed"`
	Issuer      string    `json:"issuer,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func summarize(v PolicyVersion) policyVersionSummary {
	return policyVersionSummary{
		PolicyID: v.PolicyID, Version: v.Version, Hash: v.Hash, Digest: v.Digest,
		Signed: v.Signed(), Issuer: v.Issuer,
		Description: v.Description, CreatedAt: v.CreatedAt,
	}
}

type createPolicyRequest struct {
	PolicyID    string `json:"policy_id"`
	Description string `json:"description,omitempty"`
	YAML        string `json:"yaml"`
}

// handlePoliciesRoot serves GET (list latest version of every policy) and
// POST (create a brand-new policy_id's first version) on /api/fleet/policies.
func (s *Server) handlePoliciesRoot(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireOperator(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		latest := s.policyStore.ListLatest()
		summaries := make([]policyVersionSummary, 0, len(latest))
		for _, v := range latest {
			summaries = append(summaries, summarize(v))
		}
		writeJSON(w, summaries)
	case http.MethodPost:
		var req createPolicyRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid policy payload", http.StatusBadRequest)
			return
		}
		req.PolicyID = strings.TrimSpace(req.PolicyID)
		if req.PolicyID == "" || strings.TrimSpace(req.YAML) == "" {
			http.Error(w, "policy_id and yaml are required", http.StatusBadRequest)
			return
		}
		v, err := s.policyStore.Create(req.PolicyID, req.Description, req.YAML)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, summarize(v))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePoliciesSub serves the /api/fleet/policies/<id>[/versions[/<v>]]
// family:
//
//	GET  /api/fleet/policies/<id>                 all versions (summaries)
//	POST /api/fleet/policies/<id>/versions         add a new version
//	GET  /api/fleet/policies/<id>/versions/<v>     one version, full content
func (s *Server) handlePoliciesSub(w http.ResponseWriter, r *http.Request) {
	// Reading a policy version is the one policy operation an enrolled
	// Sentinel must be able to perform -- it is how reconciliation fetches
	// what it has been assigned. Creating versions stays operator-only, and
	// is checked separately below.
	principal := s.authenticate(r)
	if !principal.IsOperator() && principal.Type != PrincipalSentinel {
		writeAuthError(w, principal)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/fleet/policies/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	policyID := parts[0]

	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !principal.IsOperator() {
			http.Error(w, "unauthorized: only operators may browse policy history", http.StatusUnauthorized)
			return
		}
		versions, ok := s.policyStore.AllVersions(policyID)
		if !ok {
			http.Error(w, "policy not found", http.StatusNotFound)
			return
		}
		summaries := make([]policyVersionSummary, 0, len(versions))
		for _, v := range versions {
			summaries = append(summaries, summarize(v))
		}
		writeJSON(w, summaries)

	case len(parts) == 2 && parts[1] == "versions":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !principal.IsOperator() {
			http.Error(w, "unauthorized: only operators may create policy versions", http.StatusUnauthorized)
			return
		}
		var req createPolicyRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid policy payload", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.YAML) == "" {
			http.Error(w, "yaml is required", http.StatusBadRequest)
			return
		}
		v, err := s.policyStore.AddVersion(policyID, req.Description, req.YAML)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, summarize(v))

	case len(parts) == 3 && parts[1] == "versions":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		version, err := strconv.Atoi(parts[2])
		if err != nil || version <= 0 {
			http.Error(w, "invalid version number", http.StatusBadRequest)
			return
		}
		v, ok := s.policyStore.GetVersion(policyID, version)
		if !ok {
			http.Error(w, "policy version not found", http.StatusNotFound)
			return
		}
		writeJSON(w, v) // full content, including YAML -- this is what Sentinel fetches

	default:
		http.NotFound(w, r)
	}
}
