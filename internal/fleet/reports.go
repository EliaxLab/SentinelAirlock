package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Buffered fleet reporting (Prompt 14B).
//
// Prompt 14 let heartbeats simply fail while a control plane was unreachable,
// which meant everything that happened during an outage was invisible to the
// fleet afterwards -- the Sentinel's own local evidence had it, but an
// operator watching the fleet saw a gap. Reports close that gap without
// centralizing evidence: they are small, metadata-only statements about
// governance events, buffered durably on the Sentinel and flushed when the
// control plane comes back.
//
// What a report deliberately does NOT contain: file contents, diffs, patches,
// source code, or any evidence payload. A path is metadata (which file was
// denied), its contents are not. Raw local Airlock evidence stays on the
// Sentinel's own machine and remains the authoritative record, inspectable
// there with airlock inspect/replay/verify.

const (
	// MaxBufferedReports bounds a Sentinel's durable outbox. An outage must
	// cost bounded disk, so once the buffer is full the OLDEST reports are
	// dropped and counted -- newer governance activity is more actionable
	// than older, and a silently unbounded file on a machine Airlock is
	// supposed to be protecting would be its own problem.
	MaxBufferedReports = 500

	// MaxReportsPerFlush bounds one upload batch, so a Sentinel reconnecting
	// with a full buffer sends several bounded requests rather than one
	// enormous one.
	MaxReportsPerFlush = 100

	// MaxStoredAlerts bounds the control plane's retained fleet-wide alert
	// feed. This is a recent-activity view, not a log store -- authoritative
	// history lives in each Sentinel's local evidence.
	MaxStoredAlerts = 500
)

// Report types. These name governance-relevant transitions worth surfacing at
// fleet level; they are a closed, explicitly-typed set rather than free text,
// for the same reason the control-plane protocol carries desired policy
// rather than commands: a typed vocabulary is something you can reason about,
// an open string channel is not.
const (
	ReportDeny              = "DENY"
	ReportReverted          = "REVERTED"
	ReportRevertFailed      = "REVERT_FAILED"
	ReportPolicyApplied     = "POLICY_APPLIED"
	ReportReconcileFailed   = "RECONCILE_FAILED"
	ReportSignatureInvalid  = "SIGNATURE_INVALID"
	ReportDowngradeRejected = "DOWNGRADE_REJECTED"
	ReportCredentialRevoked = "CREDENTIAL_REVOKED"
	ReportSessionStarted    = "SESSION_STARTED"

	// ReportSessionStopped is how a clean shutdown reaches Fleet when the
	// control plane was unreachable at the moment it happened (Prompt 14C).
	// It rides the existing durable, bounded, deduplicated outbox rather than
	// a second mechanism, so a Sentinel that stops during an outage still
	// gets an accurate STOPPED record once something reconnects -- flushed by
	// a later session, since the one that stopped is gone.
	ReportSessionStopped = "SESSION_STOPPED"
)

// Report is one metadata-only fleet alert from a Sentinel.
//
// ID is the idempotency key. It is derived deterministically from the source
// event (see internal/cli/sentinel.go's reportID), so re-sending a report --
// after a failed flush, a retry, a restart mid-upload -- produces the same ID
// and the control plane recognizes it as a duplicate rather than creating a
// second alert.
type Report struct {
	ID         string    `json:"id"`
	SentinelID string    `json:"sentinel_id"`
	SessionID  string    `json:"session_id,omitempty"`
	Type       string    `json:"type"`
	At         time.Time `json:"at"`
	Path       string    `json:"path,omitempty"`    // repo-relative path only -- never contents
	Summary    string    `json:"summary,omitempty"` // short human-readable label
	RepoPath   string    `json:"repo_path,omitempty"`
}

// ReportID builds a deterministic idempotency key from the parts that make a
// report unique. Two logically identical reports produce the same ID on every
// machine and every retry; two different events never collide.
func ReportID(sentinelID, sessionID, typ string, at time.Time, detail string) string {
	h := sha256.Sum256([]byte(sentinelID + "\x00" + sessionID + "\x00" + typ + "\x00" +
		at.UTC().Format(time.RFC3339Nano) + "\x00" + detail))
	return hex.EncodeToString(h[:16])
}

// ReportBatch is one upload of buffered reports.
type ReportBatch struct {
	SentinelID string   `json:"sentinel_id"`
	Reports    []Report `json:"reports"`
}

// ReportBatchResponse tells a Sentinel what happened to its batch. Accepted
// and Duplicates are both successful outcomes -- a duplicate means the
// control plane already had it, so the Sentinel can drop it from its outbox
// either way. AcceptedIDs is the explicit list to drop, so a partial failure
// never causes a Sentinel to discard something that was not actually stored.
type ReportBatchResponse struct {
	Accepted    int      `json:"accepted"`
	Duplicates  int      `json:"duplicates"`
	AcceptedIDs []string `json:"accepted_ids"`
}

// AlertStore is the control plane's bounded, deduplicated feed of recent
// fleet alerts. Separate file from Store and PolicyStore, following this
// package's established one-store-per-concern convention, which also means
// adding it required no migration of any existing fleet.json.
type AlertStore struct {
	mu     sync.RWMutex
	path   string
	alerts []Report            // newest last
	ids    map[string]struct{} // dedup set over the retained window
}

// OpenAlertStore loads path if it exists, or starts an empty store.
func OpenAlertStore(path string) (*AlertStore, error) {
	s := &AlertStore{path: path, ids: map[string]struct{}{}}
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
	var alerts []Report
	if err := json.Unmarshal(b, &alerts); err != nil {
		return nil, err
	}
	s.alerts = alerts
	for _, a := range alerts {
		s.ids[a.ID] = struct{}{}
	}
	return s, nil
}

// Ingest stores reports that are not already known, attributing every one of
// them to sentinelID -- the *authenticated* identity, passed in by the
// handler, never a value read out of the report body. A Sentinel cannot file
// an alert under someone else's name.
//
// Reports whose ID is already present are counted as duplicates and ignored,
// which is what makes upload retries safe.
func (s *AlertStore) Ingest(sentinelID string, reports []Report) (ReportBatchResponse, error) {
	resp := ReportBatchResponse{AcceptedIDs: []string{}}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range reports {
		if r.ID == "" || r.Type == "" {
			continue
		}
		if _, dup := s.ids[r.ID]; dup {
			resp.Duplicates++
			resp.AcceptedIDs = append(resp.AcceptedIDs, r.ID)
			continue
		}
		r.SentinelID = sentinelID
		if r.At.IsZero() {
			r.At = time.Now().UTC()
		}
		r.At = r.At.UTC()
		s.alerts = append(s.alerts, r)
		s.ids[r.ID] = struct{}{}
		resp.Accepted++
		resp.AcceptedIDs = append(resp.AcceptedIDs, r.ID)
	}
	s.trimLocked()
	if err := s.saveLocked(); err != nil {
		return ReportBatchResponse{}, err
	}
	return resp, nil
}

// trimLocked enforces MaxStoredAlerts. The dedup set is trimmed with the
// alerts, so the idempotency window is exactly the retention window: an alert
// old enough to have aged out could in principle be re-accepted if a Sentinel
// re-sent it much later. That is a deliberate, bounded trade -- the
// alternative is an id set that grows forever.
func (s *AlertStore) trimLocked() {
	if len(s.alerts) <= MaxStoredAlerts {
		return
	}
	drop := s.alerts[:len(s.alerts)-MaxStoredAlerts]
	for _, a := range drop {
		delete(s.ids, a.ID)
	}
	s.alerts = append([]Report(nil), s.alerts[len(s.alerts)-MaxStoredAlerts:]...)
}

// Recent returns up to n alerts, newest first.
func (s *AlertStore) Recent(n int) []Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Report(nil), s.alerts...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Len returns how many alerts are retained.
func (s *AlertStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.alerts)
}

func (s *AlertStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.alerts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

// Outbox is a Sentinel's durable, bounded buffer of reports waiting to reach
// the control plane.
//
// Durable so an outage that spans a Sentinel restart does not lose what
// happened; bounded so an outage that lasts a month cannot fill a disk. It is
// entirely off the enforcement path: adding to the outbox is a local file
// write on the fleet goroutine, and nothing about a filesystem decision ever
// waits on an upload.
type Outbox struct {
	mu      sync.Mutex
	path    string
	Pending []Report `json:"pending"`
	Dropped int      `json:"dropped"`
}

type outboxFile struct {
	Pending []Report `json:"pending"`
	Dropped int      `json:"dropped"`
}

// OpenOutbox loads the durable outbox at path, or starts an empty one.
func OpenOutbox(path string) (*Outbox, error) {
	o := &Outbox{path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return o, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return o, nil
	}
	var f outboxFile
	if err := json.Unmarshal(b, &f); err != nil {
		// A corrupt outbox is not worth failing a Sentinel start over: the
		// buffer is best-effort reporting, and local evidence is unaffected.
		// Start clean rather than refusing to run.
		return o, nil
	}
	o.Pending = f.Pending
	o.Dropped = f.Dropped
	return o, nil
}

// Add appends r, dropping the oldest report if the buffer is full.
func (o *Outbox) Add(r Report) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, p := range o.Pending {
		if p.ID == r.ID {
			return nil // already buffered; deterministic ids make this cheap
		}
	}
	o.Pending = append(o.Pending, r)
	if len(o.Pending) > MaxBufferedReports {
		overflow := len(o.Pending) - MaxBufferedReports
		o.Dropped += overflow
		o.Pending = append([]Report(nil), o.Pending[overflow:]...)
	}
	return o.saveLocked()
}

// Batch returns up to MaxReportsPerFlush pending reports, oldest first.
func (o *Outbox) Batch() []Report {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(o.Pending)
	if n > MaxReportsPerFlush {
		n = MaxReportsPerFlush
	}
	return append([]Report(nil), o.Pending[:n]...)
}

// Ack removes the given ids from the buffer. Only ids the control plane
// explicitly confirmed are removed -- never "everything we tried to send" --
// so a partially-processed batch leaves the remainder buffered for the next
// flush instead of being silently lost.
func (o *Outbox) Ack(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	acked := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		acked[id] = struct{}{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	kept := o.Pending[:0]
	for _, p := range o.Pending {
		if _, ok := acked[p.ID]; !ok {
			kept = append(kept, p)
		}
	}
	o.Pending = append([]Report(nil), kept...)
	return o.saveLocked()
}

// Len returns how many reports are waiting to be delivered.
func (o *Outbox) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.Pending)
}

// DroppedCount returns how many reports were discarded to stay within
// MaxBufferedReports. Surfaced in local status output so a long outage's cost
// is visible rather than silent.
func (o *Outbox) DroppedCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.Dropped
}

func (o *Outbox) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(o.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(outboxFile{Pending: o.Pending, Dropped: o.Dropped}, "", "  ")
	if err != nil {
		return err
	}
	tmp := o.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, o.path); err != nil {
		return fmt.Errorf("could not persist fleet outbox: %w", err)
	}
	return nil
}
