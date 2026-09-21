package web

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

const sentinelActivityLimit = 50

// SentinelProcess is the small, trusted lifecycle record supplied by the CLI.
// It is never populated from browser input.
type SentinelProcess struct {
	PID        int
	Repo       string
	SessionID  string
	StartedAt  string
	LogPath    string
	Background bool
}

type SentinelStatusFunc func() (SentinelProcess, bool, error)
type SentinelStopFunc func() error

type sentinelPolicyResponse struct {
	Pack       string   `json:"pack,omitempty"`
	AllowRules int      `json:"allow_rules"`
	DenyRules  int      `json:"deny_rules"`
	AllowWrite []string `json:"allow_write,omitempty"`
	DenyWrite  []string `json:"deny_write,omitempty"`
	DenyRead   []string `json:"deny_read,omitempty"`
}

type sentinelActivity struct {
	Timestamp   string `json:"timestamp"`
	Path        string `json:"path"`
	Operation   string `json:"operation"`
	Decision    string `json:"decision"`
	RevertState string `json:"revert_state,omitempty"`
	RevertError string `json:"revert_error,omitempty"`
	Summary     string `json:"summary,omitempty"`
}

type sentinelResponse struct {
	Running       bool                   `json:"running"`
	State         string                 `json:"state"`
	Repo          string                 `json:"repo"`
	SessionID     string                 `json:"session_id,omitempty"`
	PID           int                    `json:"pid,omitempty"`
	StartedAt     string                 `json:"started_at,omitempty"`
	StoppedAt     string                 `json:"stopped_at,omitempty"`
	Uptime        string                 `json:"uptime,omitempty"`
	Mode          string                 `json:"mode"`
	Status        string                 `json:"status"`
	Enforcement   string                 `json:"enforcement"`
	Semantics     string                 `json:"semantics"`
	LogPath       string                 `json:"log_path,omitempty"`
	Background    bool                   `json:"background,omitempty"`
	Policy        sentinelPolicyResponse `json:"policy"`
	Activity      []sentinelActivity     `json:"recent_activity"`
	ActivityCount int                    `json:"activity_count"`
	Errors        []string               `json:"errors,omitempty"`
	PollSeconds   int                    `json:"poll_interval_sec"`
	ReadOnly      bool                   `json:"read_only"`
}

type sentinelSessionData struct {
	manifest runmeta.RunManifest
	events   []events.Event
	started  time.Time
	stopped  time.Time
}

func (s *Server) handleAPISentinel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.sentinelSnapshot())
}

func (s *Server) handleAPISentinelStop(w http.ResponseWriter, r *http.Request) {
	if s.readOnly {
		http.Error(w, "read-only", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	before := s.sentinelSnapshot()
	if !before.Running {
		http.Error(w, "Sentinel is not running for this repository", http.StatusConflict)
		return
	}
	if s.sentinelStop == nil {
		http.Error(w, "Sentinel stop is unavailable in this viewer", http.StatusServiceUnavailable)
		return
	}
	// Deliberately ignore the request body and query string. The callback is
	// bound to the viewer's resolved repository and resolves its own PID.
	if err := s.sentinelStop(); err != nil {
		log.Printf("web: sentinel stop failed for repo %s: %v", s.repoPath, err)
		http.Error(w, "Sentinel could not be stopped cleanly. Check the viewer log and try the CLI stop command.", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"stopped": true, "sentinel": s.sentinelSnapshot()})
}

func (s *Server) sentinelSnapshot() sentinelResponse {
	resp := sentinelResponse{
		State:       "inactive",
		Repo:        s.repoPath,
		Mode:        "sentinel",
		Status:      "Not running",
		Enforcement: "Detect → Evaluate → Revert",
		Semantics:   "Best-effort filesystem governance. Changes are observed after the OS accepts them.",
		Activity:    []sentinelActivity{},
		PollSeconds: 2,
		ReadOnly:    s.readOnly,
	}

	var proc SentinelProcess
	if s.sentinelStatus != nil {
		var err error
		proc, resp.Running, err = s.sentinelStatus()
		if err != nil {
			log.Printf("web: sentinel lifecycle read failed for repo %s: %v", s.repoPath, err)
			resp.Errors = append(resp.Errors, "Sentinel lifecycle metadata could not be read. Check the viewer log or run `airlock sentinel --repo . --status`.")
		}
	}

	var data sentinelSessionData
	var sessionErr error
	if resp.Running {
		resp.State = "active"
		resp.Status = "Persistent monitoring"
		resp.PID = proc.PID
		resp.SessionID = proc.SessionID
		resp.StartedAt = proc.StartedAt
		resp.LogPath = proc.LogPath
		resp.Background = proc.Background
		if proc.Repo != "" {
			resp.Repo = proc.Repo
		}
		if started, err := time.Parse(time.RFC3339, proc.StartedAt); err == nil {
			resp.Uptime = formatClockUptime(time.Since(started))
		}
		data, sessionErr = loadSentinelSession(s.repoPath, proc.SessionID)
	} else {
		data, sessionErr = latestSentinelSession(s.repoPath)
		if sessionErr == nil && data.manifest.RunID != "" {
			resp.SessionID = data.manifest.RunID
			resp.StartedAt = formatOptionalTime(data.started)
			resp.StoppedAt = formatOptionalTime(data.stopped)
			if data.manifest.Status.Terminal == "stopped" || !data.stopped.IsZero() {
				resp.State = "stopped"
				resp.Status = "Most recent session stopped"
			}
		}
	}
	if sessionErr != nil {
		log.Printf("web: sentinel evidence unavailable for repo %s session %s: %v", s.repoPath, resp.SessionID, sessionErr)
		resp.Errors = append(resp.Errors, "Sentinel evidence is unavailable or malformed. Raw artifacts remain on disk for CLI inspection.")
		return resp
	}
	if data.manifest.RunID == "" {
		return resp
	}

	resp.Policy = sentinelPolicyResponse{
		Pack:       data.manifest.PolicyPack.Name,
		AllowRules: len(data.manifest.PolicySummary.AllowWrite),
		DenyRules:  len(data.manifest.PolicySummary.DenyWrite),
		AllowWrite: append([]string(nil), data.manifest.PolicySummary.AllowWrite...),
		DenyWrite:  append([]string(nil), data.manifest.PolicySummary.DenyWrite...),
		DenyRead:   append([]string(nil), data.manifest.PolicySummary.DenyRead...),
	}
	resp.Activity = normalizeSentinelActivity(data.events, sentinelActivityLimit)
	resp.ActivityCount = len(resp.Activity)
	return resp
}

func loadSentinelSession(repoPath, sessionID string) (sentinelSessionData, error) {
	if sessionID == "" || filepath.Base(sessionID) != sessionID {
		return sentinelSessionData{}, fmt.Errorf("invalid sentinel session id")
	}
	runDir := filepath.Join(repoPath, ".airlock", "runs", sessionID)
	m, err := runmeta.Load(filepath.Join(runDir, "run_manifest.json"))
	if err != nil {
		return sentinelSessionData{}, fmt.Errorf("load sentinel manifest: %w", err)
	}
	if m.ExecutionMode != "sentinel" {
		return sentinelSessionData{}, fmt.Errorf("session %s is not a sentinel session", sessionID)
	}
	if filepath.Clean(m.WorkspacePath) != filepath.Clean(repoPath) {
		return sentinelSessionData{}, fmt.Errorf("sentinel manifest repository does not match viewer repository")
	}
	evs, err := events.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
	if err != nil {
		return sentinelSessionData{}, fmt.Errorf("load sentinel events: %w", err)
	}
	data := sentinelSessionData{manifest: m, events: evs}
	for _, e := range evs {
		switch e.Type {
		case "SENTINEL_START":
			if data.started.IsZero() {
				data.started = e.TS
			}
		case "SENTINEL_STOP":
			data.stopped = e.TS
		}
	}
	return data, nil
}

func latestSentinelSession(repoPath string) (sentinelSessionData, error) {
	runsDir := filepath.Join(repoPath, ".airlock", "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return sentinelSessionData{}, nil
		}
		return sentinelSessionData{}, err
	}
	type candidate struct {
		id      string
		updated time.Time
	}
	var candidates []candidate
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(runsDir, entry.Name(), "run_manifest.json")
		m, loadErr := runmeta.Load(manifestPath)
		if loadErr != nil {
			continue
		}
		if m.ExecutionMode != "sentinel" {
			continue
		}
		updated := time.Time{}
		if info, statErr := os.Stat(manifestPath); statErr == nil {
			updated = info.ModTime()
		}
		candidates = append(candidates, candidate{id: entry.Name(), updated: updated})
	}
	if len(candidates) == 0 {
		return sentinelSessionData{}, nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].updated.After(candidates[j].updated) })
	return loadSentinelSession(repoPath, candidates[0].id)
}

func normalizeSentinelActivity(evs []events.Event, limit int) []sentinelActivity {
	items := make([]sentinelActivity, 0)
	type unresolvedMutation struct {
		index int
		ts    time.Time
	}
	lastUnresolved := map[string]unresolvedMutation{}
	for _, e := range evs {
		path := filepath.ToSlash(strings.TrimPrefix(e.Path, "./"))
		if path == "" || path == ".airlock" || strings.HasPrefix(path, ".airlock/") {
			continue
		}
		switch e.Type {
		case "FILE_CREATE", "FILE_WRITE", "FILE_REMOVE", "FILE_RENAME":
			decision, _ := e.Approval["decision"].(string)
			if decision == "" {
				decision = "allow"
			}
			items = append(items, sentinelActivity{
				Timestamp: e.TS.UTC().Format(time.RFC3339Nano), Path: path,
				Operation: strings.TrimPrefix(e.Type, "FILE_"), Decision: strings.ToLower(decision), Summary: e.Summary,
			})
			if _, explicit := e.Approval["decision"]; !explicit {
				lastUnresolved[path] = unresolvedMutation{index: len(items) - 1, ts: e.TS}
			}
		case "POLICY_DENY", "APPROVAL_REQUIRED":
			op, _ := e.Meta["op"].(string)
			op = normalizeSentinelOperation(op)
			item := sentinelActivity{
				Timestamp: e.TS.UTC().Format(time.RFC3339Nano), Path: path,
				Operation: op, Decision: "deny", Summary: e.Summary,
			}
			if reverted, ok := e.Meta["reverted"].(bool); ok {
				if reverted {
					item.RevertState = "reverted"
				} else {
					item.RevertState = "failed"
				}
			}
			if revertErr, ok := e.Meta["revert_error"].(string); ok && revertErr != "" {
				item.RevertState = "failed"
				item.RevertError = revertErr
			}
			if unresolved, ok := lastUnresolved[path]; ok && !e.TS.Before(unresolved.ts) && e.TS.Sub(unresolved.ts) <= time.Second {
				items[unresolved.index] = item
				delete(lastUnresolved, path)
			} else {
				items = append(items, item)
			}
		}
	}
	// The operator cares about what happened most recently. Preserve evidence
	// order internally, then reverse only the normalized presentation.
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func normalizeSentinelOperation(op string) string {
	op = strings.ToUpper(strings.TrimSpace(op))
	for _, candidate := range []string{"CREATE", "WRITE", "REMOVE", "RENAME"} {
		if strings.Contains(op, candidate) {
			return candidate
		}
	}
	if op == "" {
		return "WRITE"
	}
	return op
}

func formatClockUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	seconds := int64(d.Round(time.Second) / time.Second)
	return fmt.Sprintf("%02d:%02d:%02d", seconds/3600, (seconds%3600)/60, seconds%60)
}

func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (s *Server) sentinelRollbackBlocked(m runmeta.RunManifest) bool {
	if m.ExecutionMode != "sentinel" {
		return false
	}
	if s.sentinelStatus == nil {
		return m.Status.Terminal == "running"
	}
	proc, running, err := s.sentinelStatus()
	if err != nil {
		// If lifecycle state is unreadable, do not risk rolling back a manifest
		// that still says its watcher is running.
		return m.Status.Terminal == "running"
	}
	return running && proc.SessionID == m.RunID
}
