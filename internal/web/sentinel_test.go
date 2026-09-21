package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

func TestSentinelAPIInactiveWithoutLifecycleOrSessions(t *testing.T) {
	repo := t.TempDir()
	s := &Server{repoPath: repo, sentinelStatus: func() (SentinelProcess, bool, error) {
		return SentinelProcess{}, false, nil
	}}
	rr := requestServer(t, s, http.MethodGet, "/api/sentinel", "")
	var got sentinelResponse
	decodeResponse(t, rr, &got)
	if got.Running || got.State != "inactive" || got.Repo != repo || got.SessionID != "" {
		t.Fatalf("unexpected inactive response: %+v", got)
	}
}

func TestSentinelAPIRunningUsesLifecycleAndRealEvidence(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo with spaces")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC().Add(-90 * time.Second).Truncate(time.Second)
	evs := []events.Event{
		{TS: started, Type: "SENTINEL_START"},
		{TS: started.Add(time.Second), Type: "FILE_CREATE", Path: "status.txt", Summary: "workspace change", Approval: map[string]any{"decision": "allow"}},
		{TS: started.Add(2 * time.Second), Type: "POLICY_DENY", Path: ".env", Summary: "write blocked and reverted", Meta: map[string]any{"op": "WRITE", "reverted": true}, Approval: map[string]any{"decision": "deny"}},
		{TS: started.Add(3 * time.Second), Type: "POLICY_DENY", Path: "secrets/token.txt", Summary: "write blocked; revert failed", Meta: map[string]any{"op": "CREATE", "reverted": false, "revert_error": "permission denied"}, Approval: map[string]any{"decision": "deny"}},
		{TS: started.Add(4 * time.Second), Type: "FILE_WRITE", Path: ".airlock/index.json", Approval: map[string]any{"decision": "allow"}},
	}
	writeSessionFixture(t, repo, "sentinel-1", "running", "sentinel", evs)
	s := &Server{repoPath: repo, sentinelStatus: func() (SentinelProcess, bool, error) {
		return SentinelProcess{PID: 4242, Repo: repo, SessionID: "sentinel-1", StartedAt: started.Format(time.RFC3339), LogPath: filepath.Join(repo, ".airlock", "sentinel.log"), Background: true}, true, nil
	}}
	rr := requestServer(t, s, http.MethodGet, "/api/sentinel", "")
	var got sentinelResponse
	decodeResponse(t, rr, &got)
	if !got.Running || got.State != "active" || got.PID != 4242 || got.SessionID != "sentinel-1" || got.Repo != repo {
		t.Fatalf("unexpected active response: %+v", got)
	}
	if got.Uptime == "" || got.Policy.AllowRules != 2 || got.Policy.DenyRules != 2 {
		t.Fatalf("missing uptime/policy summary: %+v", got)
	}
	if len(got.Activity) != 3 {
		t.Fatalf("activity count=%d, want 3: %+v", len(got.Activity), got.Activity)
	}
	byPath := map[string]sentinelActivity{}
	for _, item := range got.Activity {
		byPath[item.Path] = item
		if strings.HasPrefix(item.Path, ".airlock/") || filepath.IsAbs(item.Path) {
			t.Fatalf("activity path is not a filtered repo-relative path: %q", item.Path)
		}
	}
	if byPath["status.txt"].Decision != "allow" {
		t.Fatalf("allowed mutation represented incorrectly: %+v", byPath["status.txt"])
	}
	if byPath[".env"].Decision != "deny" || byPath[".env"].RevertState != "reverted" {
		t.Fatalf("denied/reverted mutation represented incorrectly: %+v", byPath[".env"])
	}
	if byPath["secrets/token.txt"].RevertState != "failed" || byPath["secrets/token.txt"].RevertError == "" {
		t.Fatalf("revert failure represented incorrectly: %+v", byPath["secrets/token.txt"])
	}
}

func TestSentinelAPIStaleLifecycleIsNotActiveAndStoppedSessionRemains(t *testing.T) {
	repo := t.TempDir()
	started := time.Now().UTC().Add(-time.Hour)
	stopped := started.Add(10 * time.Minute)
	writeSessionFixture(t, repo, "sentinel-stopped", "stopped", "sentinel", []events.Event{
		{TS: started, Type: "SENTINEL_START"},
		{TS: stopped, Type: "SENTINEL_STOP"},
	})
	// running=false is what the CLI lifecycle validator returns after it detects
	// and cleans a stale PID.
	s := &Server{repoPath: repo, sentinelStatus: func() (SentinelProcess, bool, error) {
		return SentinelProcess{PID: 999999, Repo: repo, SessionID: "sentinel-stopped"}, false, nil
	}}
	rr := requestServer(t, s, http.MethodGet, "/api/sentinel", "")
	var got sentinelResponse
	decodeResponse(t, rr, &got)
	if got.Running || got.State != "stopped" || got.SessionID != "sentinel-stopped" || got.StoppedAt == "" {
		t.Fatalf("stale lifecycle was shown as active or history was lost: %+v", got)
	}
}

func TestSentinelAPISurfacesLifecycleAndEvidenceErrors(t *testing.T) {
	repo := t.TempDir()
	writeSessionFixture(t, repo, "bad-events", "stopped", "sentinel", nil)
	if err := os.WriteFile(filepath.Join(repo, ".airlock", "runs", "bad-events", "events.jsonl"), []byte("not json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{repoPath: repo, sentinelStatus: func() (SentinelProcess, bool, error) {
		return SentinelProcess{}, false, os.ErrInvalid
	}}
	rr := requestServer(t, s, http.MethodGet, "/api/sentinel", "")
	var got sentinelResponse
	decodeResponse(t, rr, &got)
	if got.Running || len(got.Errors) < 2 {
		t.Fatalf("expected recoverable lifecycle and evidence errors: %+v", got)
	}
}

func TestSentinelStopAPIUsesBoundRepoControllerAndIgnoresClientPID(t *testing.T) {
	repo := t.TempDir()
	writeSessionFixture(t, repo, "sentinel-live", "running", "sentinel", []events.Event{{TS: time.Now().UTC(), Type: "SENTINEL_START"}})
	running := true
	stopCalls := 0
	s := &Server{
		repoPath: repo,
		sentinelStatus: func() (SentinelProcess, bool, error) {
			return SentinelProcess{PID: 321, Repo: repo, SessionID: "sentinel-live", StartedAt: time.Now().UTC().Format(time.RFC3339)}, running, nil
		},
		sentinelStop: func() error {
			stopCalls++
			running = false
			return nil
		},
	}
	rr := requestServer(t, s, http.MethodPost, "/api/sentinel/stop?pid=987654&repo=/tmp/not-the-viewer-repo", `{"pid":123456}`)
	if rr.Code != http.StatusOK || stopCalls != 1 {
		t.Fatalf("stop status=%d calls=%d body=%s", rr.Code, stopCalls, rr.Body.String())
	}
	var got map[string]any
	decodeResponse(t, rr, &got)
	if stopped, _ := got["stopped"].(bool); !stopped {
		t.Fatalf("stop response did not confirm completion: %v", got)
	}
}

func TestSentinelStopAPIReadOnlyAndInactiveGuards(t *testing.T) {
	status := func() (SentinelProcess, bool, error) { return SentinelProcess{}, false, nil }
	for _, tc := range []struct {
		name string
		s    *Server
		want int
	}{
		{"read-only", &Server{readOnly: true, repoPath: t.TempDir(), sentinelStatus: status}, http.StatusForbidden},
		{"inactive", &Server{repoPath: t.TempDir(), sentinelStatus: status, sentinelStop: func() error { t.Fatal("stop called while inactive"); return nil }}, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := requestServer(t, tc.s, http.MethodPost, "/api/sentinel/stop", "")
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func TestSentinelStopAPISurfacesStopFailure(t *testing.T) {
	repo := t.TempDir()
	writeSessionFixture(t, repo, "sentinel-live", "running", "sentinel", []events.Event{{TS: time.Now().UTC(), Type: "SENTINEL_START"}})
	s := &Server{
		repoPath: repo,
		sentinelStatus: func() (SentinelProcess, bool, error) {
			return SentinelProcess{PID: 42, Repo: repo, SessionID: "sentinel-live"}, true, nil
		},
		sentinelStop: func() error { return os.ErrPermission },
	}
	rr := requestServer(t, s, http.MethodPost, "/api/sentinel/stop", "")
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), "permission denied") {
		t.Fatalf("stop failure status/details were unsafe: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSentinelActivityEndpointReflectsNewEvidence(t *testing.T) {
	repo := t.TempDir()
	now := time.Now().UTC()
	writeSessionFixture(t, repo, "sentinel-poll", "running", "sentinel", []events.Event{
		{TS: now, Type: "SENTINEL_START"},
	})
	s := &Server{repoPath: repo, sentinelStatus: func() (SentinelProcess, bool, error) {
		return SentinelProcess{PID: 9, Repo: repo, SessionID: "sentinel-poll", StartedAt: now.Format(time.RFC3339)}, true, nil
	}}
	first := requestServer(t, s, http.MethodGet, "/api/sentinel", "")
	var before sentinelResponse
	decodeResponse(t, first, &before)
	if len(before.Activity) != 0 {
		t.Fatalf("initial activity=%d, want 0", len(before.Activity))
	}
	eventsPath := filepath.Join(repo, ".airlock", "runs", "sentinel-poll", "events.jsonl")
	if err := events.AppendJSONLEvent(eventsPath, events.Event{TS: now.Add(time.Second), Type: "FILE_WRITE", Path: "src/app.ts", Approval: map[string]any{"decision": "allow"}}); err != nil {
		t.Fatal(err)
	}
	second := requestServer(t, s, http.MethodGet, "/api/sentinel", "")
	var after sentinelResponse
	decodeResponse(t, second, &after)
	if len(after.Activity) != 1 || after.Activity[0].Path != "src/app.ts" {
		t.Fatalf("refreshed activity did not include new evidence: %+v", after.Activity)
	}
}

func TestNormalizeSentinelActivityCoalescesUnresolvedMutationAndDeny(t *testing.T) {
	now := time.Now().UTC()
	got := normalizeSentinelActivity([]events.Event{
		{TS: now, Type: "FILE_WRITE", Path: ".env"},
		{TS: now.Add(time.Millisecond), Type: "POLICY_DENY", Path: ".env", Meta: map[string]any{"reverted": true, "op": "WRITE"}},
	}, 50)
	if len(got) != 1 || got[0].Decision != "deny" || got[0].RevertState != "reverted" {
		t.Fatalf("paired evidence was not normalized: %+v", got)
	}
}

func TestViewerLoadsWithoutSentinelAndIncludesLivePolling(t *testing.T) {
	repo := t.TempDir()
	withWorkingDir(t, repo)
	s := &Server{repoPath: repo}
	rr := requestServer(t, s, http.MethodGet, "/", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"Repository governance", "/api/sentinel", "setInterval(loadSentinel,2000)", "airlock sentinel --repo . --background"} {
		if !strings.Contains(body, want) {
			t.Fatalf("viewer missing %q", want)
		}
	}
}

func TestSentinelDetailGuardsActiveRollbackAndStoppedKeepsItAvailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		running bool
		status  string
		want    string
		notWant string
	}{
		{"active", true, "running", "Stop Sentinel before rollback", `id="rollback-btn"`},
		{"stopped", false, "stopped", `id="rollback-btn"`, "Stop Sentinel before rollback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			withWorkingDir(t, repo)
			writeSessionFixture(t, repo, "sentinel-detail", tc.status, "sentinel", []events.Event{{TS: time.Now().UTC(), Type: "SENTINEL_START"}})
			s := &Server{repoPath: repo, sentinelStatus: func() (SentinelProcess, bool, error) {
				return SentinelProcess{SessionID: "sentinel-detail", Repo: repo, PID: 22}, tc.running, nil
			}}
			rr := requestServer(t, s, http.MethodGet, "/runs/sentinel-detail", "")
			if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), tc.want) || strings.Contains(rr.Body.String(), tc.notWant) {
				t.Fatalf("unexpected detail view status=%d want=%q notWant=%q", rr.Code, tc.want, tc.notWant)
			}
			if tc.running {
				rb := requestServer(t, s, http.MethodPost, "/api/runs/sentinel-detail/rollback", "checkpoint=cp-0")
				if rb.Code != http.StatusSeeOther || !strings.Contains(rb.Header().Get("Location"), "Stop+Sentinel+before+rollback") {
					t.Fatalf("active rollback was not guarded: status=%d location=%q", rb.Code, rb.Header().Get("Location"))
				}
			}
		})
	}
}

func TestNonSentinelDetailAndPolicyPanelRemainUnchanged(t *testing.T) {
	repo := t.TempDir()
	withWorkingDir(t, repo)
	writeSessionFixture(t, repo, "normal-run", "success", "dev", []events.Event{{TS: time.Now().UTC(), Type: "RUN_START"}})
	s := &Server{repoPath: repo}
	rr := requestServer(t, s, http.MethodGet, "/runs/normal-run", "")
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, "Effective policy") || !strings.Contains(body, "Configured deny rules") || !strings.Contains(body, "Rollback available") {
		t.Fatalf("existing run detail regressed: status=%d body=%s", rr.Code, body)
	}
	if strings.Contains(body, "sentinel: active") || strings.Contains(body, "Stop Sentinel before rollback") {
		t.Fatalf("normal run was mislabeled as Sentinel")
	}
}

func writeSessionFixture(t *testing.T, repo, id, status, mode string, evs []events.Event) {
	t.Helper()
	runDir := filepath.Join(repo, ".airlock", "runs", id)
	if err := os.MkdirAll(filepath.Join(runDir, "checkpoints", "cp-0"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := runmeta.RunManifest{
		RunID: id, WorkspacePath: repo, ExecutionMode: mode,
		Adapter: runmeta.AdapterSummary{Name: map[bool]string{true: "sentinel", false: "generic-shell"}[mode == "sentinel"]},
		Sandbox: runmeta.SandboxInfo{Mode: map[bool]string{true: "off", false: "workspace"}[mode == "sentinel"]},
		Status:  runmeta.RunStatus{Terminal: status},
		PolicySummary: runmeta.PolicySummary{
			PolicyPath: filepath.Join(repo, "airlock.yaml"), AllowWrite: []string{"status.txt", "src/**"}, DenyWrite: []string{"**/.env", "secrets/**"},
		},
		PolicyPack:  runmeta.PolicyPackInfo{Name: "balanced"},
		Checkpoints: []runmeta.Checkpoint{{ID: "cp-0", Path: filepath.Join(runDir, "checkpoints", "cp-0")}},
	}
	if err := runmeta.Save(filepath.Join(runDir, "run_manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	eventsPath := filepath.Join(runDir, "events.jsonl")
	if err := os.WriteFile(eventsPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if err := events.AppendJSONLEvent(eventsPath, e); err != nil {
			t.Fatal(err)
		}
	}
}

func requestServer(t *testing.T, s *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	s.register(mux)
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if strings.Contains(body, "=") {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeResponse(t *testing.T, rr *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
}

func withWorkingDir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}
