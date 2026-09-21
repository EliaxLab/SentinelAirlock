package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/remote"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func workerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "worker", Short: "Remote worker controls"}
	cmd.AddCommand(workerStartCmd())
	cmd.AddCommand(workerDoctorCmd())
	cmd.AddCommand(workerConfigInitCmd())
	return cmd
}

func workerStartCmd() *cobra.Command {
	var (
		listen          string
		authToken       string
		workRoot        string
		workerName      string
		allowedAdapters []string
	)
	c := &cobra.Command{
		Use:   "start",
		Short: "Start remote worker server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(authToken) == "" {
				return fmt.Errorf("--auth-token is required")
			}
			if workerName == "" {
				h, _ := os.Hostname()
				workerName = h
			}
			if workRoot == "" {
				workRoot = filepath.Join(os.TempDir(), "airlock-worker")
			}
			if err := os.MkdirAll(workRoot, 0o755); err != nil {
				return err
			}
			allow := map[string]struct{}{}
			for _, a := range allowedAdapters {
				allow[strings.TrimSpace(a)] = struct{}{}
			}
			mux := http.NewServeMux()
			workerID := uuid.New().String()
			mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"ok": true, "worker_name": workerName, "worker_id": workerID})
			})
			mux.HandleFunc("/v1/run", func(w http.ResponseWriter, r *http.Request) {
				if !checkToken(r, authToken) {
					fmt.Printf("REMOTE_AUTH_DENY path=%s from=%s\n", r.URL.Path, r.RemoteAddr)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, 200<<20)
				if err := r.ParseMultipartForm(200 << 20); err != nil {
					fmt.Printf("REMOTE_ARTIFACT_INVALID path=%s reason=invalid_multipart\n", r.URL.Path)
					http.Error(w, "invalid multipart payload", http.StatusBadRequest)
					return
				}
				reqJSON := r.FormValue("request")
				if strings.TrimSpace(reqJSON) == "" {
					fmt.Printf("REMOTE_ARTIFACT_INVALID path=%s reason=missing_request\n", r.URL.Path)
					http.Error(w, "missing request field", http.StatusBadRequest)
					return
				}
				var req remote.RunRequest
				if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
					fmt.Printf("REMOTE_ARTIFACT_INVALID path=%s reason=invalid_request_json\n", r.URL.Path)
					http.Error(w, "invalid request json", http.StatusBadRequest)
					return
				}
				if req.RunID == "" {
					req.RunID = uuid.New().String()
				}
				if req.Adapter == "" {
					req.Adapter = "generic-shell"
				}
				if len(allow) > 0 {
					if _, ok := allow[req.Adapter]; !ok {
						fmt.Printf("REMOTE_AUTH_DENY path=%s reason=adapter_not_allowed adapter=%s\n", r.URL.Path, req.Adapter)
						http.Error(w, "adapter not allowed on worker", http.StatusForbidden)
						return
					}
				}
				f, _, err := r.FormFile("repo")
				if err != nil {
					fmt.Printf("REMOTE_ARTIFACT_INVALID path=%s reason=missing_repo\n", r.URL.Path)
					http.Error(w, "missing repo archive", http.StatusBadRequest)
					return
				}
				defer f.Close()
				jobRoot := filepath.Join(workRoot, "jobs", req.RunID)
				repoDir := filepath.Join(jobRoot, "repo")
				if err := os.MkdirAll(repoDir, 0o755); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if err := untarGz(f, repoDir); err != nil {
					fmt.Printf("REMOTE_ARTIFACT_INVALID path=%s reason=unpack_failed\n", r.URL.Path)
					http.Error(w, "failed to unpack repo", http.StatusBadRequest)
					return
				}

				bin, _ := os.Executable()
				runArgs := []string{"run", "--agent", req.Adapter, "--repo", ".", "--mode", req.Mode}
				if req.Cmd != "" {
					runArgs = append(runArgs, "--cmd", req.Cmd)
				}
				if req.Task != "" {
					runArgs = append(runArgs, "--task", req.Task)
				}
				if req.PolicyPath != "" {
					runArgs = append(runArgs, "--policy", req.PolicyPath)
				}
				if req.PolicyPack != "" {
					runArgs = append(runArgs, "--policy-pack", req.PolicyPack)
				}
				if req.Approval != "" {
					runArgs = append(runArgs, "--approval", req.Approval)
				}
				if req.Sandbox.Mode != "" {
					runArgs = append(runArgs, "--sandbox", req.Sandbox.Mode)
				}
				if req.Sandbox.Network != "" {
					runArgs = append(runArgs, "--network", req.Sandbox.Network)
				}
				if req.Sandbox.Image != "" {
					runArgs = append(runArgs, "--sandbox-image", req.Sandbox.Image)
				}
				if req.Sandbox.ContainerRunner != "" {
					runArgs = append(runArgs, "--container-runtime", req.Sandbox.ContainerRunner)
				}
				for _, d := range req.Sandbox.AllowDomains {
					runArgs = append(runArgs, "--allow-domain", d)
				}
				if len(req.Sandbox.AllowEnv) > 0 {
					runArgs = append(runArgs, "--allow-env", strings.Join(req.Sandbox.AllowEnv, ","))
				}

				runCmd := exec.Command(bin, runArgs...)
				runCmd.Dir = repoDir
				runCmd.Env = append(os.Environ(),
					"AIRLOCK_RUN_ID_FORCE="+req.RunID,
					"AIRLOCK_EXEC_TARGET=remote",
					"AIRLOCK_EXEC_WORKER_NAME="+workerName,
					"AIRLOCK_EXEC_WORKER_ID="+workerID,
					"AIRLOCK_SUBMITTED_BY="+req.SubmittedBy,
					"AIRLOCK_SOURCE_MACHINE="+req.SourceMachine,
				)
				out, err := runCmd.CombinedOutput()
				status := "ok"
				msg := strings.TrimSpace(string(out))
				if err != nil {
					status = "error"
				}
				runID := req.RunID
				if parsed := parseRunID(msg); parsed != "" {
					runID = parsed
				}
				runDir := filepath.Join(repoDir, ".airlock", "runs", runID)
				resp := remote.RunResponse{
					RunID:      runID,
					Status:     status,
					Message:    msg,
					WorkerName: workerName,
					WorkerID:   workerID,
					Artifacts: map[string]string{
						"run_dir":  runDir,
						"events":   filepath.Join(runDir, "events.jsonl"),
						"manifest": filepath.Join(runDir, "run_manifest.json"),
					},
				}
				if m, err := loadManifestIfExists(filepath.Join(runDir, "run_manifest.json")); err == nil {
					resp.Manifest = m
				}
				w.Header().Set("Content-Type", "application/json")
				if status != "ok" {
					w.WriteHeader(http.StatusBadRequest)
				}
				_ = json.NewEncoder(w).Encode(resp)
			})
			mux.HandleFunc("/v1/artifacts/", func(w http.ResponseWriter, r *http.Request) {
				if !checkToken(r, authToken) {
					fmt.Printf("REMOTE_AUTH_DENY path=%s from=%s\n", r.URL.Path, r.RemoteAddr)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				runID := strings.TrimPrefix(r.URL.Path, "/v1/artifacts/")
				if runID == "" || strings.Contains(runID, "/") {
					http.Error(w, "invalid run id", http.StatusBadRequest)
					return
				}
				runDir := filepath.Join(workRoot, "jobs", runID, "repo", ".airlock", "runs", runID)
				if _, err := os.Stat(runDir); err != nil {
					http.Error(w, "run not found", http.StatusNotFound)
					return
				}
				var buf bytes.Buffer
				if err := zipDir(&buf, runDir); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/zip")
				w.Header().Set("Content-Disposition", "attachment; filename=run-"+runID+".zip")
				_, _ = io.Copy(w, &buf)
			})

			srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			fmt.Println("Worker started")
			fmt.Printf("Listen: %s\n", listen)
			fmt.Printf("Worker: %s (%s)\n", workerName, workerID)
			fmt.Println("Auth: enabled (token required)")
			fmt.Printf("Allowed adapters: %s\n", strings.Join(allowedAdapters, ","))
			fmt.Printf("Work root: %s\n", workRoot)
			for _, rt := range []string{"docker", "colima", "podman"} {
				if p, err := exec.LookPath(rt); err == nil {
					fmt.Printf("Runtime available: %s (%s)\n", rt, p)
				}
			}
			return srv.ListenAndServe()
		},
	}
	c.Flags().StringVar(&listen, "listen", "127.0.0.1:8787", "Listen address")
	c.Flags().StringVar(&authToken, "auth-token", "", "Shared auth token")
	c.Flags().StringVar(&workRoot, "work-root", "", "Worker storage root")
	c.Flags().StringVar(&workerName, "worker-name", "", "Worker name")
	c.Flags().StringSliceVar(&allowedAdapters, "allow-adapter", []string{"generic-shell", "codex", "ollama"}, "Allowed adapters on worker")
	return c
}

func checkToken(r *http.Request, token string) bool {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "Bearer "+token {
		return true
	}
	return strings.TrimSpace(r.Header.Get("X-Airlock-Token")) == token
}

func parseRunID(output string) string {
	re := regexp.MustCompile(`Run ID:\s*([a-zA-Z0-9-]+)`)
	m := re.FindStringSubmatch(output)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func untarGz(r io.Reader, dst string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(hdr.Name)
		if strings.HasPrefix(name, "..") {
			continue
		}
		target := filepath.Join(dst, name)
		if hdr.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
}

func zipDir(w io.Writer, root string) error {
	zw := zip.NewWriter(w)
	defer zw.Close()
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		f, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		rf, err := os.Open(path)
		if err != nil {
			return err
		}
		defer rf.Close()
		_, err = io.Copy(f, rf)
		return err
	})
}

func loadManifestIfExists(path string) (*runmeta.RunManifest, error) {
	m, err := runmeta.Load(path)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func workerDoctorCmd() *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Check worker runtime prerequisites", RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Worker diagnostics")
		checkCommand("docker")
		checkCommand("colima")
		checkCommand("podman")
		checkSandboxSupport()
		return nil
	}}
}

func workerConfigInitCmd() *cobra.Command {
	var out string
	c := &cobra.Command{Use: "config init", Short: "Write sample worker config", RunE: func(cmd *cobra.Command, args []string) error {
		if out == "" {
			out = "airlock.worker.env"
		}
		body := "AIRLOCK_WORKER_LISTEN=127.0.0.1:8787\nAIRLOCK_WORKER_TOKEN=change-me\nAIRLOCK_WORKER_ROOT=/tmp/airlock-worker\nAIRLOCK_WORKER_NAME=worker-1\n"
		if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
			return err
		}
		fmt.Printf("Worker config template written: %s\n", out)
		return nil
	}}
	c.Flags().StringVar(&out, "out", "airlock.worker.env", "Output path")
	return c
}
