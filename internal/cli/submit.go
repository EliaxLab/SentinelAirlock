package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/remote"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func submitCmd() *cobra.Command {
	var (
		target           string
		workerURL        string
		authToken        string
		repoPath         string
		agent            string
		cmdStr           string
		task             string
		policyPack       string
		policyPath       string
		approval         string
		executionMode    string
		sandboxMode      string
		networkMode      string
		allowEnvCSV      string
		containerRuntime string
		allowDomains     []string
		printRequest     bool
	)
	c := &cobra.Command{
		Use:   "submit",
		Short: "Submit a run to local or remote target",
		RunE: func(cmd *cobra.Command, args []string) error {
			target = defaultString(target, "remote")
			repoPath = defaultString(repoPath, ".")
			agent = defaultString(agent, "generic-shell")
			executionMode = defaultString(executionMode, "dev")
			sandboxMode = defaultString(sandboxMode, "workspace")
			networkMode = defaultString(networkMode, "off")
			approval = defaultString(approval, "auto")

			if target == "local" {
				args := []string{"run", "--repo", repoPath, "--agent", agent, "--mode", executionMode, "--sandbox", sandboxMode, "--network", networkMode, "--approval", approval}
				if cmdStr != "" {
					args = append(args, "--cmd", cmdStr)
				}
				if task != "" {
					args = append(args, "--task", task)
				}
				if policyPack != "" {
					args = append(args, "--policy-pack", policyPack)
				}
				if policyPath != "" {
					args = append(args, "--policy", policyPath)
				}
				if allowEnvCSV != "" {
					args = append(args, "--allow-env", allowEnvCSV)
				}
				if containerRuntime != "" {
					args = append(args, "--container-runtime", containerRuntime)
				}
				for _, d := range allowDomains {
					args = append(args, "--allow-domain", d)
				}
				bin, _ := os.Executable()
				p := exec.Command(bin, args...)
				p.Stdout = os.Stdout
				p.Stderr = os.Stderr
				return p.Run()
			}

			if workerURL == "" {
				return fmt.Errorf("--worker is required for remote target")
			}
			if authToken == "" {
				return fmt.Errorf("--auth-token is required for remote target")
			}

			runID := uuid.New().String()
			req := remote.RunRequest{
				RunID:         runID,
				Adapter:       agent,
				Cmd:           cmdStr,
				Task:          task,
				PolicyPack:    policyPack,
				PolicyPath:    policyPath,
				Approval:      approval,
				Mode:          executionMode,
				SubmittedBy:   os.Getenv("USER"),
				SourceMachine: hostName(),
				Sandbox: remote.SandboxSettings{
					Mode:            sandboxMode,
					Network:         networkMode,
					AllowDomains:    allowDomains,
					AllowEnv:        parseCSV(allowEnvCSV),
					ContainerRunner: containerRuntime,
				},
			}
			if printRequest {
				b, _ := json.MarshalIndent(req, "", "  ")
				fmt.Println("Run request")
				fmt.Println(string(b))
				if target == "remote" && cmdStr == "" && task == "" {
					return nil
				}
			}
			buf := &bytes.Buffer{}
			mw := multipart.NewWriter(buf)
			reqBytes, _ := json.Marshal(req)
			if err := mw.WriteField("request", string(reqBytes)); err != nil {
				return err
			}
			fw, err := mw.CreateFormFile("repo", "repo.tar.gz")
			if err != nil {
				return err
			}
			if err := writeRepoArchive(fw, repoPath); err != nil {
				return err
			}
			if err := mw.Close(); err != nil {
				return err
			}

			httpReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(workerURL, "/")+"/v1/run", buf)
			if err != nil {
				return err
			}
			httpReq.Header.Set("Content-Type", mw.FormDataContentType())
			httpReq.Header.Set("Authorization", "Bearer "+authToken)
			httpReq.Header.Set("X-Airlock-Token", authToken)

			resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(httpReq)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == http.StatusUnauthorized {
				return fmt.Errorf("remote auth denied: check --auth-token for worker %s", workerURL)
			}
			if resp.StatusCode == http.StatusRequestEntityTooLarge {
				return fmt.Errorf("remote rejected oversized request: reduce repo payload or excludes")
			}
			if resp.StatusCode >= 300 {
				return fmt.Errorf("remote submit failed (%s): %s", resp.Status, strings.TrimSpace(string(body)))
			}
			var rr remote.RunResponse
			if err := json.Unmarshal(body, &rr); err != nil {
				return err
			}
			fmt.Println("Remote submit complete")
			fmt.Printf("Run ID: %s\n", rr.RunID)
			fmt.Printf("Worker: %s\n", workerURL)
			fmt.Printf("Status: %s\n", rr.Status)
			if rr.Message != "" {
				fmt.Printf("Message: %s\n", rr.Message)
			}
			if err := saveRemoteSubmission(rr.RunID, workerURL); err != nil {
				return err
			}
			return nil
		},
	}
	c.Flags().StringVar(&target, "target", "remote", "Execution target: local | remote")
	c.Flags().StringVar(&workerURL, "worker", "", "Worker base URL for remote runs")
	c.Flags().StringVar(&authToken, "auth-token", "", "Shared auth token for worker")
	c.Flags().StringVar(&repoPath, "repo", ".", "Path to repo/workdir")
	c.Flags().StringVar(&agent, "agent", "generic-shell", "Adapter name")
	c.Flags().StringVar(&cmdStr, "cmd", "", "Agent command (generic-shell)")
	c.Flags().StringVar(&task, "task", "", "Optional task")
	c.Flags().StringVar(&policyPack, "policy-pack", "", "Policy pack")
	c.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path")
	c.Flags().StringVar(&approval, "approval", "auto", "Approval mode")
	c.Flags().StringVar(&executionMode, "mode", "dev", "Execution mode")
	c.Flags().StringVar(&sandboxMode, "sandbox", "workspace", "Sandbox mode")
	c.Flags().StringVar(&networkMode, "network", "off", "Network mode")
	c.Flags().StringVar(&allowEnvCSV, "allow-env", "", "Env allowlist CSV")
	c.Flags().StringVar(&containerRuntime, "container-runtime", "", "Container runtime")
	c.Flags().StringSliceVar(&allowDomains, "allow-domain", nil, "Allowed domains")
	c.Flags().BoolVar(&printRequest, "print-request", false, "Print remote run request payload")
	return c
}

func writeRepoArchive(w io.Writer, repoPath string) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	return filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(repoPath, path)
		if rel == "." {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if strings.HasPrefix(relSlash, ".git/") || strings.HasPrefix(relSlash, ".airlock/") || strings.HasPrefix(relSlash, "node_modules/") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = relSlash
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

func saveRemoteSubmission(runID, worker string) error {
	root := filepath.Join(".airlock", "remote-submissions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	payload := map[string]string{"run_id": runID, "worker": worker, "saved": time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.MarshalIndent(payload, "", "  ")
	return os.WriteFile(filepath.Join(root, runID+".json"), b, 0o644)
}

func hostName() string {
	h, _ := os.Hostname()
	if h != "" {
		return h
	}
	return runtime.GOOS
}

func defaultString(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
