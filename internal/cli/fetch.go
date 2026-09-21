package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/spf13/cobra"
)

func fetchCmd() *cobra.Command {
	var (
		workerURL string
		authToken string
		printSrc  bool
	)
	c := &cobra.Command{
		Use:   "fetch <run_id>",
		Short: "Fetch remote run artifacts into local .airlock/runs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]
			if workerURL == "" {
				workerURL = lookupWorker(runID)
			}
			if workerURL == "" {
				return fmt.Errorf("worker URL required (--worker) or known submission")
			}
			if authToken == "" {
				return fmt.Errorf("--auth-token is required")
			}
			if printSrc {
				fmt.Printf("Fetch source: worker=%s run_id=%s\n", workerURL, runID)
			}
			req, err := http.NewRequest(http.MethodGet, strings.TrimRight(workerURL, "/")+"/v1/artifacts/"+runID, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+authToken)
			req.Header.Set("X-Airlock-Token", authToken)
			resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 300 {
				b, _ := io.ReadAll(resp.Body)
				if resp.StatusCode == http.StatusUnauthorized {
					return fmt.Errorf("remote auth denied: check --auth-token for worker %s", workerURL)
				}
				return fmt.Errorf("remote fetch failed (%s): %s", resp.Status, strings.TrimSpace(string(b)))
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			dst := filepath.Join(".airlock", "runs", runID)
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			if err := unzipBytes(b, dst); err != nil {
				return err
			}
			if err := appendRemoteFetchEvent(runID, workerURL); err != nil {
				return err
			}
			refreshIndex()
			fmt.Println("Remote fetch complete")
			fmt.Printf("Run ID: %s\n", runID)
			fmt.Printf("Source worker: %s\n", workerURL)
			fmt.Printf("Local artifacts: %s\n", dst)
			return nil
		},
	}
	c.Flags().StringVar(&workerURL, "worker", "", "Worker base URL")
	c.Flags().StringVar(&authToken, "auth-token", "", "Shared auth token")
	c.Flags().BoolVar(&printSrc, "print-source", false, "Print source worker before fetching")
	return c
}

func unzipBytes(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		outPath := filepath.Join(dst, filepath.Clean(f.Name))
		if strings.HasSuffix(f.Name, "/") {
			if err := os.MkdirAll(outPath, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		wf, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(wf, rc); err != nil {
			wf.Close()
			rc.Close()
			return err
		}
		wf.Close()
		rc.Close()
	}
	return nil
}

func lookupWorker(runID string) string {
	p := filepath.Join(".airlock", "remote-submissions", runID+".json")
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var payload map[string]string
	if json.Unmarshal(b, &payload) != nil {
		return ""
	}
	return strings.TrimSpace(payload["worker"])
}

func appendRemoteFetchEvent(runID, worker string) error {
	path := filepath.Join(".airlock", "runs", runID, "events.jsonl")
	log, err := events.NewLogger(path)
	if err != nil {
		return err
	}
	defer log.Close()
	log.Add(events.Event{TS: time.Now().UTC(), Type: "REMOTE_FETCH", Summary: "remote artifacts fetched", Meta: map[string]any{"worker": worker}})
	return nil
}
