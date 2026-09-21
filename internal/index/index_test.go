package index

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/EliaxLab/SentinelAirlock/internal/review"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

func TestRebuildIncludesReviewState(t *testing.T) {
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	runID := "r1"
	runsRoot := filepath.Join(".airlock", "runs")
	runDir := filepath.Join(runsRoot, runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := runmeta.RunManifest{RunID: runID, Adapter: runmeta.AdapterSummary{Name: "generic-shell"}, Execution: runmeta.ExecutionInfo{Target: "local"}, Digest: runmeta.DigestInfo{Path: filepath.Join(runDir, "run_digest.json")}}
	if err := runmeta.Save(filepath.Join(runDir, "run_manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "events.jsonl"), []byte("{\"ts\":\"2026-01-01T00:00:00Z\",\"type\":\"RUN_START\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := runmeta.BuildDigest(runID, runDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := runmeta.SaveDigest(filepath.Join(runDir, "run_digest.json"), d); err != nil {
		t.Fatal(err)
	}
	if err := review.Save(runDir, review.Record{State: review.StateApproved, Reviewer: "t"}); err != nil {
		t.Fatal(err)
	}
	store, err := Rebuild(runsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Runs) != 1 {
		t.Fatalf("expected 1 run")
	}
	if store.Runs[0].ReviewState != "approved" {
		t.Fatalf("got %s", store.Runs[0].ReviewState)
	}
}
