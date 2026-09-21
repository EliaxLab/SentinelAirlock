package index

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/review"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

type Entry struct {
	RunID         string `json:"run_id"`
	Timestamp     string `json:"timestamp"`
	Adapter       string `json:"adapter,omitempty"`
	Target        string `json:"target,omitempty"`
	Worker        string `json:"worker,omitempty"`
	Mode          string `json:"mode,omitempty"`
	PolicyPack    string `json:"policy_pack,omitempty"`
	Sandbox       string `json:"sandbox,omitempty"`
	Signed        bool   `json:"signed"`
	Verified      bool   `json:"verified"`
	Patch         bool   `json:"patch"`
	Export        bool   `json:"export"`
	ReviewState   string `json:"review_state,omitempty"`
	ReviewTS      string `json:"review_ts,omitempty"`
	Reviewer      string `json:"reviewer,omitempty"`
	HighRiskCount int    `json:"high_risk_count"`
	DeniedCount   int    `json:"denied_count"`
}

type Store struct {
	Updated string  `json:"updated"`
	Runs    []Entry `json:"runs"`
}

func DefaultPath() string { return filepath.Join(".airlock", "index.json") }

func Rebuild(runsRoot string) (Store, error) {
	store := Store{Updated: time.Now().UTC().Format(time.RFC3339), Runs: []Entry{}}
	ents, err := os.ReadDir(runsRoot)
	if err != nil {
		return store, err
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		runID := e.Name()
		mPath := filepath.Join(runsRoot, runID, "run_manifest.json")
		m, err := runmeta.Load(mPath)
		if err != nil {
			continue
		}
		evPath := filepath.Join(runsRoot, runID, "events.jsonl")
		evs, _ := events.ReadJSONL(evPath)
		ts := ""
		if len(evs) > 0 {
			ts = evs[0].TS.UTC().Format(time.RFC3339)
		}
		target := m.Execution.Target
		if target == "" {
			target = "local"
		}
		rev, _ := review.Load(filepath.Join(runsRoot, runID))
		vr, _ := runmeta.VerifyRun(runID, m)
		store.Runs = append(store.Runs, Entry{
			RunID:         runID,
			Timestamp:     ts,
			Adapter:       m.Adapter.Name,
			Target:        target,
			Worker:        m.Execution.WorkerName,
			Mode:          m.ExecutionMode,
			PolicyPack:    m.PolicyPack.Name,
			Sandbox:       m.Sandbox.Mode,
			Signed:        m.Digest.Signed,
			Verified:      vr.Verified,
			Patch:         m.PatchPath != "",
			Export:        m.Export.Path != "",
			ReviewState:   string(rev.State),
			ReviewTS:      rev.Timestamp,
			Reviewer:      rev.Reviewer,
			HighRiskCount: m.RiskSummary.HighCount,
			DeniedCount:   len(m.DeniedPaths) + m.ApprovalSummary.DeniedCount,
		})
	}
	sort.Slice(store.Runs, func(i, j int) bool { return store.Runs[i].Timestamp > store.Runs[j].Timestamp })
	return store, nil
}

func Save(path string, s Store) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func Load(path string) (Store, error) {
	var s Store
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}
