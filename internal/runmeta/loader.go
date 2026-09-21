package runmeta

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/session"
)

// ResolveRunID resolves "latest" to the most recently modified run directory.
// Any other value is returned unchanged.
func ResolveRunID(runID string) (string, error) {
	if runID != "latest" {
		return runID, nil
	}
	runsDir := filepath.Join(".airlock", "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve 'latest': no .airlock/runs directory found")
	}
	type dirEntry struct {
		name  string
		mtime time.Time
	}
	var dirs []dirEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		dirs = append(dirs, dirEntry{name: e.Name(), mtime: info.ModTime()})
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("no runs found in %s — run 'airlock run' first", runsDir)
	}
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].mtime.After(dirs[j].mtime)
	})
	return dirs[0].name, nil
}

type Artifacts struct {
	RunID             string
	RunDir            string
	ManifestPath      string
	EventsPath        string
	SessionEventsPath string
	PatchPath         string
	ReportPath        string
	Manifest          RunManifest
	Events            []events.Event
	SessionEvents     []session.Event
}

func LoadArtifacts(runID string) (Artifacts, error) {
	resolved, err := ResolveRunID(runID)
	if err != nil {
		return Artifacts{}, err
	}
	runID = resolved
	runDir := filepath.Join(".airlock", "runs", runID)
	manifestPath := filepath.Join(runDir, "run_manifest.json")
	eventsPath := filepath.Join(runDir, "events.jsonl")
	sessionEventsPath := filepath.Join(runDir, "session_events.jsonl")
	reportPath := filepath.Join(runDir, "report", "index.html")

	m, err := Load(manifestPath)
	if err != nil {
		return Artifacts{}, err
	}
	evs, err := events.ReadJSONL(eventsPath)
	if err != nil {
		return Artifacts{}, err
	}
	sessionEvs := []session.Event{}
	if Exists(sessionEventsPath) {
		sessionEvs, err = session.ReadJSONL(sessionEventsPath)
		if err != nil {
			return Artifacts{}, err
		}
	}

	patchPath := m.PatchPath
	if patchPath == "" {
		patchPath = filepath.Join(runDir, "changes.patch")
	}

	return Artifacts{
		RunID:             runID,
		RunDir:            runDir,
		ManifestPath:      manifestPath,
		EventsPath:        eventsPath,
		SessionEventsPath: sessionEventsPath,
		PatchPath:         patchPath,
		ReportPath:        reportPath,
		Manifest:          m,
		Events:            evs,
		SessionEvents:     sessionEvs,
	}, nil
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
