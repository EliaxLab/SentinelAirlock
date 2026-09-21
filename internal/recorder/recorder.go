package recorder

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/governance"
	"github.com/EliaxLab/SentinelAirlock/internal/policy"
	"github.com/fsnotify/fsnotify"
	"github.com/sergi/go-diff/diffmatchpatch"
)

type Recorder struct {
	root         string
	cfg          atomic.Pointer[policy.Config] // see SetPolicy: hot-swappable for live Fleet policy reconciliation
	log          *events.Logger
	approvalMode governance.ApprovalMode
	debounce     time.Duration // 0 = evaluate immediately (airlock run); >0 = coalesce rapid per-path events (Sentinel)

	w      *fsnotify.Watcher
	stopCh chan struct{}
	wg     sync.WaitGroup

	mu            sync.Mutex
	lastBytes     map[string][]byte
	suppressUntil map[string]time.Time
	pending       map[string]*time.Timer // debounce mode only
	pendingWG     sync.WaitGroup
}

// New creates a Recorder that evaluates every filesystem event immediately,
// synchronously with the triggering fsnotify event. This is what `airlock
// run` needs: a single short-lived command completes and calls Stop() right
// after, so revert decisions must not be deferred behind a timer.
func New(root string, log *events.Logger, cfg *policy.Config, approvalMode governance.ApprovalMode) (*Recorder, error) {
	return newRecorder(root, log, cfg, approvalMode, 0)
}

// NewDebounced is like New but coalesces rapid-fire fsnotify events for the
// same path within debounce into a single evaluation of the settled state.
// Intended for long-running sessions (Sentinel) watching real editor/IDE
// activity, where an atomic save (temp-file write + rename) or a burst of
// consecutive writes to one path would otherwise generate multiple redundant
// evaluations/events for what is really one logical change.
func NewDebounced(root string, log *events.Logger, cfg *policy.Config, approvalMode governance.ApprovalMode, debounce time.Duration) (*Recorder, error) {
	return newRecorder(root, log, cfg, approvalMode, debounce)
}

func newRecorder(root string, log *events.Logger, cfg *policy.Config, approvalMode governance.ApprovalMode, debounce time.Duration) (*Recorder, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	r := &Recorder{
		root:          root,
		log:           log,
		approvalMode:  approvalMode,
		debounce:      debounce,
		w:             w,
		stopCh:        make(chan struct{}),
		lastBytes:     map[string][]byte{},
		suppressUntil: map[string]time.Time{},
		pending:       map[string]*time.Timer{},
	}
	r.cfg.Store(cfg)
	return r, nil
}

// SetPolicy atomically swaps the policy config the recorder enforces on every
// subsequent evaluation. Safe to call concurrently with the watch loop (and
// with debounced evaluations running on their own timer goroutines): reads
// use the same atomic.Pointer, so an in-flight evaluate() sees either the
// old or the new config in full, never a partially-updated one. This is what
// makes Fleet policy reconciliation (internal/cli/sentinel.go) take effect
// on real enforcement immediately, rather than only updating what Sentinel
// reports about itself.
func (r *Recorder) SetPolicy(cfg *policy.Config) {
	r.cfg.Store(cfg)
}

// Seed populates the before-state cache from the current on-disk content of
// every non-ignored file under root, before any watching starts. Without
// this, a file that already existed when the recorder started has no cached
// "before" — so a later denied write to it would be reverted by deleting it
// instead of restoring its real prior content (the zero-value cache is only
// correct for files the recorder itself later observes being created).
// Best-effort: a file that can't be read simply starts with no baseline,
// matching prior behavior for that one path.
func (r *Recorder) Seed() error {
	return filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := filepath.ToSlash(mustRel(r.root, path))
		if rel == "." {
			return nil
		}
		if r.shouldIgnore(rel, d.IsDir()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		r.setLast(rel, b)
		return nil
	})
}

func (r *Recorder) Start() error {
	// add watchers recursively
	if err := filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := filepath.ToSlash(mustRel(r.root, path))
		if rel != "." && r.shouldIgnore(rel, d.IsDir()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			_ = r.w.Add(path)
		}
		return nil
	}); err != nil {
		return err
	}

	r.wg.Add(1)
	go r.loop()
	return nil
}

func (r *Recorder) Stop() error {
	close(r.stopCh)
	r.wg.Wait()
	r.pendingWG.Wait() // let any in-flight/scheduled debounced evaluations finish first
	return r.w.Close()
}

func (r *Recorder) loop() {
	defer r.wg.Done()

	for {
		select {
		case <-r.stopCh:
			return
		case ev, ok := <-r.w.Events:
			if !ok {
				return
			}
			// Handle new dirs to watch
			if ev.Op&fsnotify.Create == fsnotify.Create {
				if st, err := os.Stat(ev.Name); err == nil && st.IsDir() {
					_ = r.w.Add(ev.Name)
					continue
				}
			}

			rel := filepath.ToSlash(mustRel(r.root, ev.Name))
			if rel == "." || rel == "" {
				continue
			}
			if r.shouldIgnore(rel, false) {
				continue
			}
			if r.isSuppressed(rel) {
				continue
			}

			// Record create/write/rename/remove for v0.
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}

			if r.debounce > 0 {
				r.scheduleEvaluate(rel, ev.Op)
			} else {
				r.evaluate(rel, ev.Op)
			}
		case err, ok := <-r.w.Errors:
			if !ok {
				return
			}
			r.log.Add(events.Event{
				TS:      time.Now().UTC(),
				Type:    "RECORDER_ERROR",
				Summary: err.Error(),
			})
		}
	}
}

// scheduleEvaluate coalesces rapid-fire events for the same path: a new event
// within the debounce window cancels and replaces any pending timer for that
// path, so only the settled state after the burst gets evaluated once. This
// is what absorbs editor atomic-save (temp-write + rename) and multi-syscall
// write patterns into one logical evaluation instead of several redundant
// ones — see NewDebounced's doc comment.
func (r *Recorder) scheduleEvaluate(rel string, op fsnotify.Op) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.pending[rel]; ok {
		if t.Stop() {
			// Cancelled before it fired: it will never call Done() itself.
			r.pendingWG.Done()
		}
		delete(r.pending, rel)
	}
	r.pendingWG.Add(1)
	r.pending[rel] = time.AfterFunc(r.debounce, func() {
		r.mu.Lock()
		delete(r.pending, rel)
		r.mu.Unlock()
		defer r.pendingWG.Done()
		r.evaluate(rel, op)
	})
}

// evaluate reads the current on-disk state for rel, classifies it against
// policy, and either records the allowed mutation or reverts and records the
// denied one. In immediate mode (debounce=0) this runs synchronously inline
// with the triggering fsnotify event, identical to the original
// implementation. In debounced mode it runs once the path has settled.
func (r *Recorder) evaluate(rel string, op fsnotify.Op) {
	full := filepath.Join(r.root, filepath.FromSlash(rel))
	dmp := diffmatchpatch.New()

	before := r.getLast(rel)
	after, _ := os.ReadFile(full) // if removed, read fails -> empty

	assessment := governance.ClassifyFilesystem(rel, opName(op), r.cfg.Load())
	approvalDecision := governance.Decide(r.approvalMode, assessment)
	if approvalDecision != governance.DecisionAllow {
		// compute attempted diff for logging
		diffText := ""
		patches := dmp.PatchMake(string(before), string(after))
		if len(patches) > 0 {
			diffText = dmp.PatchToText(patches)
		}

		// revert: restore previous bytes if existed, else delete newly created file
		r.markSuppress(rel, 500*time.Millisecond)
		var revertErr error
		if len(before) > 0 {
			revertErr = os.WriteFile(full, before, 0o644)
		} else {
			revertErr = os.Remove(full)
			if os.IsNotExist(revertErr) {
				revertErr = nil // already gone; nothing to revert
			}
		}

		// keep cache as "before"
		r.setLast(rel, before)

		evType := "POLICY_DENY"
		summary := "write blocked and reverted"
		if approvalDecision == governance.DecisionPrompt {
			evType = "APPROVAL_REQUIRED"
			summary = "write requires approval and was reverted"
		}
		meta := map[string]any{
			"op":       op.String(),
			"reverted": revertErr == nil,
		}
		if revertErr != nil {
			meta["revert_error"] = revertErr.Error()
			summary = "write blocked; revert failed"
		}
		r.log.Add(events.Event{
			TS:      time.Now().UTC(),
			Type:    evType,
			Path:    rel,
			Summary: summary,
			Diff:    diffText,
			Meta:    meta,
			Risk: map[string]any{
				"level":    string(assessment.Level),
				"category": string(assessment.Category),
				"reason":   assessment.Reason,
			},
			Approval: map[string]any{
				"mode":     string(r.approvalMode),
				"decision": string(approvalDecision),
			},
		})
		return
	}

	// allowed: update cache normally
	r.setLast(rel, after)

	diffText := ""
	patches := dmp.PatchMake(string(before), string(after))
	if len(patches) > 0 {
		diffText = dmp.PatchToText(patches)
	}

	r.log.Add(events.Event{
		TS:      time.Now().UTC(),
		Type:    eventType(op),
		Path:    rel,
		Summary: "workspace change",
		Diff:    diffText,
		Risk: map[string]any{
			"level":    string(assessment.Level),
			"category": string(assessment.Category),
			"reason":   assessment.Reason,
		},
		Approval: map[string]any{
			"mode":     string(r.approvalMode),
			"decision": string(governance.DecisionAllow),
		},
	})
}

func (r *Recorder) shouldIgnore(rel string, isDir bool) bool {
	rel = strings.TrimPrefix(rel, "./")
	// built-in ignores
	if rel == ".git" || strings.HasPrefix(rel, ".git/") {
		return true
	}
	if rel == ".airlock" || strings.HasPrefix(rel, ".airlock/") {
		return true
	}
	if rel == "node_modules" || strings.HasPrefix(rel, "node_modules/") {
		return true
	}
	// config ignores (simple handling)
	if cfg := r.cfg.Load(); cfg != nil {
		for _, g := range cfg.Workspace.Ignore {
			g = filepath.ToSlash(strings.TrimSpace(g))
			if g == "" {
				continue
			}
			if strings.HasSuffix(g, "/**") {
				p := strings.TrimSuffix(g, "/**")
				if rel == p || strings.HasPrefix(rel, p+"/") {
					return true
				}
			}
			if strings.HasPrefix(g, "**/") {
				s := strings.TrimPrefix(g, "**/")
				if rel == s || strings.HasSuffix(rel, "/"+s) {
					return true
				}
			}
			if rel == g {
				return true
			}
		}
	}
	return false
}

func (r *Recorder) getLast(rel string) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.lastBytes[rel]...)
}

func (r *Recorder) setLast(rel string, b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastBytes[rel] = append([]byte(nil), b...)
}

func (r *Recorder) markSuppress(rel string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppressUntil[rel] = time.Now().UTC().Add(d)
}

func (r *Recorder) isSuppressed(rel string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.suppressUntil[rel]
	if !ok {
		return false
	}
	if time.Now().UTC().Before(until) {
		return true
	}
	delete(r.suppressUntil, rel)
	return false
}

func eventType(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Write == fsnotify.Write:
		return "FILE_WRITE"
	case op&fsnotify.Remove == fsnotify.Remove:
		return "FILE_REMOVE"
	case op&fsnotify.Rename == fsnotify.Rename:
		return "FILE_RENAME"
	case op&fsnotify.Create == fsnotify.Create:
		return "FILE_CREATE"
	default:
		return "FILE_EVENT"
	}
}

func opName(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Write == fsnotify.Write:
		return "WRITE"
	case op&fsnotify.Remove == fsnotify.Remove:
		return "REMOVE"
	case op&fsnotify.Rename == fsnotify.Rename:
		return "RENAME"
	case op&fsnotify.Create == fsnotify.Create:
		return "CREATE"
	default:
		return "EVENT"
	}
}

func mustRel(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return rel
}
