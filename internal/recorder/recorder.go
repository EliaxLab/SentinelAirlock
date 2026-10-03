package recorder

import (
	"bytes"
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

// reconcileInterval is the period of the infrequent full-tree safety
// reconciliation pass for long-running (debounced/Sentinel) sessions. It
// exists to recover from fsnotify watcher loss/overflow beyond the specific
// new-directory race that reconcileSubtree's CREATE-triggered call already
// closes deterministically -- it is a low-frequency safety net, not the
// primary fix, so it is intentionally infrequent rather than a poll loop.
const reconcileInterval = 30 * time.Second

// selfEventSuppressWindow is how long a path is ignored by the fsnotify event
// loop right after the recorder itself has just accounted for it -- either by
// reverting a denied write (the revert is itself a filesystem write that
// would otherwise be observed and misclassified) or by evaluating a path
// discovered through reconciliation (see reconcileSubtree) whose own,
// legitimate fsnotify event may still be in flight and would otherwise be
// evaluated a second time as a spurious duplicate.
const selfEventSuppressWindow = 500 * time.Millisecond

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
		if fi, lerr := os.Lstat(path); lerr != nil || fi.Mode()&os.ModeSymlink != 0 {
			return nil // never baseline through a symlink
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

	// The periodic safety reconciliation pass only makes sense for long-running
	// sessions (Sentinel). airlock run's recorder lives for one short command
	// and is already fully protected by the CREATE-triggered reconciliation in
	// loop() -- a background ticker there would add a goroutine with nothing
	// meaningful to do before Stop() tears it down again.
	if r.debounce > 0 {
		r.wg.Add(1)
		go r.reconcileLoop()
	}
	return nil
}

// reconcileLoop periodically re-walks the whole tree as a low-frequency
// safety net (see reconcileInterval's doc comment). It uses the same
// reconcileSubtree used for the CREATE-triggered fix, so any path already
// accounted for is a no-op -- this only ever discovers and evaluates paths
// the watcher never reported at all.
func (r *Recorder) reconcileLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.reconcileSubtree(r.root)
		}
	}
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
			// A newly-created directory needs more than just a watch: fsnotify
			// only reports the CREATE for the directory entry itself, and a
			// writer can populate it (including creating further nested
			// directories, e.g. via MkdirAll) before this goroutine gets back
			// around to installing that watch. Any such child event is lost
			// permanently at the kernel level -- there is no "add a watch
			// retroactively" that recovers an event that already happened.
			// reconcileSubtree closes that gap: it installs watches on this
			// directory and everything already inside it, then evaluates any
			// file it finds that the recorder has never seen, exactly as if
			// its own (lost) CREATE event had arrived. See recorder_test.go's
			// TestRecorder_NewDir* suite and progress.md for the reproduction
			// that motivated this.
			if ev.Op&fsnotify.Create == fsnotify.Create {
				if st, err := os.Stat(ev.Name); err == nil && st.IsDir() {
					r.reconcileSubtree(ev.Name)
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
				// The suppression window exists to swallow the tail of an
				// event this recorder generated itself (a revert write, or a
				// reconciliation-discovered file's own still-in-flight real
				// event) -- not to blindly silence *anything* touching this
				// path for selfEventSuppressWindow. If the on-disk content no
				// longer matches what evaluate last recorded as current, a
				// genuinely new mutation arrived inside the window (e.g. an
				// immediate re-write of a just-reverted denied file) and must
				// not be dropped, so the suppression is cleared and the event
				// is let through instead of continuing past it.
				full := filepath.Join(r.root, filepath.FromSlash(rel))
				current, _ := readNoFollow(full) // empty/nil if removed, matching getLast's zero value
				if bytes.Equal(current, r.getLast(rel)) {
					continue
				}
				r.clearSuppress(rel)
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
	after, isLink := readNoFollow(full) // if removed, read fails -> empty; symlinks are never read through

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
		r.markSuppress(rel, selfEventSuppressWindow)
		var revertErr error
		if before != nil { // existed (possibly zero bytes): restore it; nil: it did not exist
			revertErr = restoreFile(full, before)
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
		if isLink {
			if tgt, err := os.Readlink(full); err == nil {
				meta["symlink_target"] = tgt
			} else {
				meta["symlink"] = true
			}
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

// reconcileSubtree walks subtreeRoot (an absolute path -- either r.root for
// the periodic safety pass, or a single newly-observed directory for the
// CREATE-triggered fix), installs a watch on every directory found (idempotent
// -- fsnotify.Add on an already-watched path is a safe no-op), and evaluates
// every file that is not already known to the recorder exactly as if it had
// just been created.
//
// "Known" is deliberately a presence check on the baseline-cache map key, not
// on its content: a path the recorder has already evaluated at least once --
// allowed or denied, even a zero-byte file -- has an entry in lastBytes (see
// evaluate, which unconditionally calls setLast on both branches). A path
// with no entry has never been evaluated by any path (normal fsnotify
// delivery, an earlier reconciliation pass, or Seed's startup baseline), so
// evaluating it here is exactly the "treat it as newly created" semantics
// evaluate already implements for a real CREATE event: before-state empty,
// after-state read from disk, policy applied, denied writes removed the same
// way a denied real-time CREATE is removed.
//
// After evaluating a discovered file this way, its own legitimate fsnotify
// event may still be sitting in the OS queue (if the race window was narrow
// rather than a full miss) or may never arrive at all (if the window was
// wide, as reproduced on this project's own dev machine). Either way it must
// not be evaluated a second time, so the path is suppressed for
// selfEventSuppressWindow the same way a self-generated revert write is --
// reusing that exact mechanism rather than adding new state.
func (r *Recorder) reconcileSubtree(subtreeRoot string) {
	_ = filepath.WalkDir(subtreeRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// The path can legitimately vanish between the CREATE event firing
			// and this walk reaching it (e.g. a rapid mkdir+rmdir). Best-effort,
			// same as Seed/Start's initial walks.
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
			_ = r.w.Add(path)
			return nil
		}
		if r.hasLast(rel) {
			return nil // already accounted for by normal delivery or an earlier pass
		}
		r.evaluate(rel, fsnotify.Create)
		r.markSuppress(rel, selfEventSuppressWindow)
		return nil
	})
}

func (r *Recorder) shouldIgnore(rel string, isDir bool) bool {
	rel = strings.TrimPrefix(rel, "./")
	// A path that escapes the governed root (e.g. an event delivered through
	// a directory symlink by a backend that follows links) is never governed:
	// evaluating it would let a revert delete or overwrite files outside the
	// workspace.
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return true
	}
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

// getLast returns the cached before-state for rel. nil means "the path did
// not exist"; a non-nil (possibly zero-length) slice means it existed with
// exactly those bytes. Callers that roll back must test `!= nil`, not
// `len() > 0`, or an existing zero-byte file is indistinguishable from an
// absent one and gets deleted instead of restored.
func (r *Recorder) getLast(rel string) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneKeepNil(r.lastBytes[rel])
}

// cloneKeepNil copies b, preserving the nil / empty-non-nil distinction that
// append([]byte(nil), b...) would collapse.
func cloneKeepNil(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append(make([]byte, 0, len(b)), b...)
}

// hasLast reports whether rel has ever been evaluated, distinct from whether
// its cached content is empty: a zero-byte file that was legitimately
// created still has a (nil-valued) entry in lastBytes once evaluate has run
// for it, whereas a path the recorder has genuinely never seen has no map key
// at all. reconcileSubtree relies on exactly that distinction to tell "never
// observed, evaluate it now" apart from "already handled, zero-length is its
// real content."
func (r *Recorder) hasLast(rel string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.lastBytes[rel]
	return ok
}

func (r *Recorder) setLast(rel string, b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastBytes[rel] = cloneKeepNil(b)
}

func (r *Recorder) markSuppress(rel string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppressUntil[rel] = time.Now().UTC().Add(d)
}

// clearSuppress ends a path's suppression window early, used when the loop
// determines the on-disk content no longer matches what triggered the
// suppression -- see isSuppressed's call site.
func (r *Recorder) clearSuppress(rel string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.suppressUntil, rel)
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

// readNoFollow reads the regular file at full. A symlink is never read
// through: following it would copy the content of an arbitrary target
// (possibly outside the workspace) into the baseline cache and the evidence
// diff. It reports isLink so callers can record that the path is a link.
func readNoFollow(full string) (b []byte, isLink bool) {
	fi, err := os.Lstat(full)
	if err != nil {
		return nil, false
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, true
	}
	b, _ = os.ReadFile(full)
	return b, false
}

// restoreFile writes content back to full. If a symlink currently occupies
// the path it is removed first (os.Remove never follows) and the file is
// recreated with O_EXCL, which refuses to follow a link raced in afterwards,
// so a rollback can never write through a link into its target.
func restoreFile(full string, content []byte) error {
	if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(full); err != nil {
			return err
		}
		f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, werr := f.Write(content)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		return werr
	}
	return os.WriteFile(full, content, 0o644)
}
