package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/fleet"
	"github.com/EliaxLab/SentinelAirlock/internal/governance"
	"github.com/EliaxLab/SentinelAirlock/internal/index"
	"github.com/EliaxLab/SentinelAirlock/internal/policy"
	"github.com/EliaxLab/SentinelAirlock/internal/policypack"
	"github.com/EliaxLab/SentinelAirlock/internal/recorder"
	"github.com/EliaxLab/SentinelAirlock/internal/report"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/EliaxLab/SentinelAirlock/internal/util"
	"github.com/EliaxLab/SentinelAirlock/internal/workspace"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// sentinelDebounce coalesces rapid-fire fsnotify events for the same path
// (editor atomic saves, multi-syscall writes) into one evaluation. See
// recorder.NewDebounced's doc comment. airlock run keeps immediate (0)
// evaluation — a single short-lived command needs synchronous-relative
// revert behavior, so this value is Sentinel-only.
const sentinelDebounce = 200 * time.Millisecond

// sentinelRefreshInterval is how often a running Sentinel rewrites its
// manifest/digest/report/index while active, so `airlock inspect/verify/
// replay <session>` reflect near-real-time state without the cost of doing
// it on every single filesystem event (which is not bounded by anything
// Sentinel controls — real editor/IDE activity can be arbitrarily frequent).
const sentinelRefreshInterval = 2 * time.Second

// fleetHeartbeatInterval returns fleet.DefaultHeartbeatInterval, unless
// AIRLOCK_FLEET_HEARTBEAT_INTERVAL is set to a valid Go duration -- a test
// hook only, so integration tests don't have to wait out the real ~10s
// production cadence to observe a heartbeat.
func fleetHeartbeatInterval() time.Duration {
	if v := strings.TrimSpace(os.Getenv("AIRLOCK_FLEET_HEARTBEAT_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fleet.DefaultHeartbeatInterval
}

// fleetEnrollBackoffBase returns the starting backoff for fleetTryEnroll's
// exponential retry burst, unless AIRLOCK_FLEET_ENROLL_BACKOFF_BASE is set
// to a valid Go duration -- a test hook only, so a test can exercise the
// bounded-retry behavior in milliseconds instead of the real up-to-30s
// production worst case.
func fleetEnrollBackoffBase() time.Duration {
	if v := strings.TrimSpace(os.Getenv("AIRLOCK_FLEET_ENROLL_BACKOFF_BASE")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return time.Second
}

func sentinelCmd() *cobra.Command {
	var (
		repoPath     string
		policyPath   string
		policyPack   string
		background   bool
		status       bool
		stop         bool
		managed      bool
		fo           fleetOptions
		fleetHistory bool
	)

	cmd := &cobra.Command{
		Use:   "sentinel",
		Short: "Persistent policy monitoring for a repository, regardless of which process writes to it",
		Long: `Continuously governs a repository instead of one execution.

airlock run       = govern one execution Airlock launches
airlock sentinel  = continuously govern a repository, no matter which
                     process writes to it (VS Code, Codex, Claude Code,
                     OpenClaw, shell, git — anything, launched any way)

Honest semantics: this is persistent policy monitoring and best-effort
revert, not kernel-level mandatory access control. A filesystem watcher
observes mutations after the OS has already accepted them:

    filesystem mutation -> Sentinel detects -> policy evaluation
        -> ALLOW: preserved, recorded
        -> DENY:  reverted from baseline (best-effort), recorded

A process that reads a file in the narrow window before Sentinel reverts
it will see the denied content. Sentinel does not prevent that; it detects,
evaluates, and reverts as fast as it reasonably can, and always records
what happened.

Sentinel combines filesystem notifications with state reconciliation, so a
watcher event lost to a race (e.g. a directory created and populated faster
than its watch could be installed) does not permanently escape governance:
the next reconciliation pass evaluates it against policy as if its own event
had arrived. Event delivery is a signal, not the source of truth -- on-disk
state is.

Lifecycle:
  airlock sentinel --repo .                      foreground, attached
  airlock sentinel --repo . --background          detached, returns the terminal
  airlock sentinel --repo . --status              show whether it's running
  airlock sentinel --repo . --stop                stop it

Evidence lives under .airlock/runs/<session-id>/ — the same artifact model
as 'airlock run' — so 'airlock inspect/replay/verify <session-id>' all work
against a Sentinel session with no separate inspection stack.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			repoPath = util.DefaultIfEmpty(repoPath, ".")
			repoAbs, err := filepath.Abs(repoPath)
			if err != nil {
				return fmt.Errorf("could not resolve --repo %q: %w", repoPath, err)
			}
			if st, statErr := os.Stat(repoAbs); statErr != nil || !st.IsDir() {
				return fmt.Errorf("--repo %q is not a usable directory", repoAbs)
			}

			if status {
				return sentinelStatusCmd(repoAbs)
			}
			if stop {
				return sentinelStopCmd(repoAbs)
			}

			if existing, ok := runningSentinel(repoAbs); ok {
				fmt.Printf("Sentinel is already running for this repository.\n")
				fmt.Printf("  Repository: %s\n  Session:    %s\n  PID:        %d\n", existing.Repo, existing.Session, existing.PID)
				fmt.Printf("Stop it first with: airlock sentinel --repo %s --stop\n", repoAbs)
				return nil
			}

			// --fleet-history is expressed positively to the operator and
			// stored negatively internally, so the zero value of
			// fleetOptions means "history on" and nothing silently opts out.
			fo.HistorySyncDisabled = !fleetHistory

			if background {
				return startSentinelBackground(repoAbs, policyPath, policyPack, fo)
			}

			return runSentinelForeground(repoAbs, policyPath, policyPack, managed, fo)
		},
	}

	cmd.Flags().StringVar(&repoPath, "repo", ".", "Path to the repository to govern")
	cmd.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path (relative to --repo unless absolute)")
	cmd.Flags().StringVar(&policyPack, "policy-pack", "", "Policy pack to apply (strict, balanced, oss-maintainer, ci-safe, research)")
	cmd.Flags().BoolVar(&background, "background", false, "Run Sentinel detached in the background")
	cmd.Flags().BoolVar(&status, "status", false, "Show whether Sentinel is running for --repo")
	cmd.Flags().BoolVar(&stop, "stop", false, "Stop the running Sentinel for --repo")
	cmd.Flags().BoolVar(&managed, "managed", false, "Internal: run as the managed background sentinel")
	_ = cmd.Flags().MarkHidden("managed")
	cmd.Flags().StringVar(&fo.URL, "fleet", "", "Airlock Fleet control plane URL to enroll with and heartbeat to (optional; standalone if unset)")
	cmd.Flags().StringVar(&fo.Token, "fleet-token", "", "Shared operator token for the fleet control plane, if it requires one")
	cmd.Flags().StringVar(&fo.EnrollToken, "fleet-enroll-token", "", "One-time enrollment token from 'airlock fleet enroll-token create' (first enrollment only)")
	cmd.Flags().StringVar(&fo.PublicKey, "fleet-pubkey", "", "Pin the control plane's policy signing key explicitly (hex key, or a path to a file containing it)")
	cmd.Flags().StringVar(&fo.CACert, "fleet-ca", "", "PEM bundle to trust for an https:// control plane behind a private CA")
	cmd.Flags().BoolVar(&fleetHistory, "fleet-history", true, "Contribute governance session history metadata to Fleet (health heartbeat and local enforcement are unaffected either way)")
	return cmd
}

// runSentinelForeground resolves policy, takes the session-start checkpoint,
// seeds and starts the recorder against the real repo, and blocks until a
// stop signal (Ctrl-C, SIGTERM, or `airlock sentinel --stop`) arrives.
func runSentinelForeground(repoAbs, policyPath, policyPack string, managed bool, fo fleetOptions) error {
	sess, err := startSentinelSession(repoAbs, policyPath, policyPack, managed, fo)
	if err != nil {
		return err
	}

	fmt.Println("Sentinel started")
	fmt.Printf("Repository: %s\n", repoAbs)
	fmt.Printf("Session:    %s\n", sess.sessionID)
	fmt.Printf("Policy:     %s\n", sess.policyPath)
	if !managed {
		fmt.Println("Persistent policy monitoring and best-effort revert. Ctrl-C to stop cleanly.")
		fmt.Printf("Or from another terminal: airlock sentinel --repo %s --stop\n", repoAbs)
	}

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stopCh)
	}()

	ticker := time.NewTicker(sentinelRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			sess.shutdown()
			return nil
		case <-ticker.C:
			sess.refreshEvidence("running")
		}
	}
}

// startSentinelSession does everything a Sentinel session needs before it can
// start observing the repository: resolve policy, take the session-start
// checkpoint, seed and start the recorder, and publish the process's
// lifecycle metadata. Split out from runSentinelForeground (which just adds
// the OS-signal-driven wait/shutdown loop around it) so tests can drive a
// session deterministically — perform filesystem operations, assert on
// evidence, then call sess.shutdown() directly — without needing to send a
// real signal to the test process.
func startSentinelSession(repoAbs, policyPath, policyPack string, managed bool, fo fleetOptions) (*sentinelSession, error) {
	fleetURL := strings.TrimSpace(fo.URL)
	resolvedPolicyPath := policyPath
	if !filepath.IsAbs(resolvedPolicyPath) {
		resolvedPolicyPath = filepath.Join(repoAbs, resolvedPolicyPath)
	}
	cfg, cfgErr := policy.Load(resolvedPolicyPath)
	if cfgErr != nil {
		fmt.Printf("WARN: could not load %s (%v). Running with built-in ignores.\n", resolvedPolicyPath, cfgErr)
	}
	if strings.TrimSpace(policyPack) == "" && cfg != nil {
		policyPack = cfg.Defaults.PolicyPack
	}
	if strings.TrimSpace(policyPack) != "" {
		pack, err := policypack.Get(policyPack)
		if err != nil {
			return nil, err
		}
		if packCfg, err := policypack.ParseConfig(pack); err == nil {
			cfg = policypack.Merge(cfg, packCfg)
		}
	}

	// Local-vs-Fleet precedence (Prompt 14A, documented in progress.md): once
	// this Sentinel identity has ever successfully reconciled a Fleet-
	// managed policy, that last-known-good policy is authoritative on every
	// subsequent start -- it supersedes local airlock.yaml and any
	// --policy-pack, even if the control plane is unreachable right now.
	// This is what lets a restarted, Fleet-managed Sentinel keep enforcing
	// v12 (not silently fall back to a stale/looser local file) until it
	// reconnects and confirms v12 is still current. A brand-new Fleet-
	// managed Sentinel that has never yet reconciled anything falls back to
	// local airlock.yaml, exactly like a standalone Sentinel, until its
	// first successful reconciliation establishes an LKG.
	//
	// The pinned signing key is loaded first (Prompt 14B), because the
	// last-known-good policy is re-verified against it before being trusted:
	// a Sentinel restarting while its control plane is unreachable still
	// proves to itself that the policy it is about to enforce is the signed
	// one it accepted, not something that has since been edited on disk.
	var (
		fleetPolicyRef fleet.PolicyRef
		trust          fleet.TrustStore
		maxAccepted    = map[string]int{}
		signatureState string
		signerKeyID    string
		identityState  = "UNAUTHENTICATED"
	)
	if strings.TrimSpace(fleetURL) != "" {
		if cred, ok := loadFleetCredential(repoAbs); ok {
			trust = fleet.Trust(cred.SigningKeyID, cred.SigningPublicKey)
			identityState = "AUTHENTICATED"
			signerKeyID = cred.SigningKeyID
		}
		if lkg, ok := loadFleetLKG(repoAbs, trust); ok {
			cfg = lkg.cfg
			fleetPolicyRef = lkg.ref
			maxAccepted = lkg.maxAccepted
			signatureState = lkg.signatureState
			if lkg.signerKeyID != "" {
				signerKeyID = lkg.signerKeyID
			}
			fmt.Printf("Restored last-known-good Fleet policy: %s v%d (hash %s, signature %s)\n",
				lkg.ref.PolicyID, lkg.ref.Version, lkg.ref.Hash, strings.ToLower(lkg.signatureState))
		}
	}

	sessionID := strings.TrimSpace(os.Getenv("AIRLOCK_RUN_ID_FORCE"))
	if sessionID == "" {
		sessionID = uuid.New().String()
	}
	runsDir := filepath.Join(repoAbs, ".airlock", "runs", sessionID)
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		return nil, err
	}

	logger, err := events.NewLogger(filepath.Join(runsDir, "events.jsonl"))
	if err != nil {
		return nil, err
	}

	ignore := []string{".git/**", ".airlock/**", "node_modules/**"}
	if cfg != nil && len(cfg.Workspace.Ignore) > 0 {
		ignore = cfg.Workspace.Ignore
	}
	checkpointPath := filepath.Join(runsDir, "checkpoints", "cp-0")
	if err := workspace.CopyRepo(repoAbs, checkpointPath, ignore); err != nil {
		_ = logger.Close()
		return nil, fmt.Errorf("could not take session-start checkpoint: %w", err)
	}

	startedAt := time.Now().UTC()
	logger.Add(events.Event{TS: startedAt, Type: "SENTINEL_START", Summary: "sentinel session started", Meta: map[string]any{
		"session_id": sessionID, "repo": repoAbs, "pid": os.Getpid(), "policy_path": resolvedPolicyPath,
	}})

	sess := &sentinelSession{
		repoAbs:        repoAbs,
		sessionID:      sessionID,
		runsDir:        runsDir,
		checkpointPath: checkpointPath,
		policyPath:     resolvedPolicyPath,
		policyPack:     policyPack,
		cfg:            cfg,
		fleetPolicyRef: fleetPolicyRef,
		trust:          trust,
		maxAccepted:    maxAccepted,
		signatureState: signatureState,
		signerKeyID:    signerKeyID,
		identityState:  identityState,
		logger:         logger,
		startedAt:      startedAt,
	}
	if err := sess.writeManifest("running"); err != nil {
		_ = logger.Close()
		return nil, err
	}
	sess.refreshEvidence("running")

	rec, err := recorder.NewDebounced(repoAbs, logger, cfg, governance.ApprovalAuto, sentinelDebounce)
	if err != nil {
		_ = logger.Close()
		return nil, err
	}
	if err := rec.Seed(); err != nil {
		_ = logger.Close()
		return nil, err
	}
	if err := rec.Start(); err != nil {
		_ = logger.Close()
		return nil, err
	}
	sess.rec = rec

	logDesc := "(foreground terminal)"
	if managed {
		logDesc = sentinelLogPath(repoAbs)
	}
	if err := writeSentinelMeta(repoAbs, sentinelMeta{
		PID: os.Getpid(), Repo: repoAbs, Session: sessionID,
		Started: startedAt.Format(time.RFC3339), Log: logDesc, Background: managed,
	}); err != nil {
		sess.shutdown()
		return nil, err
	}

	if fleetURL != "" {
		sess.startFleet(fo)
	}

	return sess, nil
}

// fleetOptions bundles everything a Sentinel needs to talk to a Fleet control
// plane. It replaced a growing list of positional string parameters once
// Prompt 14B added enrollment tokens, key pinning, and private-CA trust --
// five adjacent strings threaded through three functions is exactly how a
// caller ends up silently passing a token where a URL belongs.
type fleetOptions struct {
	// URL is the control plane address. Empty means standalone: no fleet
	// code runs at all.
	URL string

	// Token is the optional shared operator token from Prompt 14. It is not
	// a Sentinel identity -- see EnrollToken.
	Token string

	// EnrollToken is a one-time, operator-issued enrollment token, presented
	// only until this Sentinel holds a durable credential.
	EnrollToken string

	// PublicKey optionally pins the control plane's policy-signing key
	// explicitly (hex, or a path to a file containing it), instead of
	// accepting the one advertised at enrollment.
	PublicKey string

	// CACert optionally adds a PEM trust anchor for a self-hosted control
	// plane behind a private CA or self-signed certificate.
	CACert string

	// HistorySyncDisabled stops this Sentinel contributing governance session
	// history to Fleet (Prompt 14C). It suppresses HISTORY ONLY: enrollment,
	// health heartbeat, policy reconciliation, and local enforcement all
	// continue exactly as before, so turning history off never quietly turns
	// off fleet health monitoring. Raw evidence was never uploaded in the
	// first place and is unaffected.
	HistorySyncDisabled bool
}

func (o fleetOptions) enabled() bool { return strings.TrimSpace(o.URL) != "" }

// sentinelSession bundles the state a running Sentinel needs to keep its
// evidence (manifest, digest, report, index) current and to finalize
// cleanly on stop. It deliberately does not do a full-repo re-copy on every
// refresh — only the session-start checkpoint (once) plus re-deriving small
// evidence artifacts (manifest/digest/report/index) from what the recorder
// has already logged.
type sentinelSession struct {
	repoAbs        string
	sessionID      string
	runsDir        string
	checkpointPath string
	policyPath     string
	policyPack     string
	logger         *events.Logger
	rec            *recorder.Recorder
	startedAt      time.Time

	// cfg and fleetPolicyRef are read from the fleet goroutine
	// (policyIdentity, buildHeartbeatRequest) and written from it too (a
	// successful Fleet reconciliation), while writeManifest/refreshEvidence
	// read cfg from the session's own ticker goroutine -- so both go through
	// policyMu rather than being plain fields. fleetPolicyRef's zero value
	// (PolicyID=="") means "not yet running a Fleet-managed policy": cfg is
	// still whatever local airlock.yaml (+ policy pack) resolved to, or a
	// restored last-known-good Fleet policy loaded at startup -- see
	// loadFleetLKG.
	policyMu       sync.RWMutex
	cfg            *policy.Config
	fleetPolicyRef fleet.PolicyRef

	// Trust state (Prompt 14B), guarded by the same policyMu as the policy it
	// describes, since the two always change together.
	//
	//   trust           the pinned control-plane signing key(s); empty means
	//                   no signing relationship has ever been established
	//   maxAccepted     anti-downgrade high-water mark, policy id -> highest
	//                   version ever accepted
	//   lastRejectedRef the last desired ref refused on trust grounds, so a
	//                   deterministic refusal is not retried every heartbeat.
	//                   Latched together with the rollback authorization that
	//                   was (or was not) presented with it -- see
	//                   lastRejectedGrantSig
	//   identityState   AUTHENTICATED / UNAUTHENTICATED / REVOKED
	//   signatureState  how the running policy was verified: VERIFIED /
	//                   UNSIGNED / "" (not Fleet-managed)
	trust           fleet.TrustStore
	maxAccepted     map[string]int
	lastRejectedRef fleet.PolicyRef
	// lastRejectedGrantSig is the rollback authorization that accompanied the
	// latched rejection (empty if there was none). The latch keys on it as
	// well as on the ref, because an operator issuing a signed rollback grant
	// for a ref this Sentinel already refused is precisely the case that must
	// be retried -- the inputs changed, so the outcome may too.
	lastRejectedGrantSig string
	identityState        string
	signatureState       string
	signerKeyID          string
	// fleetConnected tracks whether the control plane was reachable on the
	// last attempt. It is reported locally but never conflated with identity:
	// "cannot reach the control plane" and "my credential was revoked" are
	// different states with different meanings.
	fleetConnected bool

	// Fleet reporting (optional; nil/zero when --fleet is unset). See
	// startFleet and fleetLoop below. sentinelID is the durable identity for
	// "this Sentinel governing this repo" -- distinct from sessionID, which
	// is fresh every restart. See internal/fleet/identity.go.
	sentinelID     string
	fleetMachineID string
	fleetOpts      fleetOptions
	fleetClient    *fleet.Client
	fleetStopCh    chan struct{}
	fleetDone      chan struct{}

	// outbox durably buffers metadata-only reports while the control plane is
	// unreachable; reportCursor is this session's position in its own event
	// log, and is touched only from the fleet goroutine.
	outbox       *fleet.Outbox
	reportCursor int
}

func (s *sentinelSession) getTrust() fleet.TrustStore {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.trust
}

func (s *sentinelSession) getIdentityState() string {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	if s.identityState == "" {
		return "UNAUTHENTICATED"
	}
	return s.identityState
}

func (s *sentinelSession) setIdentityState(state string) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	s.identityState = state
}

func (s *sentinelSession) getSignatureState() string {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.signatureState
}

func (s *sentinelSession) setSignatureState(state, keyID string) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	s.signatureState = state
	if keyID != "" {
		s.signerKeyID = keyID
	}
}

func (s *sentinelSession) setConnected(connected bool) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	s.fleetConnected = connected
}

func (s *sentinelSession) isConnected() bool {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.fleetConnected
}

func (s *sentinelSession) getSignerKeyID() string {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.signerKeyID
}

func (s *sentinelSession) getCfg() *policy.Config {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.cfg
}

func (s *sentinelSession) setCfg(cfg *policy.Config) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	s.cfg = cfg
}

func (s *sentinelSession) getFleetPolicyRef() fleet.PolicyRef {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.fleetPolicyRef
}

func (s *sentinelSession) setFleetPolicyRef(ref fleet.PolicyRef) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	s.fleetPolicyRef = ref
}

func (s *sentinelSession) writeManifest(status string) error {
	evs := s.logger.EventsSnapshot()
	manifest := runmeta.RunManifest{
		RunID:           s.sessionID,
		WorkspacePath:   s.repoAbs,
		PolicySummary:   runmeta.BuildPolicySummary(s.policyPath, s.getCfg()),
		ExecutionMode:   "sentinel",
		TouchedPaths:    touchedPathsFromEvents(evs),
		DeniedPaths:     deniedPathsFromEvents(evs),
		Checkpoints:     []runmeta.Checkpoint{{ID: "cp-0", Path: s.checkpointPath}},
		RiskSummary:     riskSummaryFromEvents(evs),
		ApprovalSummary: approvalSummaryFromEvents(evs),
		Adapter:         runmeta.AdapterSummary{Name: "sentinel"},
		Invocation:      runmeta.InvocationSummary{DisplayCommand: fmt.Sprintf("airlock sentinel --repo %s", s.repoAbs)},
		Sandbox:         runmeta.SandboxInfo{Mode: "off"},
		Digest:          runmeta.DigestInfo{Path: filepath.Join(s.runsDir, "run_digest.json")},
		Status:          runmeta.RunStatus{Terminal: status},
		Product:         runmeta.ProductInfo{Version: Version, Commit: Commit, BuildDate: BuildDate},
	}
	if s.policyPack != "" {
		if pack, err := policypack.Get(s.policyPack); err == nil {
			manifest.PolicyPack = runmeta.PolicyPackInfo{Name: pack.Name, Version: pack.Version, Source: pack.Source}
		}
	}
	return runmeta.Save(filepath.Join(s.runsDir, "run_manifest.json"), manifest)
}

// refreshEvidence rewrites manifest/digest/report/index from what's been
// logged so far, so inspect/replay/verify reflect near-real-time state for a
// still-running session. Cheap: no full-repo re-copy, just re-deriving small
// artifacts already backed by the events log. status is the manifest's
// terminal-status label ("running" while active, "stopped" once shutdown
// has logged SENTINEL_STOP) — a caller-supplied value rather than a fixed
// "running" so shutdown's final refresh doesn't clobber its own status write.
func (s *sentinelSession) refreshEvidence(status string) {
	_ = s.writeManifest(status)
	if digest, err := runmeta.BuildDigest(s.sessionID, s.runsDir); err == nil {
		_ = runmeta.SaveDigest(filepath.Join(s.runsDir, "run_digest.json"), digest)
	}
	_ = report.Generate(s.runsDir, s.logger.EventsSnapshot())
	if store, err := index.Rebuild(filepath.Join(s.repoAbs, ".airlock", "runs")); err == nil {
		_ = index.Save(filepath.Join(s.repoAbs, ".airlock", "index.json"), store)
	}
}

// shutdown stops the recorder, finalizes evidence, and removes the process's
// lifecycle metadata. Order matters: the recorder must stop (and its
// pendingWG must drain — see recorder.Stop) before the final manifest/digest
// are written, so no in-flight debounced evaluation is lost or races the
// final write; SENTINEL_STOP is logged and evidence refreshed one last time
// before metadata is removed, so --status can never observe a "not running"
// state before evidence is actually consistent.
func (s *sentinelSession) shutdown() {
	s.stopFleet()
	if s.rec != nil {
		_ = s.rec.Stop()
	}
	s.logger.Add(events.Event{TS: time.Now().UTC(), Type: "SENTINEL_STOP", Summary: "sentinel session stopped", Meta: map[string]any{
		"session_id": s.sessionID, "repo": s.repoAbs,
	}})
	s.refreshEvidence("stopped")
	_ = s.logger.Close()
	removeSentinelMeta(s.repoAbs)
}

// --- Fleet reporting -------------------------------------------------------
//
// Everything below this point is asynchronous management traffic to an
// optional Airlock Fleet control plane (`airlock fleet serve`). It never
// participates in a filesystem-mutation decision: local governance
// (recorder + governance packages, above) has already allowed/denied/
// reverted a change before any of this code runs. This goroutine's only
// job is to periodically tell a control plane "I exist, here is my
// identity/version/policy, and here is what I've done" -- and to keep doing
// that indefinitely, tolerating any number of failures, for as long as the
// session runs.

// startFleet resolves this Sentinel's durable identity and launches the
// enroll+heartbeat goroutine. Any failure here (e.g. cannot resolve a home
// directory for the machine identity file) only disables fleet reporting
// for this run -- it never fails session startup, since Sentinel must work
// standalone regardless of fleet configuration or fleet reachability.
func (s *sentinelSession) startFleet(fo fleetOptions) {
	machineID, err := fleet.MachineID()
	if err != nil {
		fmt.Printf("WARN: fleet reporting disabled: could not establish machine identity: %v\n", err)
		return
	}
	sentinelID, err := fleet.SentinelID(s.repoAbs)
	if err != nil {
		fmt.Printf("WARN: fleet reporting disabled: could not establish sentinel identity: %v\n", err)
		return
	}
	s.sentinelID = sentinelID
	s.fleetMachineID = machineID
	s.fleetOpts = fo
	s.fleetClient = fleet.NewClient(fo.URL, fo.Token)

	if strings.TrimSpace(fo.CACert) != "" {
		if err := s.fleetClient.SetRootCA(fo.CACert); err != nil {
			fmt.Printf("WARN: fleet reporting disabled: %v\n", err)
			s.fleetClient = nil
			return
		}
	}
	// An explicitly supplied key is pinned before the first request, so this
	// Sentinel never even briefly trusts whatever the network hands it.
	if strings.TrimSpace(fo.PublicKey) != "" {
		keyID, hexKey, err := resolvePinnedPublicKey(fo.PublicKey)
		if err != nil {
			fmt.Printf("WARN: fleet reporting disabled: %v\n", err)
			s.fleetClient = nil
			return
		}
		s.policyMu.Lock()
		s.trust = fleet.Trust(keyID, hexKey)
		s.signerKeyID = keyID
		s.policyMu.Unlock()
	}

	// A previously-issued credential makes this Sentinel authenticated from
	// its very first request after a restart -- no re-enrollment, and no
	// window where it speaks unauthenticated.
	if cred, ok := loadFleetCredential(s.repoAbs); ok {
		s.fleetClient.SetCredential(cred.Credential)
		s.setIdentityState("AUTHENTICATED")
	}
	s.warnOnInsecureTransport()

	if outbox, err := fleet.OpenOutbox(fleetOutboxPath(s.repoAbs)); err == nil {
		s.outbox = outbox
	} else {
		fmt.Printf("WARN: fleet report buffering disabled: %v (heartbeats and enforcement are unaffected)\n", err)
	}

	s.fleetStopCh = make(chan struct{})
	s.fleetDone = make(chan struct{})
	go s.fleetLoop()
}

// warnOnInsecureTransport states the transport posture plainly instead of
// letting a plaintext deployment pass unnoticed.
//
// Bearer credentials over plaintext HTTP to a remote host are not secure, and
// this code does not pretend otherwise: loopback HTTP is a supported
// development posture, anything else without TLS gets told what it is. Real
// deployments point --fleet at an https:// URL (see `airlock fleet serve
// --tls-cert/--tls-key`, or a TLS-terminating proxy).
func (s *sentinelSession) warnOnInsecureTransport() {
	if s.fleetClient == nil || s.fleetClient.UsesTLS() {
		return
	}
	host := s.fleetClient.BaseURL()
	if isLoopbackFleetURL(host) {
		return
	}
	fmt.Printf("WARN: fleet control plane %s uses plaintext HTTP to a non-loopback host.\n", host)
	fmt.Printf("      Credentials and reports will cross the network unencrypted and unauthenticated in transit.\n")
	fmt.Printf("      Use an https:// URL for anything but local development.\n")
}

func isLoopbackFleetURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// stopFleet signals the fleet goroutine to exit and waits briefly for it, so
// shutdown() does not race a final in-flight HTTP call and does not leak the
// goroutine past session end. It never blocks long: fleetStopCh is buffered
// by nothing but is always drained by fleetLoop's select within one HTTP
// round trip (bounded by fleet.ClientTimeout) or immediately if idle.
func (s *sentinelSession) stopFleet() {
	if s.fleetStopCh == nil {
		return
	}
	close(s.fleetStopCh)
	select {
	case <-s.fleetDone:
	case <-time.After(fleet.ClientTimeout + time.Second):
	}
	// Report the clean stop only after the fleet goroutine has exited, so
	// this final heartbeat cannot race an in-flight one and arrive out of
	// order. Everything here is best-effort and bounded: local shutdown must
	// succeed whether or not a control plane is reachable.
	s.reportSessionStopped()
}

// reportSessionStopped tells Fleet this monitoring session ended cleanly
// (Prompt 14C).
//
// Two delivery paths, because a Sentinel is often stopped precisely when the
// control plane is unavailable:
//
//   - live: a final heartbeat with Status=stopped, which Fleet records as
//     stopped_at immediately
//   - buffered: if that fails, a durable SESSION_STOPPED report in the
//     existing outbox, which a LATER session flushes on reconnect -- the
//     stopping session is gone, but its outbox is on disk and its session id
//     is in the report
//
// Both converge on the same record: MarkStopped is first-write-wins, so a
// stop delivered twice records one stopped_at rather than contradicting
// itself. If neither path ever succeeds, the session is honestly left
// INTERRUPTED rather than being given a fabricated clean stop.
func (s *sentinelSession) reportSessionStopped() {
	if s.fleetClient == nil || s.sentinelID == "" || s.fleetOpts.HistorySyncDisabled {
		return
	}
	stoppedAt := time.Now().UTC()
	req := s.buildHeartbeatRequest()
	req.Status = fleet.SessionStoppedStatus
	if _, err := s.fleetClient.Heartbeat(req); err == nil {
		return
	}
	s.bufferReport(fleet.ReportSessionStopped, stoppedAt, "", "session stopped cleanly")
	fmt.Printf("Fleet unreachable at shutdown; buffered the session-stop record for delivery on reconnect.\n")
}

// fleetLoop enrolls (with a bounded, exponentially-backed-off burst of
// attempts) and then heartbeats on a fixed interval indefinitely. If the
// initial burst does not succeed, it keeps retrying enrollment once per
// heartbeat tick forever -- never faster than DefaultHeartbeatInterval, so
// an unreachable control plane never becomes a tight retry loop, and a
// control plane that comes back later is reconnected to automatically with
// no Sentinel restart required. Every failure is logged and swallowed:
// nothing here ever returns an error to the caller or affects local
// enforcement.
func (s *sentinelSession) fleetLoop() {
	defer close(s.fleetDone)
	// Publish local trust status before the enrollment burst, not after it.
	// The burst backs off up to tens of seconds against an unreachable
	// control plane, and during exactly that window someone is likely to ask
	// this machine what it is enforcing -- they should get this session's
	// answer, not the previous one's, and a first-ever run should not have no
	// answer at all.
	s.writeFleetStatus("")
	enrolled := s.fleetTryEnroll()
	if s.getIdentityState() != "REVOKED" {
		s.setConnected(enrolled)
	}
	s.writeFleetStatus("")
	ticker := time.NewTicker(fleetHeartbeatInterval())
	defer ticker.Stop()
	for {
		select {
		case <-s.fleetStopCh:
			// Collect one last time so activity from the final moments of a
			// session is buffered durably even if there is no time to upload
			// it -- the next session flushes it.
			s.collectReports()
			return
		case <-ticker.C:
			// Buffering happens first and unconditionally: what a Sentinel
			// observed is recorded locally whether or not anything can be
			// reached right now.
			s.collectReports()
			if !enrolled {
				if _, err := s.enrollOnce(); err != nil {
					s.noteFleetError(err)
					s.setConnected(false)
					s.writeFleetStatus(err.Error())
					continue
				}
				enrolled = true
			}
			resp, err := s.fleetClient.Heartbeat(s.buildHeartbeatRequest())
			if err != nil {
				s.noteFleetError(err)
				// Refresh local status on the failure path too: an outage is
				// precisely when someone runs `airlock sentinel --status` to
				// ask what this machine is still enforcing and how much it has
				// buffered. Leaving it frozen at the last successful heartbeat
				// would answer that question with stale information.
				//
				// A revoked credential is NOT a connectivity failure -- the
				// control plane answered, it just refused us. Reporting that
				// as UNREACHABLE would blame the network for an authorization
				// decision, and those call for completely different responses
				// from whoever is reading the status.
				s.setConnected(errors.Is(err, fleet.ErrCredentialRevoked))
				s.writeFleetStatus(err.Error())
				continue
			}
			s.setConnected(true)
			if s.getIdentityState() == "REVOKED" {
				// Reinstated: the control plane is accepting this credential
				// again.
				s.setIdentityState("AUTHENTICATED")
				fmt.Println("Fleet credential accepted again; fleet participation resumed.")
			}
			s.flushReports()
			s.reconcileFleetPolicy(resp)
			s.writeFleetStatus("")
		}
	}
}

// enrollOnce performs one enrollment attempt and processes its response:
// storing a newly-issued credential and pinning the control plane's signing
// key the first time one is seen.
func (s *sentinelSession) enrollOnce() (fleet.EnrollResponse, error) {
	resp, err := s.fleetClient.Enroll(s.buildEnrollRequest())
	if err != nil {
		return resp, err
	}
	s.acceptEnrollResponse(resp)
	return resp, nil
}

// acceptEnrollResponse persists whatever trust material an enrollment
// returned.
//
// Key pinning is deliberately one-way. The first key seen -- in the exchange
// an operator authorized with an out-of-band enrollment token -- is stored and
// used forever after. A later response advertising a different key is refused
// and reported, not adopted: otherwise anyone who took over the control
// plane's address could re-point an established Sentinel at their own signing
// key, and every other check in this file would then be verifying signatures
// against the attacker's key.
func (s *sentinelSession) acceptEnrollResponse(resp fleet.EnrollResponse) {
	if strings.TrimSpace(resp.Credential) != "" {
		cred := fleetCredentialFile{
			SentinelID:       s.sentinelID,
			FleetURL:         s.fleetClient.BaseURL(),
			Credential:       resp.Credential,
			SigningKeyID:     resp.SigningKeyID,
			SigningPublicKey: resp.SigningPublicKey,
			EnrolledAt:       time.Now().UTC(),
		}
		if err := saveFleetCredential(s.repoAbs, cred); err != nil {
			fmt.Printf("WARN: could not persist fleet credential: %v (this Sentinel will need to re-enroll after a restart)\n", err)
		}
		s.fleetClient.SetCredential(resp.Credential)
		s.setIdentityState("AUTHENTICATED")
		fmt.Printf("Enrolled with Fleet control plane; credential stored at %s\n", fleetCredentialPath(s.repoAbs))
	}

	if strings.TrimSpace(resp.SigningKeyID) == "" {
		return
	}
	current := s.getTrust()
	if current.Empty() {
		s.policyMu.Lock()
		s.trust = fleet.Trust(resp.SigningKeyID, resp.SigningPublicKey)
		s.signerKeyID = resp.SigningKeyID
		s.policyMu.Unlock()
		fmt.Printf("Pinned Fleet policy signing key %s\n", resp.SigningKeyID)
		s.persistPinnedKey(resp)
		return
	}
	if _, known := current.Keys[resp.SigningKeyID]; !known {
		fmt.Printf("WARN: control plane advertised policy signing key %s, but this Sentinel has pinned a different key.\n", resp.SigningKeyID)
		fmt.Printf("      Refusing to adopt it. Policy signed by the new key will be REJECTED and the last-known-good\n")
		fmt.Printf("      policy stays in force. If this is an intentional key rotation, revoke and re-enroll this Sentinel.\n")
	}
}

// persistPinnedKey records a newly-pinned key alongside an existing
// credential, for the case where the key was advertised on a later enrollment
// than the one that issued the credential.
func (s *sentinelSession) persistPinnedKey(resp fleet.EnrollResponse) {
	cred, ok := loadFleetCredential(s.repoAbs)
	if !ok || cred.SigningKeyID == resp.SigningKeyID {
		return
	}
	cred.SigningKeyID = resp.SigningKeyID
	cred.SigningPublicKey = resp.SigningPublicKey
	if err := saveFleetCredential(s.repoAbs, cred); err != nil {
		fmt.Printf("WARN: could not persist pinned signing key: %v\n", err)
	}
}

// fleetTryEnroll makes a bounded, exponentially-backed-off burst of
// enrollment attempts at session startup. It returns quickly (false) if the
// control plane is unreachable rather than blocking indefinitely --
// fleetLoop's ticker takes over retrying afterward at a much slower, bounded
// rate.
func (s *sentinelSession) fleetTryEnroll() bool {
	backoff := fleetEnrollBackoffBase()
	for attempt := 0; attempt < fleet.MaxEnrollAttempts; attempt++ {
		_, err := s.enrollOnce()
		if err == nil {
			return true
		}
		if errors.Is(err, fleet.ErrCredentialRevoked) {
			// A revoked credential is a settled state, not a transient
			// failure: retrying the burst cannot fix it, and it must be
			// classified here rather than only once the first heartbeat runs
			// -- otherwise a restarted, revoked Sentinel would report itself
			// AUTHENTICATED and UNREACHABLE for the whole backoff window,
			// which is wrong on both counts.
			s.noteFleetError(err)
			s.setConnected(true)
			return false
		}
		if attempt == 0 {
			fmt.Printf("WARN: fleet enrollment did not succeed (%v); Sentinel continues local governance and will keep retrying.\n", err)
		}
		select {
		case <-time.After(backoff):
			if backoff < fleet.MaxEnrollBackoff {
				backoff *= 2
			}
		case <-s.fleetStopCh:
			return false
		}
	}
	return false
}

func (s *sentinelSession) buildEnrollRequest() fleet.EnrollRequest {
	policyID, policyVersion, policyHash := s.policyIdentity()
	return fleet.EnrollRequest{
		SentinelID:      s.sentinelID,
		MachineID:       s.fleetMachineID,
		Hostname:        hostName(),
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		RepoPath:        s.repoAbs,
		SentinelVersion: Version,
		SessionID:       s.sessionID,
		StartedAt:       s.startedAt,
		PolicyID:        policyID,
		PolicyVersion:   policyVersion,
		PolicyHash:      policyHash,
		// The enrollment token is presented only while this Sentinel has no
		// credential of its own; once one is issued, it is never sent again.
		EnrollToken: s.pendingEnrollToken(),
	}
}

// pendingEnrollToken returns the one-time enrollment token, but only if this
// Sentinel does not already hold a credential -- so a configured token is not
// needlessly re-presented (and re-exposed) on every restart of an
// already-enrolled Sentinel.
func (s *sentinelSession) pendingEnrollToken() string {
	if s.fleetClient != nil && s.fleetClient.HasCredential() {
		return ""
	}
	return strings.TrimSpace(s.fleetOpts.EnrollToken)
}

func (s *sentinelSession) buildHeartbeatRequest() fleet.HeartbeatRequest {
	policyID, policyVersion, policyHash := s.policyIdentity()
	allow, deny, reverted, revertFailed, lastEventAt := governanceCounters(s.logger.EventsSnapshot())
	return fleet.HeartbeatRequest{
		SentinelID:        s.sentinelID,
		SessionID:         s.sessionID,
		Status:            "running",
		Timestamp:         time.Now().UTC(),
		SentinelVersion:   Version,
		PolicyID:          policyID,
		PolicyVersion:     policyVersion,
		PolicyHash:        policyHash,
		LastEventAt:       lastEventAt,
		AllowCount:        allow,
		DenyCount:         deny,
		RevertedCount:     reverted,
		RevertFailedCount: revertFailed,
		SignatureState:    s.getSignatureState(),
		SignerKeyID:       s.getSignerKeyID(),
		BufferedReports:   s.bufferedReportCount(),
		// Governance session history (Prompt 14C). StartedAt is this
		// session's start, so the control plane can record when the session
		// began without a separate session-registration call.
		SessionStartedAt:    s.startedAt,
		HistorySyncDisabled: s.fleetOpts.HistorySyncDisabled,
	}
}

func (s *sentinelSession) bufferedReportCount() int {
	if s.outbox == nil {
		return 0
	}
	return s.outbox.Len()
}

// policyIdentity derives policy_id/policy_version/policy_hash from what this
// session already resolved. policy_hash is a stable digest of the effective
// write/read policy actually in force (not the raw config file, so
// formatting/comment changes don't spuriously change it) -- enough for a
// fleet operator to notice two Sentinels have diverging effective policy,
// without Prompt 14 needing to implement any policy distribution.
func (s *sentinelSession) policyIdentity() (id, version, hash string) {
	// Once a Fleet-managed policy has been successfully applied, THAT is the
	// actual state being enforced and reported -- not the local pack/file
	// this session started with (which, for a Fleet-managed Sentinel, is
	// only ever a pre-first-reconciliation fallback; see startSentinelSession
	// and loadFleetLKG).
	if ref := s.getFleetPolicyRef(); !ref.Empty() {
		return ref.PolicyID, strconv.Itoa(ref.Version), ref.Hash
	}
	id = "local"
	if s.policyPack != "" {
		id = s.policyPack
		if pack, err := policypack.Get(s.policyPack); err == nil {
			version = pack.Version
		}
	}
	b, _ := json.Marshal(runmeta.BuildPolicySummary(s.policyPath, s.getCfg()))
	sum := sha256.Sum256(b)
	hash = hex.EncodeToString(sum[:])[:16]
	return id, version, hash
}

// governanceCounters summarizes evs the same way the Sentinel viewer's
// activity feed does (internal/web/sentinel.go): FILE_* events are allowed
// mutations; POLICY_DENY/APPROVAL_REQUIRED are denials, further split by
// whether the revert Meta recorded success or failure. lastEventAt is the
// timestamp of the most recent governance-relevant event, or nil if none
// have occurred yet.
func governanceCounters(evs []events.Event) (allow, deny, reverted, revertFailed int, lastEventAt *time.Time) {
	for i := range evs {
		e := evs[i]
		switch {
		case strings.HasPrefix(e.Type, "FILE_"):
			allow++
		case e.Type == "POLICY_DENY" || e.Type == "APPROVAL_REQUIRED":
			deny++
			failed := false
			if rv, ok := e.Meta["reverted"].(bool); ok {
				if rv {
					reverted++
				} else {
					failed = true
				}
			}
			if es, ok := e.Meta["revert_error"].(string); ok && es != "" {
				failed = true
			}
			if failed {
				revertFailed++
			}
		default:
			continue
		}
		ts := e.TS
		lastEventAt = &ts
	}
	return allow, deny, reverted, revertFailed, lastEventAt
}

// --- Fleet policy reconciliation and trust (Prompts 14A / 14B) --------------
//
// A heartbeat response carries the control plane's desired policy, if one is
// assigned (fleet.HeartbeatResponse). reconcileFleetPolicy is what turns
// "desired differs from actual" into a real, local policy swap -- entirely on
// the fleet goroutine, never blocking or being blocked by the recorder. The
// only interaction with live enforcement is the single, atomic
// Recorder.SetPolicy call, made only after a fetched policy has been fully
// fetched, integrity-checked, signature-verified, downgrade-checked, and
// durably installed -- so a slow, failing, or untrusted reconciliation
// attempt can never leave the recorder in a half-updated state, and can never
// delay a filesystem decision that is already in flight.
//
// The core invariant on this side: a Sentinel does not trust the control
// plane merely because something answered an HTTP request. Everything below
// is verification of what came back, not of the fact that something came
// back.

// reconcileFleetPolicy compares resp's desired policy against what this
// session currently enforces and, only if they differ, fetches, verifies, and
// atomically installs the new version. An empty DesiredPolicyID means "not
// (or no longer) Fleet-policy-managed" -- Sentinel keeps enforcing whatever
// it already has rather than treating a missing assignment as "clear my
// policy."
func (s *sentinelSession) reconcileFleetPolicy(resp fleet.HeartbeatResponse) {
	if resp.DesiredPolicyID == "" {
		return
	}
	desired := fleet.PolicyRef{PolicyID: resp.DesiredPolicyID, Version: resp.DesiredPolicyVersion, Hash: resp.DesiredPolicyHash}
	if s.getFleetPolicyRef().Equal(desired) {
		return // already in sync; do not re-fetch/re-apply identical desired state
	}
	// A desired ref this Sentinel has already rejected on trust grounds is
	// not retried: a bad signature will not become valid on the next tick,
	// and re-fetching it every heartbeat would be noise. Only deterministic
	// trust failures are latched this way -- transient fetch failures are
	// always retried (see failReconcile).
	//
	// The latch includes the rollback authorization presented with the ref,
	// so an operator who responds to a DOWNGRADE_REJECTED by issuing a signed
	// grant for that same version gets a fresh attempt rather than silence.
	grantSig := ""
	if resp.RollbackGrant != nil {
		grantSig = resp.RollbackGrant.Signature
	}
	if s.alreadyRejected(desired, grantSig) {
		return
	}

	// A real, observable "actively working on it" window -- reported before
	// the network fetch, not fabricated after the fact.
	s.reportReconcileStatus(fleet.ReconcileInProcess, "", desired.Hash)

	pv, err := s.fleetClient.GetPolicyVersion(desired.PolicyID, desired.Version)
	if err != nil {
		s.failReconcile(desired, fmt.Sprintf("fetch failed: %v", err))
		return
	}
	if pv.Hash != desired.Hash {
		s.rejectReconcile(fleet.ReconcileFailed, desired, grantSig, fmt.Sprintf("fetched content hash %s does not match desired hash %s -- refusing to apply", pv.Hash, desired.Hash))
		return
	}
	// Recompute both digests from the fetched bytes rather than trusting any
	// field the control plane sent. Everything downstream -- the signature
	// check and the rollback binding -- is checked against these locally
	// derived values.
	digest, short, newCfg, err := fleet.ComputePolicyDigest(pv.YAML)
	if err != nil {
		s.rejectReconcile(fleet.ReconcileFailed, desired, grantSig, fmt.Sprintf("fetched policy failed to parse: %v", err))
		return
	}
	if short != desired.Hash {
		s.rejectReconcile(fleet.ReconcileFailed, desired, grantSig, "recomputed hash does not match desired hash -- refusing to apply")
		return
	}
	if pv.Digest != "" && pv.Digest != digest {
		s.rejectReconcile(fleet.ReconcileFailed, desired, grantSig, "recomputed digest does not match the digest the control plane published -- refusing to apply")
		return
	}
	pv.Digest = digest

	if err := s.verifyFleetPolicy(pv); err != nil {
		s.rejectReconcile(fleet.SignatureInvalid, desired, grantSig, err.Error())
		return
	}
	if err := s.checkDowngrade(desired, digest, resp.RollbackGrant); err != nil {
		s.rejectReconcile(fleet.DowngradeRejected, desired, grantSig, err.Error())
		return
	}

	maxAccepted := s.acceptedVersions(desired)
	if err := installFleetPolicy(s.repoAbs, pv, maxAccepted); err != nil {
		s.failReconcile(desired, fmt.Sprintf("could not install policy atomically: %v", err))
		return
	}

	s.applyFleetPolicy(desired, newCfg, pv, maxAccepted)
	fmt.Printf("Fleet policy reconciled: %s v%d (hash %s, %s) now active\n",
		desired.PolicyID, desired.Version, desired.Hash, strings.ToLower(s.getSignatureState()))
	s.bufferReport(fleet.ReportPolicyApplied, time.Now().UTC(), "",
		fmt.Sprintf("applied %s v%d (%s)", desired.PolicyID, desired.Version, strings.ToLower(s.getSignatureState())))
	s.writeFleetStatus("")
	// Report success immediately rather than waiting for the next regular
	// heartbeat tick (up to a full heartbeat interval later): the control
	// plane's IN_SYNC display should catch up to real enforcement promptly,
	// not lag it. buildHeartbeatRequest already reflects the new
	// fleetPolicyRef, so this is an ordinary heartbeat -- best-effort like
	// every other fleet call.
	if _, err := s.fleetClient.Heartbeat(s.buildHeartbeatRequest()); err != nil {
		fmt.Printf("WARN: fleet post-reconcile heartbeat failed: %v (will report as usual on the next interval)\n", err)
	}
}

// verifyFleetPolicy is the signature gate.
//
// If this Sentinel has pinned a control-plane signing key, a policy MUST be
// signed by it -- unsigned or differently-signed content is refused. If no
// key has ever been pinned (a control plane that does not sign policy, i.e.
// the pre-14B configuration), the policy is applied with the 14A integrity
// checks alone and loudly labeled UNSIGNED, so the weaker posture is visible
// rather than implied.
//
// The direction of that rule matters: trust only ever ratchets up. A Sentinel
// that has established a signing relationship cannot be talked back down to
// accepting unsigned policy by a control plane that simply stops signing.
func (s *sentinelSession) verifyFleetPolicy(pv fleet.PolicyVersion) error {
	trust := s.getTrust()
	if trust.Empty() {
		s.setSignatureState("UNSIGNED", "")
		fmt.Printf("WARN: applying UNSIGNED Fleet policy %s v%d -- this control plane advertises no signing key\n", pv.PolicyID, pv.Version)
		return nil
	}
	if err := fleet.VerifyPolicyVersion(pv, trust); err != nil {
		return fmt.Errorf("policy signature rejected: %w", err)
	}
	s.setSignatureState("VERIFIED", pv.Issuer)
	return nil
}

// checkDowngrade enforces the anti-downgrade rule: a Sentinel never moves to
// a version older than the highest it has already accepted for that policy,
// unless the control plane presents a valid signed RollbackGrant for exactly
// this Sentinel, policy, version, and content digest.
//
// The grant -- not a flag, not a timestamp -- is what authorizes the move.
// An attacker able to rewrite heartbeat responses can set any field they
// like; they cannot produce a signature over one.
func (s *sentinelSession) checkDowngrade(desired fleet.PolicyRef, digest string, grant *fleet.RollbackGrant) error {
	highest := s.highestAccepted(desired.PolicyID)
	if desired.Version >= highest {
		return nil
	}
	trust := s.getTrust()
	if trust.Empty() {
		return fmt.Errorf("refusing to move %s from v%d back to v%d: rollback requires a signed authorization and this Sentinel trusts no signing key",
			desired.PolicyID, highest, desired.Version)
	}
	if err := fleet.VerifyRollbackGrant(grant, trust, s.sentinelID, desired, digest, time.Now().UTC()); err != nil {
		return fmt.Errorf("refusing to move %s from v%d back to v%d: %v", desired.PolicyID, highest, desired.Version, err)
	}
	fmt.Printf("Fleet rollback authorized by signed grant: %s v%d -> v%d\n", desired.PolicyID, highest, desired.Version)
	return nil
}

// acceptedVersions returns the updated anti-downgrade high-water map that
// accepting desired implies.
//
// An authorized rollback LOWERS the mark to the version it authorized, rather
// than leaving a stale higher one in place. That is deliberate: the grant is
// an explicit operator statement that this older version is now current, and
// keeping the old high mark would force a signed grant for every ordinary
// forward step afterwards. It does not weaken the guarantee -- an attacker
// still cannot push anything below the lowest version an operator has
// actually authorized, because getting there at all required a valid grant.
func (s *sentinelSession) acceptedVersions(desired fleet.PolicyRef) map[string]int {
	s.policyMu.RLock()
	out := make(map[string]int, len(s.maxAccepted)+1)
	for k, v := range s.maxAccepted {
		out[k] = v
	}
	s.policyMu.RUnlock()
	out[desired.PolicyID] = desired.Version
	return out
}

// alreadyRejected reports whether this exact attempt -- same desired ref,
// same rollback authorization -- has already been refused.
func (s *sentinelSession) alreadyRejected(desired fleet.PolicyRef, grantSig string) bool {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.lastRejectedRef.Equal(desired) && s.lastRejectedGrantSig == grantSig
}

func (s *sentinelSession) highestAccepted(policyID string) int {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.maxAccepted[policyID]
}

// applyFleetPolicy is the single moment a verified policy becomes the policy
// actually being enforced. Recorder.SetPolicy is an atomic pointer store, so
// the very next filesystem evaluation uses the new config and none of them
// ever observe a half-applied state.
func (s *sentinelSession) applyFleetPolicy(desired fleet.PolicyRef, cfg *policy.Config, pv fleet.PolicyVersion, maxAccepted map[string]int) {
	s.policyMu.Lock()
	s.cfg = cfg
	s.fleetPolicyRef = desired
	s.maxAccepted = maxAccepted
	s.lastRejectedRef = fleet.PolicyRef{}
	s.lastRejectedGrantSig = ""
	s.policyMu.Unlock()
	s.rec.SetPolicy(cfg)
}

// reportReconcileStatus sends an out-of-band heartbeat carrying only a
// reconcile self-report, best-effort. A failure here is logged and swallowed
// like every other fleet call -- it never affects local enforcement, and a
// missed status report is superseded by the next regular heartbeat regardless.
func (s *sentinelSession) reportReconcileStatus(status, errMsg, forHash string) {
	req := s.buildHeartbeatRequest()
	req.ReconcileStatus = status
	req.ReconcileError = errMsg
	req.ReconcileForHash = forHash
	if _, err := s.fleetClient.Heartbeat(req); err != nil {
		s.noteFleetError(err)
	}
}

// failReconcile records a TRANSIENT reconciliation failure (a fetch that did
// not complete). The current policy is untouched, and the same desired ref
// will be retried on the next heartbeat.
func (s *sentinelSession) failReconcile(desired fleet.PolicyRef, reason string) {
	fmt.Printf("WARN: fleet policy reconciliation failed for %s v%d: %s (keeping last-known-good policy)\n", desired.PolicyID, desired.Version, reason)
	s.reportReconcileStatus(fleet.ReconcileFailed, reason, desired.Hash)
	s.bufferReport(fleet.ReportReconcileFailed, time.Now().UTC(), "", fmt.Sprintf("%s v%d: %s", desired.PolicyID, desired.Version, reason))
	s.writeFleetStatus(reason)
}

// rejectReconcile records a DETERMINISTIC refusal -- bad content, bad
// signature, or an unauthorized downgrade. Like failReconcile it leaves the
// current last-known-good policy completely untouched (the whole point of
// verify-before-install: an untrusted remote policy must never replace a
// valid local one, and Sentinel never falls back to "no policy"), but it also
// latches the rejected ref so the same doomed attempt is not repeated every
// heartbeat.
func (s *sentinelSession) rejectReconcile(status string, desired fleet.PolicyRef, grantSig, reason string) {
	fmt.Printf("WARN: fleet policy %s v%d REJECTED (%s): %s (keeping last-known-good policy)\n", desired.PolicyID, desired.Version, status, reason)
	s.policyMu.Lock()
	s.lastRejectedRef = desired
	s.lastRejectedGrantSig = grantSig
	s.policyMu.Unlock()
	s.reportReconcileStatus(status, reason, desired.Hash)
	reportType := fleet.ReportSignatureInvalid
	switch status {
	case fleet.DowngradeRejected:
		reportType = fleet.ReportDowngradeRejected
	case fleet.ReconcileFailed:
		reportType = fleet.ReportReconcileFailed
	}
	s.bufferReport(reportType, time.Now().UTC(), "", fmt.Sprintf("%s v%d: %s", desired.PolicyID, desired.Version, reason))
	s.writeFleetStatus(reason)
}

// --- Buffered fleet reporting (Prompt 14B) ----------------------------------

// collectReports turns governance events this session has logged since the
// last pass into metadata-only fleet reports. It reads only the event type,
// timestamp, and path -- never the diff, never file contents -- so what is
// buffered for upload can never carry repository data off the machine.
func (s *sentinelSession) collectReports() {
	if s.outbox == nil {
		return
	}
	evs := s.logger.EventsSnapshot()
	for i := s.reportCursor; i < len(evs); i++ {
		e := evs[i]
		typ := reportTypeFor(e)
		if typ == "" {
			continue
		}
		s.bufferReport(typ, e.TS, e.Path, e.Summary)
	}
	s.reportCursor = len(evs)
}

// reportTypeFor classifies one governance event, mirroring how
// governanceCounters and the Sentinel viewer already read the same events:
// a denial that was reverted is REVERTED, one whose revert failed is
// REVERT_FAILED (the case an operator most needs to see at fleet level), and
// anything else denied is DENY.
func reportTypeFor(e events.Event) string {
	if e.Type != "POLICY_DENY" && e.Type != "APPROVAL_REQUIRED" {
		return ""
	}
	if es, ok := e.Meta["revert_error"].(string); ok && es != "" {
		return fleet.ReportRevertFailed
	}
	if rv, ok := e.Meta["reverted"].(bool); ok {
		if rv {
			return fleet.ReportReverted
		}
		return fleet.ReportRevertFailed
	}
	return fleet.ReportDeny
}

// bufferReport durably buffers one metadata-only report. The report id is
// derived deterministically from its content, so re-buffering or re-uploading
// the same event never produces a second fleet alert.
func (s *sentinelSession) bufferReport(typ string, at time.Time, path, summary string) {
	if s.outbox == nil || s.sentinelID == "" {
		return
	}
	rel := path
	if rel != "" {
		if r, err := filepath.Rel(s.repoAbs, path); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		}
	}
	_ = s.outbox.Add(fleet.Report{
		ID:         fleet.ReportID(s.sentinelID, s.sessionID, typ, at, rel+"|"+summary),
		SentinelID: s.sentinelID,
		SessionID:  s.sessionID,
		Type:       typ,
		At:         at.UTC(),
		Path:       rel,
		Summary:    summary,
		RepoPath:   s.repoAbs,
	})
}

// flushReports uploads buffered reports once the control plane is reachable
// and this Sentinel is authenticated. Only ids the control plane explicitly
// acknowledged are cleared, so a partial or failed flush leaves the remainder
// buffered rather than silently losing it. Nothing about local enforcement
// waits on any of this.
func (s *sentinelSession) flushReports() {
	if s.outbox == nil || s.outbox.Len() == 0 {
		return
	}
	batch := s.outbox.Batch()
	resp, err := s.fleetClient.SendReports(fleet.ReportBatch{SentinelID: s.sentinelID, Reports: batch})
	if err != nil {
		s.noteFleetError(err)
		return
	}
	if err := s.outbox.Ack(resp.AcceptedIDs); err != nil {
		fmt.Printf("WARN: could not clear delivered fleet reports: %v\n", err)
	}
}

// noteFleetError centralizes how a failed fleet call is interpreted. A
// revoked credential is a state, not a transient error: it is recorded,
// reported locally, and announced once rather than repeated every tick --
// and, critically, it changes nothing about local enforcement.
func (s *sentinelSession) noteFleetError(err error) {
	if errors.Is(err, fleet.ErrCredentialRevoked) {
		if s.getIdentityState() != "REVOKED" {
			fmt.Printf("WARN: this Sentinel's Fleet credential has been REVOKED by the control plane.\n")
			fmt.Printf("      Fleet participation has stopped. Local governance of %s continues unchanged,\n", s.repoAbs)
			fmt.Printf("      still enforcing its last-known-good policy. Revocation removes a Sentinel from\n")
			fmt.Printf("      the fleet; it is not a remote instruction to stop protecting this repository.\n")
			s.setIdentityState("REVOKED")
			s.bufferReport(fleet.ReportCredentialRevoked, time.Now().UTC(), "", "fleet credential revoked; local enforcement continues")
			s.writeFleetStatus("fleet credential revoked")
		}
		return
	}
	fmt.Printf("WARN: fleet call failed: %v (continuing local governance)\n", err)
}

// writeFleetStatus refreshes the locally-readable trust status file.
func (s *sentinelSession) writeFleetStatus(lastErr string) {
	if s.fleetClient == nil {
		return
	}
	ref := s.getFleetPolicyRef()
	st := fleetStatusFile{
		FleetURL:       s.fleetClient.BaseURL(),
		SentinelID:     s.sentinelID,
		Connected:      s.isConnected(),
		Identity:       s.getIdentityState(),
		SignerKeyID:    s.getSignerKeyID(),
		SignatureState: s.getSignatureState(),
		PolicyID:       ref.PolicyID,
		PolicyVersion:  ref.Version,
		PolicyHash:     ref.Hash,
		LastError:      lastErr,
	}
	if s.outbox != nil {
		st.BufferedReports = s.outbox.Len()
		st.DroppedReports = s.outbox.DroppedCount()
	}
	saveFleetStatus(s.repoAbs, st)
}
