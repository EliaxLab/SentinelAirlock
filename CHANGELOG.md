# Changelog

All notable changes to Sentinel Airlock are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [2.4.0-rc1] — 2026-09-14

### Added

**Sentinel — persistent, repo-level governance**
- `airlock sentinel --repo .` — continuously governs a real repository regardless of which process writes to it (not limited to workflows launched through `airlock run`)
- `--background` / `--status` / `--stop` lifecycle, mirroring `airlock serve`'s pattern
- Userspace detect → evaluate → revert model: filesystem watcher observes mutations after the OS accepts them, reverts denied ones, and records everything through the same artifact model as `airlock run` (`.airlock/runs/<session-id>/`)
- `sandbox=off`, in-place execution against the real repo; session checkpoint taken at start
- Sentinel status surfaced in the local viewer (`airlock serve`)

**Fleet — control plane for many Sentinels**
- `airlock fleet serve` / `init` / `list` / `status` — control plane with Sentinel enrollment and inventory
- One-time enrollment tokens exchanged for durable, opaque per-Sentinel credentials (Fleet stores only hashes)
- Ed25519-signed desired-state policy (`airlock fleet policy create/assign/show/update`), verified by each Sentinel against a pinned public key; full SHA-256 digest for the security check, short digest for display/drift only
- Policy reconciliation and drift reporting; anti-downgrade high-water marks; explicit signed rollback grants
- `airlock fleet revoke` — revokes a Sentinel's Fleet credential without stopping that Sentinel's local enforcement
- Local last-known-good policy, re-verified (digest + signature) on every load
- Bounded, deduplicated, buffered status/metadata reporting across Fleet outages
- `airlock fleet sessions` / `session` — durable session history per Sentinel across restarts, with honest ACTIVE/STOPPED/INTERRUPTED status computed from facts, never fabricated
- `airlock fleet alerts` — recent fleet-wide governance alerts
- Fleet governance/session-history views in the local viewer
- Architectural invariant throughout: Fleet is never in the filesystem-decision path, and Fleet unavailability never disables local Sentinel enforcement

### Fixed
- `make release-artifacts` now emits binaries named exactly as `scripts/install.sh` expects (no version segment in the filename), removing a manual rename step that previously had to happen before every release; also now emits `dist/checksums.txt`

### Known Limitations
- Sentinel is a userspace watcher, not kernel-level mandatory access control — see `airlock sentinel --help` and `SECURITY.md` for the precise detect/evaluate/revert model and its race window
- Fleet's own operator access is single-deployment (no multi-tenant SSO/RBAC); per-Sentinel credentials are enrolled/revocable, but this is a control plane you run yourself, not a hosted service

## [2.3.0-rc1] — 2026-09-01

### Changed
- **License changed from MIT to AGPL-3.0-only.** See [`LICENSE`](LICENSE).

### Added
- `airlock policy configure` — interactive first-run setup for common sensitive-path deny rules (`.env`, `*.key`, `*.pem`, `secrets/**`, `credentials/**`, custom paths) and network mode. Preserves the rest of `airlock.yaml`, is idempotent, and fails cleanly (no hang) on non-interactive stdin.
- `docs/RUNBOOK.md` — canonical command-by-command CLI runbook, linked from the README Quick Start.
- `airlock bootstrap` now prints next-step guidance pointing to `policy configure` and `policy show`.

## [2.2.0-rc1] — 2026-03-08

First release candidate. Covers the full governed run lifecycle, evidence artifact model, all terminal operator flows, and the remote worker foundation.

### Added

**Core run engine**
- Full 22-step governed execution pipeline: policy load → workspace copy → governance → sandbox execution → artifact write → index refresh
- UUID run IDs; all artifacts scoped under `.airlock/runs/<run_id>/`
- Workspace isolation: repo copied to `.airlock/workspaces/<run_id>/repo`; original repo untouched during execution
- Filesystem watcher records `FILE_READ`, `FILE_WRITE`, `POLICY_DENY` events during execution
- Pre-run workspace snapshot at `checkpoints/cp-0/`
- `changes.patch` — unified diff of workspace vs original repo

**Sandbox**
- Three sandbox modes: `workspace` (default), `container`, `off`
- Container mode: Docker, Colima, Podman auto-detection via `DetectRuntime()`
- `--fallback-workspace` flag: graceful fallback if no container runtime found
- Three network modes: `off`, `on`, `allowlist` — configurable per run

**Policy and governance**
- `airlock.yaml` per-project config: workspace ignores, `deny_read` / `deny_write` / `allow_write` glob patterns, network mode, signing key, team name
- Five built-in named policy packs: `balanced`, `strict`, `ci-safe`, `oss-maintainer`, `research`
- Three execution mode presets with automatic sandbox/network/approval defaults: `dev`, `team`, `ci`
- Risk classifier: `ClassifyCommand()` → `low / medium / high` + category label
- Approval modes: `auto`, `prompt`, `deny-high-risk`

**Artifact model**
- `events.jsonl` — structured event log
- `session_events.jsonl` — model/tool/message session trace
- `run_manifest.json` — full run metadata (adapter, sandbox, policy, risk, approval)
- `run_digest.json` — SHA-256 digest of artifact set (tamper evidence)
- `run_digest.sig` — optional ed25519 signature over digest
- `report/index.html` — static HTML evidence report per run (self-contained, no external dependencies)
- `review.json` — review decision artifact (state, note, reviewer, timestamp)
- `rollback.json` — rollback record artifact (run_id, checkpoint, mode, paths, timestamp, status); written by `airlock rollback`

**Terminal operator flows**
- `inspect` — pretty-print run artifacts
- `replay` — terminal event-timeline replay with `--tail`, `--json`, `--stream` flags
- `verify` — digest check + signature verification with `--json` output
- `review` — persist review decision; read-only mode when no `--state` passed
- `export` — evidence bundle as zip or tar.gz; optional report and checkpoint flags
- `rollback` — restore Airlock workspace from checkpoint; supports full restore, path-scoped restore, `--dry-run`, and `--force`
- `patch` — apply or inspect `changes.patch`
- `cleanup` — prune old run artifacts
- `runs` / `index_sync` — fast run listing from `.airlock/index.json`

**Agent diagnostics**
- `agents list` — list installed agent backends
- `agents doctor` — health-check installed backends
- `agents inspect` — detailed backend info
- `agents install-hints` — installation guidance for missing backends

**BYOM Agent Runtime Integration**
- `integrations/byom-agent/` — optional integration showing how to run any process-based or LLM-backed agent under Airlock governance using `generic-shell`
- `integrations/byom-agent/agent.py` — Python stdlib-only agent; reads project context, produces structured notes, optionally attempts policy-denied writes to demonstrate governance boundary
- `integrations/byom-agent/policy.airlock.yaml` — per-integration policy: `allow_write: [docs/**, src/**, app/**]`, `deny_write: [**/.env, secrets/**]`, `network: off`
- `integrations/byom-agent/requirements-optional.txt` — all-commented optional deps (Ollama, openai, langchain-core, langgraph); default mode needs none
- `integrations/byom-agent/README.md` — connection patterns for Ollama, OpenAI-compatible endpoints, LangChain/LangGraph, raw HTTP (stdlib)
- `samples/demo-byom.sh` — two-scenario demo: normal context-aware write (allowed) + governance test (`--attempt-risky`: `.env` + `secrets/demo.pem` blocked)
- `samples/byom-workspace/` — minimal demo project with `README.md`, `src/processor.py`, `docs/.gitkeep`

**Remote worker**
- `worker start` — HTTP job server; accepts jobs, executes locally, serves artifacts
- `submit` — POST job to remote worker, poll for completion, download artifact bundle
- `fetch` — download + unpack remote run artifacts; full local parity (inspect/replay/verify/serve all work on fetched runs)

**Web evidence viewer**
- `serve` — local HTTP viewer with routes: `/runs`, `/runs/:id`, `/compare`, `/review`, `/export`
- `--read-only` flag to disable review writes
- `--open` flag to launch browser automatically

### Changed
- Polished CLI summaries and status wording across major commands
- Improved serve/worker startup messaging and failure clarity
- Updated sample quickstart/demo flows for canonical usage

### Fixed
- Verify classification and review event persistence regressions
- Multiple failure-mode messaging and artifact consistency issues
- `airlock verify` returned `hash-mismatch` after `airlock export`: export updates `run_manifest.json` with export metadata; digest is now rebuilt after the manifest is saved so verify returns `verified-unsigned` consistently after export

### Known Limitations
- Workspace sandbox caveat: agent process runs on host OS; workspace directory boundary is best-effort, not OS-enforced. Container recommended for stronger isolation.
- Network `off` mode in workspace sandbox is advisory, not kernel-enforced
- Only captures workflows launched through Airlock — not a system-wide agent monitor
- Remote worker uses shared-token auth only — no per-user IAM
- Web viewer (`serve`) has no authentication
- Local-first — no hosted control plane
- Rollback restores the Airlock execution workspace (`.airlock/workspaces/<run_id>/repo`), not the original `--repo` source directory; one checkpoint per run (cp-0); operation-level rollback (last N operations) is future work
- `generic-shell` adapter (and BYOM integration) captures process-level evidence only — commands, file events, policy decisions; does not capture model-internal reasoning or token-level traces
