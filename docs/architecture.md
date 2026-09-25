# Sentinel Airlock — Architecture

## Execution Boundary Diagram

```
  ┌─────────────────────────────────────────────────────────┐
  │                    airlock run                          │
  │                                                         │
  │  ┌──────────┐   Policy + Risk   ┌──────────────────┐  │
  │  │  Config   │ ───────────────▶ │   Governance     │  │
  │  │ airlock   │                  │ ClassifyCommand() │  │
  │  │  .yaml    │                  │ Decide() → allow  │  │
  │  └──────────┘                   │           deny    │  │
  │                                 └────────┬─────────┘  │
  │                                          │ allow        │
  │                                          ▼              │
  │  ┌──────────┐   Copy repo     ┌──────────────────┐    │
  │  │  Repo    │ ──────────────▶ │   Workspace      │    │
  │  │ (source) │                 │ .airlock/work-   │    │
  │  └──────────┘                 │ spaces/<id>/repo │    │
  │                               └────────┬─────────┘    │
  │                                        │               │
  │  ┌──────────┐  Execute in sandbox      ▼               │
  │  │  Agent   │ ──────────────▶ ┌──────────────────┐    │
  │  │ Adapter  │                 │ Sandbox Engine    │    │
  │  │(generic- │                 │  workspace mode:  │    │
  │  │  shell,  │                 │  dir copy + watcher│   │
  │  │  codex…) │                 │  container mode:  │    │
  │  └──────────┘                 │  Docker/Colima/   │    │
  │                               │  Podman           │    │
  │                               └────────┬─────────┘    │
  │                                        │               │
  │         FS Watcher (recorder)          │               │
  │  FILE_CREATE / FILE_WRITE / POLICY_DENY│               │
  │  ◀─────────────────────────────────────               │
  │         ▼                                              │
  │  ┌──────────────────────────────────────────────────┐ │
  │  │                  Artifact Set                     │ │
  │  │  events.jsonl   session_events.jsonl              │ │
  │  │  run_manifest.json   changes.patch                │ │
  │  │  run_digest.json     run_digest.sig (optional)    │ │
  │  │  report/index.html   review.json                  │ │
  │  │  checkpoints/cp-0/                                │ │
  │  └──────────────────────────────────────────────────┘ │
  └─────────────────────────────────────────────────────────┘
```

---

## Run Lifecycle

Every `airlock run` follows this 22-step pipeline:

```
 1. Load airlock.yaml + merge policy pack (balanced/strict/ci-safe/…)
 2. Apply execution mode defaults (dev/team/ci → sandbox/network/approval)
 3. Resolve adapter by name (generic-shell, codex, ollama, …)
 4. Generate run_id (UUID); create .airlock/runs/<run_id>/
 5. Open events logger (events.jsonl) + session sink (session_events.jsonl)
 6. Emit RUN_START event
 7. Copy repo → isolated workspace (.airlock/workspaces/<run_id>/repo)
 8. Snapshot workspace as checkpoint cp-0
 9. Adapter.Prepare() → Invocation{Executable, Args, DisplayCommand}
10. Resolve sandbox mode (workspace / container / off)
    → container: DetectRuntime() → fallback to workspace if --fallback-workspace
11. Evaluate env denials, sensitive path references, network allowlist
12. governance.ClassifyCommand() + Decide() → allow or block
    → block: emit CMD event (risk=high, approval=deny), skip to step 16
13. recorder.New() + rec.Start() — watch workspace for file events
14. execution.Run() — executes agent in sandbox
15. rec.Stop() — flush recorded file events
16. gitops.CreatePatchForPaths() → changes.patch
17. Build RunManifest (policy, sandbox, risk/approval summary, touched/denied paths)
18. runmeta.BuildDigest() → run_digest.json (SHA-256 per artifact)
19. Optional: ed25519 sign digest → run_digest.sig
20. report.Generate() → report/index.html (static, self-contained, no external deps)
21. output.PrintRunSummary() → terminal summary + next-step hints
22. refreshIndex() → update .airlock/index.json
```

---

## Artifact Model

All artifacts for a run are stored under `.airlock/runs/<run_id>/`:

| File | Description |
|---|---|
| `events.jsonl` | Structured event log — policy decisions, file events, risk classifications |
| `session_events.jsonl` | Model/tool/message session trace (adapter-dependent) |
| `run_manifest.json` | Full run metadata — adapter, sandbox, network, policy, risk/approval summary |
| `run_digest.json` | SHA-256 digest of artifact set (tamper-evident) |
| `run_digest.sig` | Optional ed25519 signature over the digest |
| `changes.patch` | Unified diff — workspace state vs original repo at run start |
| `report/index.html` | Static HTML evidence report (self-contained, no external dependencies) |
| `checkpoints/cp-0/` | Full workspace snapshot taken before agent execution |
| `review.json` | Review decision artifact — state, note, reviewer, timestamp |
| `review_events.jsonl` | Audit log of review state changes |
| `rollback.json` | Rollback record — checkpoint, mode, paths, timestamp, status (written by `airlock rollback`) |
| `build_info.json` | Airlock version, commit, build date at run time |

The artifact set is designed for offline use. All post-run commands (`inspect`, `replay`, `verify`, `serve`) read from this set with no live agent connection.

---

## Policy Model

### Config hierarchy

```
airlock.yaml (per-project)
  + policy pack merge (--policy-pack balanced|strict|ci-safe|oss-maintainer|research)
  + execution mode defaults (--mode dev|team|ci)
  + per-run flags (--sandbox, --network, --approval)
```

### Path policy

```yaml
policy:
  deny_read:  ["**/.env", "**/*.pem", "**/.ssh/**"]
  deny_write: [".git/**", ".airlock/**"]
  allow_write: ["src/**", "app/**"]
```

`deny_write` and `deny_read` are evaluated against every file event by the filesystem watcher. A write matching `deny_write` is immediately reverted and a `POLICY_DENY` event is recorded with a diff.

### Risk classification

`governance.ClassifyCommand()` maps commands to:
- **Level:** `low` / `medium` / `high`
- **Category:** `command`, `file`, `network`, `secret`, etc.

High-risk patterns (e.g. `rm -rf`, `chmod -r`, `curl | sh`) are caught pre-execution.

### Approval modes

| Mode | Behavior |
|---|---|
| `auto` | Allow all (record everything) |
| `prompt` | Interactive — ask the operator at run time |
| `deny-high-risk` | Block any command classified `high` before execution |

### Execution mode presets

| Mode | Sandbox | Network | Approval |
|---|---|---|---|
| `dev` (default) | workspace | off | auto |
| `team` | container | allowlist | deny-high-risk |
| `ci` | container | off | deny-high-risk |

---

## Sandbox Modes

### `workspace` (default)

Repo is copied to an isolated directory before execution. A filesystem watcher records every file event. The original working directory is not modified during execution.

**Limitation:** The agent process runs on the host OS. The workspace directory boundary is best-effort, not OS-enforced. Container mode is recommended for stronger isolation.

### `container`

Agent executes inside a Docker, Colima, or Podman container. Airlock auto-detects the available runtime. Provides stronger process and filesystem isolation.

`--fallback-workspace`: falls back to workspace mode if no runtime is found. The actual mode used is always recorded in `run_manifest.json`.

**Limitation:** Container security depends on runtime configuration. Airlock does not configure seccomp, AppArmor, or rootless settings. Configure those at the runtime level.

### `off`

No isolation. Agent executes directly in the working directory. Use only when isolation is handled externally.

---

## Replay / Review / Verify Model

These three commands operate entirely on the artifact set — no agent required:

**`airlock replay <id>`**
- Reads `events.jsonl` + `session_events.jsonl`
- Merges and sorts by timestamp
- Prints terminal timeline with markers: `⛔` for denied/blocked events, `·` for file changes
- `--tail N` to show last N rows; `--json` for structured output

**`airlock review <id> --state <state>`**
- Writes `review.json`: `{ state, note, reviewer, timestamp }`
- Valid states: `unreviewed` / `approved` / `rejected` / `needs-attention`
- Appends a `REVIEW_UPDATED` event to `review_events.jsonl`
- Regenerates `report/index.html` so review state is reflected immediately

**`airlock verify <id>`**
- Reads `run_digest.json` (SHA-256 per artifact)
- Recomputes hashes for: `events.jsonl`, `session_events.jsonl`, `run_manifest.json`, `changes.patch`, `checkpoints.meta`
- Compares stored vs current
- If signed: verifies ed25519 signature against `run_digest.sig`
- Outputs: `verified-signed` / `verified-unsigned` / `hash-mismatch` / `signature-invalid`

**Digest policy:**

| Artifact | In digest | Notes |
|---|---|---|
| `events.jsonl` | ✓ | Core evidence; also mutated by `rollback` which rebuilds digest |
| `session_events.jsonl` | ✓ | Session trace |
| `run_manifest.json` | ✓ | Also mutated by `export` (adds export path); export rebuilds digest |
| `changes.patch` | ✓ | Workspace diff |
| `checkpoints.meta` | ✓ | Hash of checkpoint file names |
| `report/index.html` | ✗ | Display artifact; regenerated by `review`/`rollback` |
| `review.json` | ✗ | Mutable by design — review gate |
| `rollback.json` | ✗ | Written by `rollback` |
| `review_events.jsonl` | ✗ | Review audit log |
| `run_digest.json` | ✗ | Cannot hash itself |
| `run_digest.sig` | ✗ | Signature over digest |
| `build_info.json` | ✗ | Written by `export` |
| `airlock-run-*.zip` | ✗ | Export bundle |

Sanctioned mutations (by `export` and `rollback`) rebuild `run_digest.json` automatically so `airlock verify` continues to return `verified-unsigned` after those commands. Third-party modifications to any digested file will produce `hash-mismatch`.

---

## Rollback Model

**`airlock rollback <id>`** (or `latest`) restores the isolated run workspace from checkpoint `cp-0`.

### What it restores

The workspace at `.airlock/workspaces/<run_id>/repo` — the directory where the agent executed. The original source repo (`--repo` path) is never modified by Airlock at any point.

### Modes

| Mode | Command |
|---|---|
| Full restore | `airlock rollback <id>` |
| Subtree restore | `airlock rollback <id> --path src/slides` |
| Preview only | `airlock rollback <id> --dry-run` |
| Skip prompt | `airlock rollback <id> --force` |

### Post-rollback artifact updates

After restoring the workspace, Airlock updates the artifact set so it stays consistent:

1. Appends a `ROLLBACK` event to `events.jsonl` with mode, checkpoint, and paths
2. Sets `review.json` to `needs-attention` — a prior approval is not silently left in place
3. Rebuilds `run_digest.json` — so `airlock verify` returns `verified-unsigned`, not `hash-mismatch`
4. Writes `rollback.json` — permanent rollback record (run_id, checkpoint, mode, timestamp, status)
5. Regenerates `report/index.html` — rollback event and new review state appear immediately

### Limitations

- **Workspace-only.** Does not touch your original `--repo` path.
- **One checkpoint per run (`cp-0`)**, taken before agent execution starts.
- **No operation-level rollback** — cannot undo the last N agent moves. Future work.
- **No patch-reverse** — `changes.patch` has absolute paths into the workspace; applying in reverse is not supported in this release.

---

## Sentinel Mode (`airlock sentinel`)

Sentinel continuously governs a real repository instead of one execution. The writer does not need to be launched through Airlock — OpenClaw, Claude Code, Codex, an IDE, a shell command, or any other local process can write to the repo, and Sentinel reacts the same way regardless of which one it was.

```
  writer / agent   (OpenClaw, Claude Code, Codex, an IDE, a shell command, anything)
        │
        ▼
  real repository
        │
        ▼
     Sentinel
        │
  local policy engine
     /        \
  ALLOW      DENY
                │
              REVERT
```

**Sentinel v1 is userspace: Detect → Evaluate → Revert.** It is not kernel-level pre-write enforcement — a filesystem watcher observes mutations after the OS has already accepted them. "Best-effort filesystem governance. Changes are observed after the OS accepts them." Prohibited bytes can briefly exist on disk; Airlock does not claim otherwise (see [`SECURITY.md`](../SECURITY.md) for the full statement).

**How it maps onto the `airlock run` primitives it reuses:**
- `sandbox=off`, execution in-place against the real `--repo` (no isolated workspace copy)
- creates a session checkpoint at start, same as a run's `cp-0`
- evaluates every mutation with the same `governance`/`policy` engine `airlock run` uses
- allows permitted mutations, reverts denied ones, and produces the same artifact set (`events.jsonl`, `run_manifest.json`, etc.) under `.airlock/runs/<session-id>/`
- runs persistently in the background when started with `--background`, with its own PID/status/stop lifecycle (`internal/cli/sentinel_lifecycle.go`)

Restarting Sentinel starts a new session (`session_id`) but keeps its durable identity (`sentinel_id`, when Fleet-enrolled) and never erases the history of earlier sessions — see the Fleet section below.

**Watcher reconciliation.** fsnotify only reports a directory's own CREATE event; a writer that creates a directory and immediately populates it (a single `mkdir -p a/b/c && write a/b/c/file`, for example) can do so faster than `internal/recorder` installs a watch on each new level, and the kernel never re-delivers an event it already fired. `internal/recorder.reconcileSubtree` closes this by walking a newly-observed directory immediately after installing its watch and evaluating any file not already known to the recorder exactly as if its CREATE event had arrived, plus an infrequent (30s) full-tree safety pass for the same reason during long-running sessions. This is reconciliation against on-disk state, not a change to the detect → evaluate → revert model above — a `.env` denied inside a brand-new directory is still detected and reverted after landing on disk, just via the reconciliation path instead of (or in addition to) the direct fsnotify path when the two race.

---

## Fleet / Control Plane (`airlock fleet`)

Fleet coordinates desired-state policy across many Sentinels. The critical architectural property is that it is **not** in the filesystem-decision path:

```
                   Airlock Fleet
                coordination/policy
                       plane
                         │
            ┌────────────┼────────────┐
            │            │            │
        Sentinel     Sentinel     Sentinel
            │            │            │
          repo A       repo B       repo C
            │            │            │
         agents       agents       agents
```

Filesystem allow/deny decisions are made locally by the Sentinel watching that repository — never `filesystem write → remote Fleet request → allow/deny`. This is what makes the following invariant hold:

```
Fleet unavailable  ≠  local governance unavailable
```

A Sentinel keeps its last-known-good policy and keeps enforcing it locally when Fleet cannot be reached, or after its Fleet credential has been revoked.

**Trust model** (full detail in [`SECURITY.md`](../SECURITY.md)):
- One-time enrollment tokens → durable, opaque per-Sentinel credentials (Fleet stores only hashes)
- Ed25519-signed policy versions, verified by each Sentinel against a pinned public key
- A full SHA-256 policy digest for the actual security check; a short 16-hex digest for display/drift only
- Anti-downgrade high-water marks per policy id, overridable only by an explicit signed rollback grant
- Revocation that stops Fleet from trusting/issuing new policy to a Sentinel, but never stops that Sentinel's local enforcement
- A locally re-verified last-known-good policy (digest + signature re-checked on every load)
- Bounded, deduplicated, buffered status/metadata reporting across outages

**Fleet capabilities:** Sentinel enrollment and inventory, durable machine/Sentinel/session identity, heartbeats, desired-state policy assignment and reconciliation, drift reporting, and session history across restarts (`airlock fleet sessions`/`session`) — including honest ACTIVE/STOPPED/INTERRUPTED status computed from facts, never fabricated.

**What Fleet never receives:** raw repository contents, diffs, patches, or evidence. Those stay on the machine that produced them (`airlock inspect/replay/verify <session-id>` reads them locally). Fleet's protocol carries coordination, status, and governance metadata only — there is no upload path for evidence, and no remote-delete or remote-stop capability reaching a Sentinel's disk or enforcement loop.

**Precision on the trust model:** signature verification proves a policy came from whoever holds Fleet's signing key — it does not prove Fleet's operator is trustworthy. A compromised or malicious control plane can sign and distribute a new, valid-looking policy; anti-downgrade defends against replaying an *old* signed policy, not against a *new* one signed with a legitimate (but compromised) key. Protecting that signing key is the deploying operator's responsibility.

Package: `internal/fleet` (control plane server, trust/signing, session store, auth) has zero dependency on `internal/cli` or `internal/web` — it is usable as a standalone control plane library.

---

## Remote Worker Model

```
┌─────────────────────────────┐     ┌───────────────────────────┐
│         operator            │     │       remote worker        │
│                             │     │  airlock worker start      │
│  airlock submit             │────▶│  → runs job locally        │
│  (POST /jobs, poll)         │     │  → same pipeline as local  │
│                             │◀────│  → artifact bundle upload  │
│  airlock fetch <id>         │     └───────────────────────────┘
│  → unpacks to .airlock/runs/│
│                             │
│  airlock inspect/verify/… │
│  (identical to local runs) │
└─────────────────────────────┘
```

Fetched remote runs produce the same artifact set as local runs. All local commands (`inspect`, `replay`, `verify`, `serve`) work identically on fetched artifacts.

**Current limitation:** Shared bearer token auth only. No per-user IAM, roles, or token rotation. Always run the worker behind TLS for non-local deployments. (This is separate from Fleet's per-Sentinel enrollment/credential/revocation model above — the worker executes jobs, Fleet coordinates policy.)

---

## Package Layout

```
internal/
├── adapters/       Agent adapter layer — resolves named adapters
├── agents/         Diagnostics for installed agent backends
├── cli/            One file per CLI command
├── events/         Structured event logger → events.jsonl
├── execution/      Sandbox engine (workspace / container / off)
├── fleet/          Fleet control plane — enrollment, trust/signing, policy, session store
├── gitops/         Patch generation (workspace diff → changes.patch)
├── governance/     Risk classification + approval decisions
├── index/          Fast run listing (.airlock/index.json)
├── output/         CLI summary printer
├── policy/         airlock.yaml config loader
├── policypack/     Named policy packs (balanced/strict/ci-safe/…)
├── providers/      LLM provider clients (anthropic/openai/ollama)
├── recorder/       Filesystem watcher (FILE_READ/FILE_WRITE/POLICY_DENY)
├── remote/         Remote worker HTTP protocol
├── replay/         Terminal timeline replay engine
├── report/         Static HTML evidence report generator
├── review/         review.json artifact (state/note/reviewer/timestamp)
├── runmeta/        Run manifest, digest, artifact loader
├── runner/         Internal runner core
├── session/        Session event sink → session_events.jsonl
├── util/           Shared helpers
├── web/            Local HTTP evidence viewer
└── workspace/      Repo copy/isolation
```
