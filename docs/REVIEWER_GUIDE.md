# Sentinel Airlock — Reviewer Guide

> For any OSS evaluator, security/devtool reviewer, platform engineer, or early adopter.

---

## Concept

Sentinel Airlock is a governance and observability layer that wraps agent execution with policy controls and a tamper-evident evidence trail. When an agent runs under Airlock, every command is risk-classified, every file event is recorded, policy violations are blocked and reverted, and the full audit trail is written to a structured artifact set before the run completes. The result is a set of files you can replay, verify, review, and export — with no live agent connection required at review time.

---

## What Airlock Is / Is Not

**Is:**
- A local-first, agent-governance boundary for coding agents
- A structured evidence recorder (events, manifest, patch, digest, HTML report)
- A post-run review/verify/replay toolkit
- An offline-first, single-binary tool (no SaaS, no telemetry)

**Is not:**
- A hosted SaaS dashboard — Fleet, when used, is a control plane you run yourself
- A replacement for OS-level security or network perimeter controls
- Limited to workflows launched through it: `airlock run` only captures what it launches, but `airlock sentinel` governs a repository regardless of which process writes to it (see below)
- A model provider or chat interface

---

## Why Agent-Governance Boundaries Matter

Coding agents are fast. They can write files, run shell commands, and modify repo state in seconds. Without a governance boundary, there is no reliable record of what was attempted, what was blocked, or who reviewed the result.

Airlock answers three questions after every agent run:
1. **What did the agent actually do?** → `events.jsonl`, `changes.patch`
2. **What was allowed vs blocked?** → `run_manifest.json`, `POLICY_DENY` events
3. **Who reviewed it and decided it was safe?** → `review.json`

These artifacts are written at run time, not assembled later. The digest makes tampering detectable.

**Beyond one execution:** `airlock sentinel --repo .` runs this same policy engine persistently against a real repository, reacting to any writer (not just something launched through Airlock). `airlock fleet` coordinates signed desired-state policy across many Sentinels without ever entering the filesystem decision path — see [`docs/architecture.md`](architecture.md) and [`SECURITY.md`](../SECURITY.md) for both.

---

## 5-Minute Path (Recommended Start)

### Prerequisites

| Tool | Required for |
|---|---|
| Go 1.22+ | Build |
| make | Build |
| Git | Clone |

No Docker. No API keys. No internet required.

### Step 1 — Build

```bash
git clone <repo-url>
cd sentinel-airlock
make build
./airlock --version
```

### Step 2 — Try the Quickstart

```bash
bash samples/quickstart.sh
```

This script (~60 seconds) proves the core flow end-to-end:
build → bootstrap → governed run → inspect → verify → viewer.

For the full operator walkthrough (fresh target repo, allow/deny policy, both allowed and denied
agent writes, background viewer, browser-driven rollback, original-repo honesty check):
```bash
bash samples/operator-walkthrough.sh
# PORT=8090 bash samples/operator-walkthrough.sh   # override viewer port
```

Additional examples — governance denial, CLI rollback, BYOM integration — are in [`scripts/dev/`](../scripts/dev/):
```bash
bash scripts/dev/demo-full.sh      # full governance boundary proof
bash scripts/dev/demo-rollback.sh  # CLI rollback (path-scoped + full workspace)
bash scripts/dev/demo-byom.sh      # BYOM agent runtime integration
```

Expected quickstart final output:
```
========================================
 Quickstart complete.

 Next steps:
   cd your-project
   make install PREFIX=$HOME/bin    # put airlock on PATH
   airlock bootstrap
   airlock run --agent generic-shell --cmd '...' --repo .
========================================
```

### Step 3 — Open the HTML Evidence Report

```bash
open .airlock/runs/$(ls -1t .airlock/runs | head -1)/report/index.html
# or launch the viewer:
./airlock serve --read-only --open
```

---

## Full Governance Path (5 minutes)

```bash
bash scripts/dev/demo-full.sh
```

Proves three distinct governance behaviors:

| Scenario | What the agent does | Expected outcome |
|---|---|---|
| 1 — Safe run | Writes only to `src/` | All writes allowed; clean artifacts |
| 2 — Policy denial | Writes `.env` + `deploy_config.yaml` | POLICY_DENY events; files reverted in workspace |
| 3 — Command block | Runs `rm -rf src` | Command blocked before execution; `Status: failed class=policy` |

---

## What to Look For in the HTML Reports

After either demo, each run has a static HTML evidence report at `.airlock/runs/<run_id>/report/index.html`. Open it and check:

**Scenario 1 (safe write):**
- Status badge → `success`
- "Allowed changes" section → `src/artifact.txt`, `src/test_results.txt`
- Patch summary → insertions, no denied changes
- Verification section → `digest present · N artifact(s)`
- Review status → `approved`

**Scenario 2 (policy denial):**
- "Denied / reverted changes" table → `.env` (risk: high, reason: policy deny)
- Evidence timeline → red `POLICY_DENY` rows
- "Allowed changes" → `src/output.txt` (safe path, allowed through)
- No `⛔ Command blocked` alert (command ran; writes were denied mid-execution)

**Scenario 3 (command block):**
- Red `⛔ Command blocked before execution` alert at the top
- Command shown: `rm -rf src`
- Risk badge → `high`, Decision badge → `deny`
- Evidence timeline → `CMD` row marked `BLOCKED`
- Status badge → `failed — command blocked by approval mode: deny`

**On every report and viewer page:**
- **What should I do next?** — a state-dependent guidance card at the top (review the patch, re-review after rollback, inspect denied writes, or nothing to do).
- **Replay summary** — phase-grouped counts before the raw timeline. The ~20 `ENV_DENY` environment-hardening events are collapsed into one neutral "Environment guardrail" note — reserve red for real policy denials, blocked commands, and hash mismatches.
- **Rollback panels** — always state they restore the *Airlock workspace* (`.airlock/workspaces/<id>/repo`), never your original repo. Before rollback: the exact `--dry-run` / `--force` / `--path` commands. After rollback: what was restored and why review reset to `needs-attention`.

The live viewer (`airlock serve`) additionally auto-refreshes when evidence changes on disk, so a `review` or `rollback` run in a terminal updates an open page without a manual reload.

**Two viewer modes:**
- **Read-only** (`airlock serve --read-only`) — safe to hand to a reviewer. State-changing actions (review, rollback, export) appear as terminal commands, never as mutating buttons. Rollback shows *Rollback instructions*.
- **Operator** (`airlock serve`, the default) — local trusted control. Review and a `Restore workspace` rollback can execute directly from the UI after an explicit confirmation. UI rollback runs the same shared implementation as the CLI and still restores only the Airlock workspace, never your original repo.

**Background lifecycle** — either mode can run detached so it does not occupy your terminal:

```bash
airlock serve --background --open              # operator, detached
airlock serve --background --read-only --open  # read-only, detached
airlock serve --status                         # mode / URL / PID / log
airlock serve --stop                           # stop cleanly
```

A recommended operator loop: `serve --background --open` → run a governed agent → open the run page → click **Restore workspace** → the page auto-refreshes to "Workspace rolled back" → `serve --stop`.

**Viewer durability — what to expect:**

The background viewer is a local devtool process, not a system daemon. It stays up until you stop it, kill it, or the OS reclaims it (restart, sleep, memory pressure). Specifically:

- It **survives terminal close** — it runs in its own process group (`PGID == PID`) and is reparented to init (PID 1) when the launching shell exits, so it does not receive `SIGHUP` when your terminal closes.
- It **stays up after 60 minutes of idle** — no keep-alive mechanism needed; `http.Serve` blocks indefinitely until the process exits.
- It **picks up new runs automatically** — the index is rebuilt on each page load and refreshed by the polling fingerprint; a new run appears in the viewer without a restart.
- If the process is killed externally (OOM, `kill -9`), `viewer.json` and `viewer.pid` will be stale. The **next** `airlock serve --status` (or `--stop` or `--background`) call detects the dead PID and auto-cleans the stale files so a new viewer can start.
- **Operator mode** (`airlock serve`) allows UI rollback and review. It should only be run on `localhost`. Do not expose the port on a shared or public network interface.
- **Read-only mode** (`airlock serve --read-only`) is safe to run on a shared machine — all mutating API endpoints return `403 Forbidden`.

Long-run manual checklist:
```
1. airlock serve --background --open
2. airlock serve --status              # confirm mode/URL/PID/log/since
3. <leave running 30-60 min or overnight>
4. airlock serve --status              # should still report same PID
5. airlock run --agent generic-shell --cmd '...' --repo .
6. (browser) reload or wait for auto-refresh (~3 s)  # new run visible
7. airlock serve --stop
8. airlock serve --status              # "No local viewer running."
```

Logs: `.airlock/viewer.log` (stdout + stderr of the background process). `viewer.log` is **not** removed on stop — it is retained for post-mortem inspection.

---

## Feedback Questions

If you evaluate Airlock, these are the questions that most help:

1. **Does the evidence model explain what the agent did?** Is `events.jsonl` / the HTML report enough to reconstruct what happened without access to the agent?

2. **Are approval/review gates placed at the right level?** Should blocking happen at command classification, file-write time, or both? Is the current split right?

3. **What artifact would you need before trusting an agent-generated patch?** Digest? Signature? Named reviewer? What's missing from `review.json`?

4. **Which agent integrations should be prioritized?** (`generic-shell` is the baseline; Claude Code, Codex, and others are adapters. The BYOM integration (`integrations/byom-agent/`) shows how to wire a custom Python agent. Which adapter matters most for your workflow?)

5. **Which sandbox/policy limitations are most important to harden next?** (Workspace network enforcement? Container sandbox by default? Path-deny at the OS level?)

---

## Known Limitations

| Limitation | Detail |
|---|---|
| Local-first | No hosted control plane. All runs and artifacts are stored locally in `.airlock/`. |
| Workspace sandbox caveat | In workspace mode, the agent process runs on the host OS. The workspace directory boundary is best-effort, not OS-enforced. Container mode is recommended for stronger isolation. |
| Network enforcement | Network `off` mode in workspace sandbox records policy intent but does not block syscalls. Use container mode for enforced network isolation. |
| Remote worker auth | Shared bearer token only. No per-user IAM, token rotation, or scoped access at this stage. |
| `airlock run` scope | Workflows not launched through `airlock run` are not recorded by it — it's a run-wrapper. Use `airlock sentinel` to govern a repository regardless of which process writes to it. |
| Sentinel is userspace | Detect → evaluate → revert happens after the OS accepts a write; not kernel-level mandatory access control. Killing the process stops enforcement with no built-in supervision. |
| Web viewer auth | `airlock serve` has no authentication. In **operator mode** this allows UI rollback and review — only run it on `localhost`; never expose the port publicly. **Read-only mode** (`--read-only`) returns `403` on all mutating endpoints and is safe on a shared machine. |
| Viewer process durability | The background viewer is a regular local process, not a system daemon. It survives terminal close (own process group, reparented to init) but not OS restart or `kill -9`. On unexpected exit, `viewer.pid`/`viewer.json` become stale and are auto-cleaned on the next `--status`/`--stop`/`--background` call. Logs persist in `.airlock/viewer.log`. |
| Container runtime | Container sandbox requires Docker, Colima, or Podman. The default workspace sandbox runs without any container runtime. |
| Rollback scope | `airlock rollback` restores the Airlock execution workspace (`.airlock/workspaces/<run_id>/repo`), not the original source repo. One checkpoint per run (`cp-0`). Operation-level rollback (last N operations) is future work. |
| `generic-shell` evidence scope | The `generic-shell` adapter captures process-level evidence: commands, file events, risk classification, policy decisions. It does not capture model-internal reasoning or chain-of-thought. Adapters that emit session events (model/tool/message) can populate `session_events.jsonl`; `generic-shell` does not produce session events beyond tool call wrappers. The BYOM integration (`integrations/byom-agent/`) uses `generic-shell` and documents this limitation explicitly. |

---

## Roadmap

| Area | Status |
|---|---|
| Additional agent adapters (Claude Code, Codex, Ollama) | In progress |
| Persistent, repo-level governance (`airlock sentinel`) | Shipped |
| Fleet control plane (enrollment, signed policy, revocation, session history) | Shipped |
| CI/CD integration (GitHub Actions, etc.) | Planned |
| Stronger remote worker IAM (per-user tokens, roles) | Planned |
| Hosted (multi-tenant SaaS) control plane | Not planned — Fleet is self-deployed |

---

## Quick Reference — Useful Commands After the Demo

```bash
# Check environment readiness (runtimes, writability, adapters)
./airlock doctor
./airlock agents doctor

# Browse all runs (read-only, safe to share)
./airlock serve --read-only --open

# Operator viewer in the background (review/rollback from the UI); keep the terminal
./airlock serve --background --open
./airlock serve --status
./airlock serve --stop

# Inspect the latest run
./airlock inspect latest

# Replay events with governance markers
./airlock replay latest --tail 30

# Verify artifact digest
./airlock verify latest

# Leave a review decision
./airlock review latest --state approved --note "reviewed"

# Preview a workspace rollback (no changes)
./airlock rollback latest --dry-run

# Restore a specific path from checkpoint
./airlock rollback latest --path src/myfile.txt --force

# Restore entire workspace from checkpoint
./airlock rollback latest --force

# Export an evidence bundle
./airlock export latest --format zip --include-report

# Open the HTML report
open .airlock/runs/$(ls -1t .airlock/runs | head -1)/report/index.html
```

---

## Where to Find More

| Document | Contents |
|---|---|
| [`README.md`](../README.md) | Full CLI reference, config, artifact model |
| [`SECURITY.md`](../SECURITY.md) | Sandbox model, honest guarantees and limitations |
| [`docs/architecture.md`](architecture.md) | Execution boundary, run lifecycle, artifact model |
| [`samples/QUICKSTART.md`](../samples/QUICKSTART.md) | Copy-paste walkthrough with expected output |
| [`CHANGELOG.md`](../CHANGELOG.md) | Full release history |
