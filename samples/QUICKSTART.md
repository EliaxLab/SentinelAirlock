# Sentinel Airlock — Quickstart

Copy-paste walkthrough from a fresh clone. Under 10 minutes. Local-first — no container runtime, no SaaS, no internet required.

> **In a hurry?** Jump straight to the demo scripts:
> ```bash
> bash samples/demo.sh           # 90-second proof — build, run, inspect, review, verify, export
> bash samples/demo-full.sh      # 5-minute governance boundary — policy denial + command block
> bash samples/demo-rollback.sh  # 3-minute workspace rollback proof — path-scoped + full restore
> bash samples/demo-byom.sh      # 3-minute BYOM agent integration — governed context write + policy denial
> ```

---

## Prerequisites

| Tool | Version |
|---|---|
| Go | 1.22+ |
| make | any |
| Git | any |

This walkthrough uses **workspace sandbox** — the default. Docker/Colima/Podman is not required. Note the workspace sandbox caveat: container mode is recommended for stronger isolation in production use (see [`SECURITY.md`](../SECURITY.md)).

---

## Step 1 — Clone and Build

```bash
git clone <repo-url>
cd sentinel-airlock
make build
./airlock --version
```

Expected output:
```
airlock version 2.2.0-rc1
```

After building, run `./airlock doctor` to verify your environment:

```bash
./airlock doctor
```

This checks Go runtime, container runtimes (Docker/Colima/Podman), `.airlock/` writability, and file opener availability. `[WARN]` lines on optional runtimes are expected if you don't have Docker/Colima installed — Airlock works without them in workspace sandbox mode.

---

## Step 2 — Bootstrap

Run once per project to create `.airlock/` and a starter config:

```bash
./airlock bootstrap
```

Creates:
```
.airlock/
airlock.yaml
```

---

## Step 3 — Run an Agent

```bash
./airlock run --agent generic-shell \
  --cmd 'mkdir -p src && echo hi > src/test.txt' \
  --repo .
```

Airlock will: copy the repo → classify risk → execute in sandbox → record file events → write all artifacts.

Expected output (last section):
```
Status: success
Manifest: .airlock/runs/<run_id>/run_manifest.json

Next steps:
  ./airlock inspect <run_id>
  ./airlock replay <run_id> --tail 20
  ...

  Tip: use 'latest' as a shorthand for any of the above, e.g.:
    ./airlock inspect latest
```

The run_id is printed in the output. You can also find it in `.airlock/index.json`, or browse it at `http://localhost:8080/runs` after `airlock serve`.

---

## Step 4 — Inspect

```bash
./airlock inspect latest
```

Prints adapter, sandbox mode, touched paths, denied paths, risk classification, policy decisions, and artifact locations.

---

## Step 5 — Replay

```bash
./airlock replay latest --tail 20
```

Replays the event timeline in the terminal — policy decisions, file reads/writes, risk classifications, in order.

Available flags:
- `--tail N` — show last N rows (default: 10)
- `--json` — emit full timeline as JSON
- `--stream system|session|both` — filter event streams

---

## Step 6 — Review

```bash
./airlock review latest --state approved --note "Reviewed demo run"
```

Valid states: `unreviewed` | `approved` | `rejected` | `needs-attention`

To check review status without writing:
```bash
./airlock review latest
```

Writes `.airlock/runs/<run_id>/review.json`:
```json
{
  "state": "approved",
  "note": "clean run, write denial worked as expected",
  "reviewer": "<your $USER>",
  "timestamp": "2026-07-08T18:00:00Z"
}
```

---

## Step 7 — Verify

```bash
./airlock verify latest
```

Without a signing key configured:
```json
{ "status": "verified-unsigned", "run_id": "..." }
```

With `AIRLOCK_SIGNING_KEY` set at run time:
```json
{ "status": "verified-signed", "run_id": "..." }
```

Possible status values: `verified-signed` | `verified-unsigned` | `hash-mismatch` | `signature-invalid`

---

## Step 8 — Export

```bash
./airlock export latest --format zip --include-report
```

Writes `airlock-run-<run_id>.zip` in `.airlock/runs/<run_id>/`. Also supported:
```bash
./airlock export latest --format tar.gz
```

Optional flags:
- `--include-report` — bundle `report/index.html`
- `--include-checkpoints-meta` — bundle `checkpoints/cp-0`

---

## Step 9 — Rollback (Workspace Restore)

```bash
# Preview what would be restored — no changes
./airlock rollback latest --dry-run

# Restore one file from checkpoint (workspace only)
./airlock rollback latest --path src/test.txt --force

# Restore entire workspace from checkpoint
./airlock rollback latest --force
```

Rollback restores `.airlock/workspaces/<run_id>/repo` — the isolated Airlock sandbox where the agent ran. The original `--repo` source directory is **not** modified by Airlock at any point.

After rollback:
- `review.json` is set to `needs-attention` — a prior approval is not silently left in place
- `run_digest.json` is rebuilt so `airlock verify` returns `verified-unsigned`
- `rollback.json` artifact is written (checkpoint, mode, timestamp, status)
- `report/index.html` is regenerated to reflect the rollback event

**Limitation:** One checkpoint per run (`cp-0`). Operation-level rollback (undo last N operations) is future work.

---

## Step 10 — Web Viewer

```bash
./airlock serve --listen 127.0.0.1:8080 --open
```

| Route | Contents |
|---|---|
| `/runs` | All runs list |
| `/runs/<run_id>` | Run detail view |
| `/review` | Review queue |
| `/compare` | Diff two runs |
| `/export` | Export from browser |

---

## What You Just Proved

| Claim | Evidence in `.airlock/runs/<run_id>/` |
|---|---|
| Command ran under governance | `run_manifest.json` — adapter, mode, approval decision |
| Repo untouched during execution | `checkpoints/cp-0/` = pre-run snapshot; `changes.patch` = what changed |
| File events recorded | `events.jsonl` — file creates, reads, writes |
| Artifacts haven't been tampered | `verify` passed SHA-256 check |
| Reviewer signed off | `review.json` — state, note, timestamp |
| Bundle is exportable | zip produced and self-contained |
| HTML evidence report | `report/index.html` — static, self-contained, no external dependencies |

For a full governance boundary demonstration (policy denial + command block), run `bash samples/demo-full.sh`. For workspace rollback proof (path-scoped + full restore), run `bash samples/demo-rollback.sh`. For the BYOM agent runtime integration (custom agent + policy enforcement), run `bash samples/demo-byom.sh`. See [`docs/REVIEWER_GUIDE.md`](../docs/REVIEWER_GUIDE.md) for what to look for in the HTML reports.

---

## Optional: BYOM Agent Runtime Integration

Airlock's `generic-shell` adapter lets you run any process-based agent under governance. The BYOM integration (`integrations/byom-agent/`) demonstrates this with a Python agent that reads project context and writes structured notes — no API keys, no network required in default mode.

```bash
# Full demo: normal run + governance test (policy-denied writes)
bash samples/demo-byom.sh

# Manual governed run
./airlock run \
  --agent generic-shell \
  --cmd "python3 integrations/byom-agent/agent.py \
    --task 'Summarize project context' \
    --context README.md \
    --output docs/byom-agent-notes.md" \
  --repo samples/byom-workspace \
  --policy integrations/byom-agent/policy.airlock.yaml
```

To connect a local LLM (Ollama, llama.cpp, vLLM, LangChain): see [`integrations/byom-agent/README.md`](../integrations/byom-agent/README.md).

---

## Optional: Signed Evidence

```bash
export AIRLOCK_SIGNING_KEY=/path/to/ed25519-private-key.hex
./airlock run --agent generic-shell --cmd 'echo signed > src/signed.txt' --repo .
signed_run_id="$(ls -1t .airlock/runs | head -n 1)"
./airlock verify "$signed_run_id" --json
# → { "status": "verified-signed", ... }
```

---

## Optional: Remote Worker Flow

```bash
# Start a worker
./airlock worker start \
  --listen 127.0.0.1:8787 \
  --auth-token testtoken \
  --work-root /tmp/airlock-worker \
  --worker-name local-worker

# Submit a run
./airlock submit \
  --target remote \
  --worker http://127.0.0.1:8787 \
  --auth-token testtoken \
  --agent generic-shell \
  --cmd 'echo remote > src/remote.txt' \
  --repo .

# Fetch artifacts (run_id printed by submit)
./airlock fetch <run_id> --auth-token testtoken

# Same local commands work on fetched artifacts
./airlock inspect <run_id>
./airlock verify <run_id>
```
