# `airlock ci` — embedding workspace filesystem governance into a workflow

`airlock ci` wraps the **existing** Sentinel (detect -> evaluate -> revert on the
workspace filesystem, see [SECURITY.md](../SECURITY.md)) so a CI job, script or
container can start it before a workflow runs and finalize it afterward. It adds
no new enforcement engine, policy language, or evidence format.

| Command | Who owns the workload | Use it when |
|---|---|---|
| `airlock run` | Airlock launches and sandboxes it | Airlock should run the agent |
| `airlock sentinel` | Nobody: a long-lived watcher on a real repo | Continuous governance |
| `airlock ci start/status/finalize` | **Your workflow** (Airlock never launches it) | You have an existing pipeline |
| `airlock ci exec -- <cmd>` | Airlock runs one child process | Convenience wrapper only |

What this is **not**: it does not isolate containers, govern processes, network
or the Docker/Kubernetes API, act as an admission controller, or replace
runtime security. It governs writes to the workspace directory, best-effort and
userspace (fsnotify), exactly like `airlock sentinel`.

## Commands

All accept `--workspace <dir>` (default `.`) and `--json`. Policy/Fleet flags
(`--policy`, `--policy-pack`, `--fleet`, `--fleet-token`, `--fleet-enroll-token`,
`--fleet-pubkey`, `--fleet-ca`) are the same as `airlock sentinel`.

- `ci start [--attach-existing] [--env-file F]` — starts a background Sentinel and
  returns only once it reports ready. Records ownership in
  `<workspace>/.airlock/ci.json`. A second `start` for the same session is a
  no-op success. If a Sentinel this lifecycle did not start is already running,
  it **refuses** (exit 30) unless `--attach-existing` is given, which attaches
  read-only (`owned: false`).
- `ci status` — read-only. `status` is one of `not_started`, `running`,
  `stopped_unclean`, `conflict`, `finalized`.
- `ci finalize [--session ID]` — if owned, stops Sentinel via the same path as
  `airlock sentinel --stop` (which flushes the recorder and writes
  manifest/digest/report/index); if attached, snapshots without stopping. Runs
  `airlock verify <session> --json`. Idempotent: repeating it returns the cached
  result. Refuses if a *different* session is now running. If Sentinel died
  without finalizing, evidence is finalized defensively and status is
  `finalized_after_crash`.
- `ci exec -- <cmd> [args...]` — starts an in-process Sentinel session, runs
  `<cmd>` directly (argv, **no shell**) with the workspace as cwd, always
  finalizes, and reports. Refuses if any Sentinel is already active for the
  workspace. SIGINT/SIGTERM cancel the child and evidence is still finalized. In
  `--json` mode the child's stdout goes to stderr so stdout stays one JSON
  document.

`--env-file` writes `AIRLOCK_SESSION_ID`, `AIRLOCK_SENTINEL_ID`,
`AIRLOCK_WORKSPACE`, `AIRLOCK_EVIDENCE_DIR`, `AIRLOCK_POLICY_HASH` as
`KEY=VALUE` lines (never secrets). A child process cannot modify its parent's
environment, so **you must `source` the file yourself** (or parse `--json`).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 10 | Governed workload failed (`ci exec` only) |
| 20 | Policy violation observed; all denied writes reverted |
| 21 | Revert failure: denied content may still be present |
| 30 | Airlock internal/lifecycle failure (couldn't start/stop, foreign Sentinel, bad workspace, no lifecycle) |

Precedence when several apply: `30 > 21 > 20 > 10 > 0`. `status` exits 0 for any
state it can determine accurately. Other `airlock` commands are unchanged (0/1).

## JSON (`schema_version: "1"`)

```json
{
  "schema_version": "1", "command": "finalize", "status": "finalized",
  "workspace": "/abs/path", "owned": true,
  "session_id": "...", "sentinel_id": "...",
  "policy": {"id": "local", "version": "", "hash": "..."},
  "fleet": { "...same secret-free struct as fleet-status.json..." },
  "governance": {"allowed": 1, "denied": 1, "reverted": 1, "revert_failed": 0, "last_event_at": "..."},
  "evidence": {"run_dir": "...", "events": "...", "manifest": "...", "digest": "...", "report": "..."},
  "verify": {"run_id": "...", "verified": true, "status": "..."},
  "child": {"command": ["..."], "exit_code": 0},
  "exit_code": 20
}
```

No tokens or secrets are emitted. Evidence lives in the existing
`.airlock/runs/<session>/`; archive that directory as a CI artifact. No
separate export command exists and no evidence schema was changed.

## Reference integrations

Status labels: **TESTED** = exercised in this repo; **NOT ENV-TESTED** = uses
only tested commands but the CI system itself was not run; **EXAMPLE ONLY**.

| Integration | Status |
|---|---|
| Plain shell lifecycle (`samples/ci-acceptance.sh`, real binary, disposable workspace) | **TESTED** |
| `ci exec` (Go tests + acceptance script) | **TESTED** |
| Jenkins, Buildkite, GitLab self-hosted runner | **NOT ENV-TESTED** (shell steps below) |
| Docker / Kubernetes shared workspace | **EXAMPLE ONLY** |

The shape is always the same: start, run your steps, finalize in an
always-run block, archive `.airlock/runs`, and fail on the exit code.

**Jenkins (declarative)**
```groovy
stage('governed build') {
  steps { sh 'airlock ci start --workspace "$WORKSPACE" --json > airlock-start.json' }
}
// ... your stages ...
post { always {
  sh 'airlock ci finalize --workspace "$WORKSPACE" --json > airlock-result.json'
  archiveArtifacts artifacts: 'airlock-result.json, .airlock/runs/**', allowEmptyArchive: true
} }
```

**Buildkite** (`pipeline.yml` steps; use a `command` hook or one step with a trap)
```bash
airlock ci start --workspace . --json
trap 'airlock ci finalize --workspace . --json' EXIT
./build.sh
```
(With the trap, the script's exit status is finalize's when finalize fails; capture
your workload's status first if you need to combine them.)

**GitLab self-hosted runner**: `before_script: airlock ci start ...`,
`after_script: airlock ci finalize ...`, `artifacts: paths: [.airlock/runs/]`.
`after_script` runs even if the job fails.

**Docker / Kubernetes shared workspace**: run `airlock ci start` inside the
container (or a sidecar) that shares the workspace volume with the writer, then
`ci finalize` when the writer completes. Sentinel governs writes it can observe
on that filesystem via fsnotify; network filesystems and volumes that don't
deliver inotify events are not covered (see
[LIMITATIONS.md](LIMITATIONS.md)). This is not container or pod security.

## Limitations

- Same detect -> evaluate -> revert model as Sentinel: a write is briefly
  visible before revert; nothing is kernel-enforced.
- Lifecycle detection is PID-liveness only (no file locks), inherited from
  `airlock sentinel`; two `ci start` calls racing on one workspace are not
  strictly serialized.
- `.airlock/ci.json` is a plain file, not tamper-proof.
- `ci start`/`finalize` re-execute the airlock binary (`os.Executable()`), as
  `airlock sentinel --background` does; `verify` is run as a subprocess because
  `runmeta.VerifyRun` is cwd-relative.
- Windows was not tested.
