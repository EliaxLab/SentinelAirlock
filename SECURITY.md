# Security

## Scope

This document describes the security model, guarantees, and explicit limitations of Sentinel Airlock v2.4.0-rc1, covering all three governance modes: `airlock run` (one execution), `airlock sentinel` (persistent, repo-level), and `airlock fleet` (coordination across many Sentinels).

Airlock is an agent-governance boundary and observability layer for coding agent execution. **It is not a security boundary in the OS or hypervisor sense.** `airlock run` only captures workflows launched through it — `airlock sentinel` is the mode built for governing a repository regardless of which process writes to it, and its own guarantees and limits are stated in full below. Read this document before deploying with untrusted agents or commands.

---

## Sandbox Modes

Set via `--sandbox` flag or `defaults.sandbox` in `airlock.yaml`.

### `workspace` (default)

The repo is copied to an isolated directory (`.airlock/workspaces/<run_id>/repo`) before the agent executes. A filesystem watcher records all file events against that directory.

**What it provides:**
- Original working directory is not modified during execution
- Pre-run snapshot written to `checkpoints/cp-0/` for comparison
- All file reads, writes, and policy denials recorded in `events.jsonl`
- `changes.patch` diff generated against original repo state

**Workspace sandbox caveat:** The agent process runs on the host OS with the privileges of the current user. It can access anything outside the workspace directory that the current user can access. The workspace directory boundary is best-effort, not a hard OS-enforced isolation guarantee. Container mode is recommended for stronger isolation.

---

### `container`

The agent executes inside a Docker, Colima, or Podman container. Airlock auto-detects the available runtime. Provides stronger process and filesystem isolation than workspace mode.

**Limitation:** Container security depends on your runtime configuration. Airlock does not configure seccomp profiles, AppArmor/SELinux policies, rootless settings, or read-only filesystem mounts. If you need hardened container execution, configure those controls at the runtime level independently.

**Fallback:** If `--fallback-workspace` is set and no container runtime is found, Airlock falls back to workspace mode. The `run_manifest.json` always records which sandbox mode was actually used.

---

### `off`

No sandboxing. The agent executes directly in the working directory with no isolation.

**Use only in environments where isolation is handled externally.** Not recommended for untrusted agents or commands.

---

## Network Controls

| Mode | Behaviour |
|---|---|
| `off` (default) | No outbound network — recorded as policy intent |
| `on` | Unrestricted outbound network |
| `allowlist` | Only whitelisted hostnames are permitted |

**Limitation:** In workspace mode, network enforcement is advisory — policy intent is recorded and `POLICY_DENY` events fire, but no kernel-level syscall blocking is applied. For enforced network isolation, use container mode with appropriate runtime network configuration.

---

## Sentinel Mode (`airlock sentinel`)

Sentinel continuously governs a real repository, independent of which process writes to it — an agent not launched through Airlock, an IDE, a shell command, or any other local process.

**Model: detect → evaluate → revert, not prevent.**

```
filesystem mutation → Sentinel detects → policy evaluation
    → ALLOW: preserved, recorded
    → DENY:  reverted from baseline (best-effort), recorded
```

A filesystem watcher observes mutations *after the OS has already accepted them*. This is best-effort filesystem governance, not kernel-level mandatory access control.

**What this means concretely:**
- Denied content briefly exists on disk between the write and the revert. Airlock does not claim otherwise.
- A process that reads a file in that window sees the denied content. Sentinel does not prevent that read; it detects, evaluates, and reverts as fast as it reasonably can, and always records what happened, including the fact that a revert occurred.
- `sandbox=off`, in-place execution against the real `--repo` — there is no isolated workspace copy in Sentinel mode. Evidence (session checkpoint, `events.jsonl`, policy decisions) is produced the same way as `airlock run`.
- Restarting Sentinel starts a new session but does not erase or rewrite the history of previous sessions, and does not change its durable identity when Fleet-enrolled.
- Killing the Sentinel process (`kill -9`, OOM, etc.) stops enforcement immediately and without warning — Sentinel is a userspace watcher, not a supervised system service. There is nothing in this release that prevents a local user with permission to kill processes from doing so.
- Sentinel combines filesystem notifications with state reconciliation: a directory created and populated fast enough that its watch could not be installed in time is reconciled against on-disk state immediately after the watch is installed, and a low-frequency safety pass repeats this for the whole tree during long-running sessions. A watcher event lost to that kind of race does not permanently escape governance — on-disk state, not event delivery, is authoritative. This does not change the detect → evaluate → revert model above or narrow the read-during-revert window; it closes a separate gap where a missed *creation* event could otherwise leave a denied file in place indefinitely.

---

## Fleet / Control Plane Security Model

Fleet coordinates desired-state policy across many Sentinels. It is a metadata and coordination plane, not a filesystem-decision path: every allow/deny decision is made locally by the Sentinel watching that repository, never by a request to Fleet at write time. The invariant this is designed around:

```
Fleet unavailable  ≠  local governance unavailable
```

A Sentinel keeps its last-known-good (LKG) policy and continues enforcing it locally if Fleet is unreachable, or if that Sentinel's credential has been revoked.

**Trust architecture:**
- **Enrollment:** a one-time enrollment token (created by a Fleet operator) is exchanged once for a durable, opaque per-Sentinel credential. Fleet stores only a hash of that credential and of the enrollment token, never the values themselves.
- **Policy signing:** Fleet signs each policy version with an Ed25519 key. A Sentinel pins Fleet's public signing key at enrollment and verifies every policy against it before applying it. Verification is over a full SHA-256 digest of the policy content — the short 16-hex digest shown in CLI/UI output is a display/drift fingerprint only, never the basis for a security decision.
- **Anti-downgrade:** each Sentinel tracks a high-water-mark version per policy id and refuses to apply an older version, unless presented with an explicit, signed rollback grant scoped to that Sentinel, that policy, and an expiry.
- **Revocation:** revoking a Sentinel's Fleet credential stops it from being treated as a trusted member of the fleet and stops Fleet from issuing it new policy — it does **not** stop that Sentinel's local enforcement. A revoked Sentinel keeps enforcing its last-known-good policy against its repository.
- **Local last-known-good policy:** re-verified (digest and signature) on every load, never trusted merely because the file exists on disk.
- **Buffered reporting:** status/governance metadata generated during a Fleet outage is buffered locally (bounded, deduplicated) and delivered when Fleet becomes reachable again; local enforcement is never gated on delivery succeeding.
- **Session history:** Fleet retains per-Sentinel session metadata (durable Sentinel identity → many sessions over restarts) so it can show a session's policy and governance activity as recorded honestly at the time — a crash is never rendered as a clean stop, and a stopped Sentinel is never silently forgotten.

**What Fleet never receives:** raw repository contents, diffs, patches, or evidence. Those remain on the machine that produced them; Fleet's protocol has no path for uploading them, and no remote-delete or remote-stop capability that could reach a Sentinel's disk or its enforcement loop.

**Be precise about what signing does and doesn't prove.** Policy signature verification proves a policy was issued by whoever holds Fleet's private signing key — it does not, by itself, prove that whoever controls your Fleet deployment is trustworthy. A control plane whose signing key has been compromised (or whose operator is malicious) *can* sign and distribute a new, valid-looking, unfavorable policy — anti-downgrade defends against replaying an *old* policy, not against a *new* malicious one signed with a legitimate key. Protecting Fleet's signing key (file permissions, host security, key rotation discipline) is the operator's responsibility; Airlock does not claim otherwise.

---

## What Airlock Guarantees

- **Audit trail completeness:** Every run produces a structured event log, session trace, manifest, and patch — all written before the run is marked complete.
- **Tamper evidence:** `run_digest.json` contains a SHA-256 hash of the core evidence artifacts: `events.jsonl`, `session_events.jsonl`, `run_manifest.json`, `changes.patch`, and a hash of checkpoint file names. `airlock verify` checks these hashes. Sanctioned mutations by Airlock commands (`export`, `rollback`) rebuild the digest automatically so `verify` continues to return `verified-unsigned` after those operations. Third-party modifications to any digested artifact will cause `hash-mismatch`.
- **Optional cryptographic signing:** If `AIRLOCK_SIGNING_KEY` (ed25519) is configured, Airlock signs the digest file. This allows verification that the artifact set has not changed since it was produced.
- **Policy recording:** All policy decisions — allow, deny, risk level, approval mode — are recorded in `events.jsonl` and `run_manifest.json`, regardless of whether a command was blocked.
- **Review chain:** `review.json` records reviewer state, note, reviewer identity (from `$USER`), and timestamp as a permanent run artifact.

---

## What Airlock Does Not Guarantee

- **Workspace mode does not prevent host file access.** The process boundary is the OS process, not the workspace directory.
- **Airlock does not validate the agent binary.** It trusts the adapter and the executable it resolves.
- **Digest verification proves artifact integrity post-run, not execution integrity.** It confirms recorded artifacts haven't been modified after the run ended; it does not cryptographically prove what happened during execution.
- **Network mode `off` in workspace mode is not kernel-enforced.** It records a policy intent but does not block syscalls.
- **No multi-tenant isolation.** All runs on a machine share `.airlock/` and run as the same OS user.
- **The web viewer (`airlock serve`) has no authentication.** Anyone with access to the machine and port can read all run artifacts. Use `--read-only` to disable review writes.
- **`airlock rollback` restores the execution workspace, not the original repo.** It restores `.airlock/workspaces/<run_id>/repo` (the isolated sandbox copy). The original `--repo` source directory is not modified by Airlock at any point. One checkpoint per run (`cp-0`). Operation-level rollback (undo last N agent operations) is future work.
- **BYOM/generic-shell agents: process-level evidence only.** The `generic-shell` adapter captures commands, file events, risk classification, and policy decisions. It does not capture model-internal reasoning, chain-of-thought, or token-level traces. If you need session-level traces (model messages, tool calls, model responses), use an adapter that emits session events to `session_events.jsonl`. The BYOM integration (`integrations/byom-agent/`) documents this explicitly.

---

## Remote Worker Security

The remote worker (`airlock worker start`) uses a shared bearer token for authentication. This is a separate mechanism from Fleet's per-Sentinel enrollment/credential model described above — the worker executes submitted jobs, Fleet coordinates policy.

**Current limitations:**
- Single shared secret — no per-user identity, roles, or scopes
- No token rotation mechanism built in
- Anyone holding the token can submit jobs and retrieve any artifact
- The worker has no per-submitter audit log

**Operational guidance:**
- Always run the worker behind TLS (reverse proxy) in any non-local deployment
- Treat the auth token as a high-value secret — rotate by restarting the worker with a new token
- Do not expose the worker port to untrusted networks

Full IAM (per-user tokens, roles, scoped access) is planned for a future release.

---

## Local-First Status

Sentinel Airlock is **entirely local by default**. There is no hosted control plane and no telemetry collection. Data leaves the machine only if you explicitly configure it to: a remote worker + `airlock submit`, or a Fleet control plane you deploy yourself + `--fleet` on a Sentinel. In both cases, evidence and repository content stay local — see the Fleet section above for exactly what does and does not leave a Sentinel's machine.

---

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Include in your report:
- Impact summary
- Reproduction steps
- Affected versions
- Suggested mitigation (if known)

We aim to acknowledge reports within 48 hours and provide a remediation timeline within 7 days for confirmed issues.
