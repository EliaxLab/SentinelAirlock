# Known Limitations and Non-Goals

## Current limitations

- **Windows:** `generic-shell` uses PowerShell. macOS/Linux use bash. `--background` detachment (for `serve` and `sentinel`) is not supported on Windows; run the foreground command in its own terminal there instead.
- Agent backends (Codex, Claude Code, etc.) must be installed separately.
- Container mode depends on host runtime/socket permissions.
- Remote worker mode uses shared-token auth today; full IAM is out of scope.
- Some constrained environments block loopback bind for `serve`, `worker`, or `fleet serve`.
- Network allowlist guarantees are strongest in containerized paths.
- **Sentinel is userspace, not kernel-level.** Detect → evaluate → revert happens after the OS accepts a write; killing the Sentinel process stops enforcement immediately with no supervision/restart built in.
- **Fleet's own operator access is single-deployment.** Per-Sentinel credentials are enrolled, revocable, and hash-stored, but Fleet itself has no multi-tenant SSO/RBAC for the humans operating it — it's a control plane you run yourself, not a hosted multi-tenant service.

## Non-goals (current stage)

- Full SaaS multi-tenant control plane.
- Full enterprise identity/SSO/RBAC system.
- Replacing endpoint security or network perimeter controls.
- Becoming a model provider or chat frontend.

## `airlock ci` notes

- Lifecycle detection is PID-liveness only, so concurrent `ci start` calls on one workspace are not strictly serialized (inherited from `airlock sentinel`).
- `.airlock/ci.json` ownership marker is a plain, non-tamper-proof file.
- Not container, process, network, or Kubernetes security; workspace filesystem governance only. See [ci-integration.md](ci-integration.md).
- **Detection/rollback, not prevention.** Reverting a local file does not undo an external side effect (API call, controller apply, cloud change) that already consumed it. See [ci-integration.md](ci-integration.md).
- **No action interception.** Direct AWS/Kubernetes/API/tool actions that never touch the governed filesystem are invisible to Sentinel.
- **Path governance only.** Forbidden content under an allowed filename passes; there is no semantic/content policy.
- **Sentinel termination stops enforcement.** `ci exec` is fail-open on a hard kill of its own process (the child is left running); `ci finalize` after a crash returns exit 30 but is not continuous governance.
- **Directory symlinks.** Writes that land outside the workspace through a directory symlink are not governed (and are never reverted by Sentinel).
- **The built-in secret/auth path classifier is still substring-based for `secret` and `auth`** (e.g. `authors.md` matches). Only the `deploy` rule was narrowed: it now needs a credential/config qualifier in the same path component.
