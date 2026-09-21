# Contributing to Sentinel Airlock

## Prerequisites

| Tool | Version | Required for |
|---|---|---|
| Go | 1.22+ | Build and test |
| make | any | Build |
| Git | any | Everything |

No Docker, no API keys, no network access required for the default build and test cycle.

## Fork and clone

```bash
# 1. Fork EliaxLab/SentinelAirlock on GitHub, then:
git clone https://github.com/<your-username>/SentinelAirlock.git
cd SentinelAirlock
git remote add upstream https://github.com/EliaxLab/SentinelAirlock.git
git fetch upstream
```

## Create a branch

Always branch from the latest `upstream/main`:

```bash
git checkout -b fix/short-description upstream/main
# or
git checkout -b feat/short-description upstream/main
# or
git checkout -b docs/short-description upstream/main
```

Keep branch names lowercase with hyphens. One concern per branch.

## Build and test

```bash
make build         # produces ./airlock
go test ./...      # full test suite
go vet ./...       # static analysis
gofmt -w ./...     # format (required before committing)
```

All four must pass before opening a PR. CI runs the same checks automatically on every PR.

## What to include in a PR

- **Focused change** — one bug fix, one feature, one doc update. Do not bundle unrelated cleanup.
- **Tests** — add or update tests if you changed logic. New adapters, policy packs, and CLI commands all need tests.
- **Docs** — update `README.md`, `docs/LIMITATIONS.md`, or inline flag help text if user-facing behavior changed.
- **No generated artifacts** — do not commit `.airlock/`, `airlock` binary, `dist/`, `*.log`, secrets, or release archives. These are all in `.gitignore`.

## Commit messages

```
fix: short description of what changed and why
feat: add cross-platform shell selection to generic-shell adapter
docs: clarify Windows limitations in LIMITATIONS.md
```

Use `fix:`, `feat:`, `docs:`, `test:`, or `refactor:` prefixes. Reference issues where relevant (`Closes #12`).

## Open a PR

Push your branch to **your fork** and open a PR against `EliaxLab/SentinelAirlock:main`:

```bash
git push origin fix/short-description
# then open a PR on GitHub from your fork branch → upstream main
```

Fill in the PR template. CI will run automatically. If checks fail, fix them on the same branch and push again — GitHub updates the PR automatically.

## Project layout

| Path | Contents |
|---|---|
| `cmd/airlock/main.go` | Entry point — wires all Cobra subcommands |
| `internal/cli/` | One file per CLI command |
| `internal/adapters/` | Agent adapter layer — add new adapters here |
| `internal/policypack/` | Named policy packs |
| `internal/execution/` | Sandbox engine (workspace / container / off) |
| `internal/governance/` | Risk classification and approval decisions |
| `internal/policy/` | `airlock.yaml` config loader |
| `internal/runmeta/` | Run manifest, digest, artifact loader |
| `internal/fleet/` | Fleet control plane — enrollment, trust/signing, policy, session store |
| `internal/web/` | Local HTTP evidence viewer |

## Adding an adapter

1. Create `internal/adapters/<name>.go` implementing the `Adapter` interface (`Name`, `Prepare`, `Execute`)
2. Register it in `internal/adapters/registry.go`
3. Add diagnostics support in `internal/agents/diagnostics.go`
4. Document the adapter name in `--agent` flag help in `internal/cli/run.go`
5. Add tests

## Adding a policy pack

1. Add a named entry to the pack registry in `internal/policypack/packs.go`
2. Set only the fields the pack overrides
3. Add the pack name to `--policy-pack` flag help in `internal/cli/run.go`
4. Add a test verifying the merged config

## Reporting issues

Open a GitHub issue with:
- Airlock version (`airlock --version`)
- OS and architecture
- Minimal reproduction steps
- Actual vs expected output

Security issues: see `SECURITY.md`.
