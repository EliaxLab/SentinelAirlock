# Release Checklist

## Pre-flight
- [ ] `go test ./...` passes
- [ ] `make build VERSION=<version>` passes
- [ ] `./airlock --version` shows version/commit/build date
- [ ] `./airlock doctor` passes with no BLOCKER lines
- [ ] 90-second demo path verified from clean state: `rm -rf .airlock && bash scripts/dev/demo.sh && ./airlock verify latest`
- [ ] Governance boundary demo verified: `bash scripts/dev/demo-full.sh && ./airlock verify latest`
- [ ] Rollback demo verified: `bash scripts/dev/demo-rollback.sh && ./airlock verify latest`
- [ ] Sentinel smoke test: `airlock sentinel --repo . --background`, one allowed + one denied external write, `--status`, `--stop`
- [ ] Fleet smoke test: `airlock fleet init` + `fleet serve` + enroll a Sentinel + `fleet policy assign` + confirm `IN_SYNC`/`VERIFIED`
- [ ] All three demos end with `status=verified-unsigned`
- [ ] `./airlock export latest --format zip --include-report && ./airlock verify latest` returns `verified-unsigned`

## Artifacts
- [ ] `make release-artifacts VERSION=<version>`
- [ ] Dist files generated with expected names (must match `scripts/install.sh`'s download names exactly — no version segment, no manual renaming):
  - `dist/airlock-darwin-amd64`
  - `dist/airlock-darwin-arm64`
  - `dist/airlock-linux-amd64`
  - `dist/airlock-linux-arm64`
  - `dist/airlock-windows-amd64.exe`
  - `dist/checksums.txt`
- [ ] Upload all five binaries + `checksums.txt` to the GitHub Release as-is (filenames already correct — do not rename)
- [ ] Confirm `curl -fsSL .../scripts/install.sh | bash` actually downloads the new tag on at least one platform (not a source-build fallback)
- [ ] Confirm the new tag's binary reports `airlock sentinel`/`airlock fleet` in `--help` before publishing

## Docs
- [ ] `README.md` updated
- [ ] `CHANGELOG.md` updated
- [ ] `samples/QUICKSTART.md` updated
- [ ] `docs/messaging-pack.md` reviewed

## Release notes
- [ ] Fill `.github/release-notes-template.md`
- [ ] Tag created (`vX.Y.Z`)
- [ ] Notes include known limitations and non-goals

## Post-release
- [ ] Demo assets updated in `docs/assets/`
- [ ] Feedback template prepared (`docs/early-user-feedback.md`)
