# Versioning Notes

Sentinel Airlock uses semantic-style tags for releases:
- `vMAJOR.MINOR.PATCH`
- optional release-candidate suffixes, e.g. `v2.2.0-rc1`

## Build metadata

The CLI embeds:
- version
- commit
- build date

Check with:

```bash
./airlock --version
```

## Release artifacts

`make release-artifacts VERSION=<version>` produces (filenames intentionally carry no version
segment — they must match exactly what `scripts/install.sh` downloads):
- `dist/airlock-darwin-amd64`
- `dist/airlock-darwin-arm64`
- `dist/airlock-linux-amd64`
- `dist/airlock-linux-arm64`
- `dist/airlock-windows-amd64.exe`
- `dist/build_info.json`
- `dist/checksums.txt` — SHA-256 of each binary, for manual verification after download

## `go install` and prerelease tags

`go install .../cmd/airlock@latest` resolves to the latest **stable** (non-prerelease) tag if one
exists. As long as every tag on this repo is an `-rcN` prerelease, Go's module resolution treats
the module as "not yet stable" and `@latest` instead resolves to a pseudo-version of the current
tip of `main` — so `go install` users always get the newest merged code, not a stale prerelease.
This stops being true the moment a non-prerelease tag (e.g. `v3.0.0`) is cut; from then on
`@latest` pins to the newest stable tag as usual.
