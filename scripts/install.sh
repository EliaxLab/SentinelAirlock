#!/usr/bin/env bash
# install.sh — install the airlock binary
#
# Usage:
#   bash scripts/install.sh                  # from source clone, installs to /usr/local/bin
#   bash scripts/install.sh ~/.local/bin     # custom target dir
#   curl -fsSL https://raw.githubusercontent.com/EliaxLab/SentinelAirlock/main/scripts/install.sh | bash
#
# Behavior:
#   1. If a prebuilt release binary exists on GitHub for the current OS/arch, download it.
#   2. Otherwise fall back to building from source (requires Go 1.22+).

set -euo pipefail

REPO="EliaxLab/SentinelAirlock"
BINARY="airlock"
VERSION="${VERSION:-latest}"

# ── Target directory ───────────────────────────────────────────────────────────
if [[ $# -ge 1 ]]; then
  TARGET="$1"
elif [[ -w "/usr/local/bin" ]]; then
  TARGET="/usr/local/bin"
elif [[ -d "$HOME/.local/bin" ]]; then
  TARGET="$HOME/.local/bin"
else
  TARGET="$HOME/bin"
fi
TARGET="${TARGET/#\~/$HOME}"
mkdir -p "$TARGET"

# ── Detect OS / arch ──────────────────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "$OS" in
  darwin|linux) ;;
  *)
    echo "Unsupported OS: $OS — build from source: make build" >&2
    exit 1
    ;;
esac

ASSET="${BINARY}-${OS}-${ARCH}"

# ── Resolve version ───────────────────────────────────────────────────────────
if [[ "$VERSION" == "latest" ]]; then
  # /releases/latest only returns non-prerelease; use /releases list to include RC builds
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')"
fi

if [[ -z "$VERSION" ]]; then
  echo "Could not determine latest release version — falling back to source build." >&2
  BUILD_FROM_SOURCE=1
else
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
  # check the asset actually exists
  HTTP_STATUS="$(curl -fsSL -o /dev/null -w "%{http_code}" "$DOWNLOAD_URL" 2>/dev/null || echo 000)"
  if [[ "$HTTP_STATUS" != "200" ]]; then
    echo "No prebuilt binary found for ${OS}/${ARCH} at ${VERSION} — falling back to source build." >&2
    BUILD_FROM_SOURCE=1
  fi
fi

# ── Download prebuilt binary ───────────────────────────────────────────────────
if [[ "${BUILD_FROM_SOURCE:-0}" != "1" ]]; then
  TMP="$(mktemp)"
  echo "Downloading ${ASSET} ${VERSION}..."
  curl -fsSL "$DOWNLOAD_URL" -o "$TMP"
  chmod +x "$TMP"
  mv "$TMP" "$TARGET/$BINARY"
  echo "Installed $TARGET/$BINARY ($VERSION)"
  "$TARGET/$BINARY" --version || true
  exit 0
fi

# ── Build from source ─────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
  echo "Go is not installed and no prebuilt binary is available for ${OS}/${ARCH}." >&2
  echo "Install Go 1.22+ from https://go.dev/dl/ or download a binary from:" >&2
  echo "  https://github.com/${REPO}/releases" >&2
  exit 1
fi

# Find repo root (works both from clone root and scripts/ subdir)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../go.mod" ]]; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [[ -f "$SCRIPT_DIR/go.mod" ]]; then
  ROOT="$SCRIPT_DIR"
else
  echo "Cannot find go.mod — run this script from a cloned copy of the repo." >&2
  exit 1
fi

COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo none)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILD_VERSION="${VERSION:-dev}"

echo "Building from source (${OS}/${ARCH})..."
cd "$ROOT"
go build \
  -ldflags "-X main.version=$BUILD_VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
  -o "$TARGET/$BINARY" \
  ./cmd/airlock

echo "Installed $TARGET/$BINARY (built from source)"
"$TARGET/$BINARY" --version || true
