#!/usr/bin/env bash
# Local-dev convenience only: builds the Electron shell against a throwaway
# venv so it can run without installing the system package. The *released*
# desktop app is built as part of the single combined .deb by
# scripts/build_deb.sh, which shares its Python runtime with the CLI instead
# of bundling the venv this script creates - see desktop/README.md.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
RUNTIME_DIR="$ROOT_DIR/build/desktop/runtime"
VENV_DIR="$RUNTIME_DIR/python-venv"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_command "$PYTHON_BIN"
require_command npm

cd "$ROOT_DIR"

echo "[desktop] Building frontend bundle..."
if [[ ! -d frontend/node_modules ]]; then
  (cd frontend && npm ci)
fi
(cd frontend && npm run build)

echo "[desktop] Preparing isolated Python venv..."
rm -rf "$RUNTIME_DIR"
"$PYTHON_BIN" -m venv --copies "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --upgrade pip setuptools wheel
"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --no-compile "$ROOT_DIR"

echo "[desktop] Installing Electron dependencies..."
if [[ -f desktop/package-lock.json ]]; then
  (cd desktop && npm ci)
else
  (cd desktop && npm install)
fi

echo "[desktop] Building Linux desktop artifacts..."
(cd desktop && npm run dist)

echo "[desktop] Artifacts are in $ROOT_DIR/dist/desktop"
