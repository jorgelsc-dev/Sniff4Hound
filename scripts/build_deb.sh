#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
PACKAGE_NAME="${PACKAGE_NAME:-sniff4hound}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build/deb}"
PACKAGE_ROOT="$BUILD_DIR/$PACKAGE_NAME"
DEBIAN_DIR="$PACKAGE_ROOT/DEBIAN"
INSTALL_ROOT="$PACKAGE_ROOT/usr/lib/$PACKAGE_NAME"
VENDOR_DIR="$INSTALL_ROOT/vendor"
BIN_DIR="$PACKAGE_ROOT/usr/bin"
DOC_DIR="$PACKAGE_ROOT/usr/share/doc/$PACKAGE_NAME"
LAUNCHER_SOURCE="$ROOT_DIR/scripts/deb_launcher.py"
WRAPPER_SOURCE="$ROOT_DIR/scripts/deb_wrapper.sh"
POSTRM_SOURCE="$ROOT_DIR/scripts/deb_postrm.sh"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_command "$PYTHON_BIN"
require_command dpkg-deb
require_command sha256sum

if [[ ! -f "$LAUNCHER_SOURCE" ]]; then
  echo "Missing launcher template: $LAUNCHER_SOURCE" >&2
  exit 1
fi
if [[ ! -f "$WRAPPER_SOURCE" ]]; then
  echo "Missing wrapper template: $WRAPPER_SOURCE" >&2
  exit 1
fi
if [[ ! -f "$POSTRM_SOURCE" ]]; then
  echo "Missing postrm template: $POSTRM_SOURCE" >&2
  exit 1
fi

if [[ ! -d frontend/dist ]]; then
  echo "frontend/dist is missing. Run 'cd frontend && npm ci && npm run build' before building the Debian package." >&2
  exit 1
fi

PACKAGE_VERSION="$("$PYTHON_BIN" -m sniff4hound.versioning --apply --print-version)"

echo "[build] Release version: $PACKAGE_VERSION"

echo "[build] Preparing Debian package layout..."
rm -rf "$BUILD_DIR"
mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR"/"${PACKAGE_NAME}"_*.deb "$DIST_DIR"/"${PACKAGE_NAME}"_*.deb.sha256
install -d "$DEBIAN_DIR" "$INSTALL_ROOT" "$VENDOR_DIR" "$BIN_DIR" "$DOC_DIR"

echo "[build] Installing Python application into staging root..."
"$PYTHON_BIN" -m pip install --disable-pip-version-check --no-compile --target "$VENDOR_DIR" .

find "$VENDOR_DIR" -type d -name "__pycache__" -exec rm -rf {} +
find "$VENDOR_DIR" -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete
rm -rf "$VENDOR_DIR/bin"

if find "$VENDOR_DIR" -type f \( -name "*.so" -o -name "*.pyd" \) | grep -q .; then
  PACKAGE_ARCH="$(dpkg --print-architecture)"
else
  PACKAGE_ARCH="all"
fi

cat > "$DEBIAN_DIR/control" <<EOF
Package: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Section: net
Priority: optional
Architecture: $PACKAGE_ARCH
Maintainer: JorgelSC Dev
Depends: python3 (>= 3.12)
Homepage: https://github.com/jorgelsc-dev/Sniff4Hound
Description: Native Python network sniffer with bundled web dashboard
 Sniff4Hound captures local traffic, persists runtime data in SQLite, and
 serves the bundled dashboard and API from a single process.
EOF

install -m 0644 "$LAUNCHER_SOURCE" "$INSTALL_ROOT/launcher.py"
install -m 0755 "$WRAPPER_SOURCE" "$BIN_DIR/sniff4hound"
install -m 0755 "$POSTRM_SOURCE" "$DEBIAN_DIR/postrm"
install -m 0644 README.md "$DOC_DIR/README.md"
install -m 0644 LICENSE "$DOC_DIR/LICENSE"

PACKAGE_FILE="$DIST_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}_${PACKAGE_ARCH}.deb"
# Unversioned copy of the exact same package. Published alongside the
# versioned one so the GitHub "latest release" redirect resolves to a URL
# that never changes between releases:
#   https://github.com/<owner>/<repo>/releases/latest/download/sniff4hound_latest.deb
# A real copy rather than a symlink - neither `dpkg-deb`, `gh release
# upload` nor `actions/upload-artifact` follow one usefully.
LATEST_FILE="$DIST_DIR/${PACKAGE_NAME}_latest.deb"

echo "[build] Building $PACKAGE_FILE..."
dpkg-deb --build --root-owner-group "$PACKAGE_ROOT" "$PACKAGE_FILE" >/dev/null

cp -f "$PACKAGE_FILE" "$LATEST_FILE"

(
  cd "$DIST_DIR"
  sha256sum "$(basename "$PACKAGE_FILE")" > "$(basename "$PACKAGE_FILE").sha256"
  # Checksum names its own file, so `sha256sum -c` works on the download.
  sha256sum "$(basename "$LATEST_FILE")" > "$(basename "$LATEST_FILE").sha256"
)

echo "[build] Created $PACKAGE_FILE"
echo "[build] Created $LATEST_FILE (unversioned copy)"
