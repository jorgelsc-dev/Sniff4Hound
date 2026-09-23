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
POSTINST_SOURCE="$ROOT_DIR/scripts/deb_postinst.sh"
POSTRM_SOURCE="$ROOT_DIR/scripts/deb_postrm.sh"
DESKTOP_ENTRY_SOURCE="$ROOT_DIR/scripts/sniff4hound.desktop"
DESKTOP_SOURCE_DIR="$ROOT_DIR/desktop"
DESKTOP_ICON_SOURCE="$DESKTOP_SOURCE_DIR/assets/icon.png"
DESKTOP_BIN_NAME="sniff4hound-desktop"
# Set SNIFF4HOUND_SKIP_DESKTOP=1 to produce a CLI-only package without
# building the Electron app at all (e.g. a constrained CI runner with no
# Node/Electron download available). The normal, released package always
# builds both - scripts/deb_postinst.sh decides at install time whether the
# desktop half actually sticks around, based on whether the target machine
# has a graphical environment.
BUILD_DESKTOP="1"
if [[ "${SNIFF4HOUND_SKIP_DESKTOP:-0}" == "1" ]]; then
  BUILD_DESKTOP="0"
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_command "$PYTHON_BIN"
require_command dpkg-deb
require_command sha256sum
require_command npm

if [[ ! -f "$LAUNCHER_SOURCE" ]]; then
  echo "Missing launcher template: $LAUNCHER_SOURCE" >&2
  exit 1
fi
if [[ ! -f "$WRAPPER_SOURCE" ]]; then
  echo "Missing wrapper template: $WRAPPER_SOURCE" >&2
  exit 1
fi
if [[ ! -f "$POSTINST_SOURCE" ]]; then
  echo "Missing postinst template: $POSTINST_SOURCE" >&2
  exit 1
fi
if [[ ! -f "$POSTRM_SOURCE" ]]; then
  echo "Missing postrm template: $POSTRM_SOURCE" >&2
  exit 1
fi
if [[ "$BUILD_DESKTOP" == "1" && ! -f "$DESKTOP_ENTRY_SOURCE" ]]; then
  echo "Missing desktop entry template: $DESKTOP_ENTRY_SOURCE" >&2
  exit 1
fi

echo "[build] Building frontend..."
(cd "$ROOT_DIR/desktop/frontend" && npm ci && npm run build)

PACKAGE_VERSION="$("$PYTHON_BIN" -m sniff4hound.versioning --apply --print-version)"

echo "[build] Release version: $PACKAGE_VERSION"

echo "[build] Preparing Debian package layout..."
rm -rf "$BUILD_DIR"
mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR"/"${PACKAGE_NAME}"_*.deb "$DIST_DIR"/"${PACKAGE_NAME}"_*.deb.sha256
install -d "$DEBIAN_DIR" "$INSTALL_ROOT" "$VENDOR_DIR" "$BIN_DIR" "$DOC_DIR"

echo "[build] Installing Python application into staging root..."
"$PYTHON_BIN" -m pip install --disable-pip-version-check --no-compile --target "$VENDOR_DIR" .

# The wsbuilder requirement is a floor, not an exact pin, so two builds of the
# same commit can vendor different versions. Record what this one shipped.
VENDORED_WSBUILDER="$(find "$VENDOR_DIR" -maxdepth 1 -name 'wsbuilder-*.dist-info' -printf '%f\n' 2>/dev/null | head -n 1)"
VENDORED_WSBUILDER="${VENDORED_WSBUILDER%.dist-info}"
echo "[build] Vendored ${VENDORED_WSBUILDER:-wsbuilder (version could not be resolved)}"

find "$VENDOR_DIR" -type d -name "__pycache__" -exec rm -rf {} +
find "$VENDOR_DIR" -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete
rm -rf "$VENDOR_DIR/bin"

DESKTOP_INSTALL_ROOT="$INSTALL_ROOT/desktop"
APPLICATIONS_DIR="$PACKAGE_ROOT/usr/share/applications"
ICON_DIR="$PACKAGE_ROOT/usr/share/icons/hicolor/512x512/apps"

if [[ "$BUILD_DESKTOP" == "1" ]]; then
  echo "[build] Building desktop (Electron) app..."
  if [[ -f "$DESKTOP_SOURCE_DIR/package-lock.json" ]]; then
    (cd "$DESKTOP_SOURCE_DIR" && npm ci)
  else
    (cd "$DESKTOP_SOURCE_DIR" && npm install)
  fi
  # Keeps the bundled Electron app reporting the same version as the .deb
  # it ships inside.
  (cd "$DESKTOP_SOURCE_DIR" && npm pkg set version="$PACKAGE_VERSION" >/dev/null)
  rm -rf "$ROOT_DIR/dist/desktop"
  # `--linux dir` (electron-builder's unpacked target): just the app binary
  # and its resources, no AppImage/deb of its own - this script builds the
  # one combined .deb everything ships in. It shares the vendored Python
  # runtime above (see desktop/main.js's usingSharedVendorRuntime()) rather
  # than bundling a second copy.
  (cd "$DESKTOP_SOURCE_DIR" && npm run pack)

  UNPACKED_DIR="$ROOT_DIR/dist/desktop/linux-unpacked"
  if [[ ! -d "$UNPACKED_DIR" ]]; then
    echo "Desktop build did not produce $UNPACKED_DIR" >&2
    exit 1
  fi

  install -d "$DESKTOP_INSTALL_ROOT" "$APPLICATIONS_DIR" "$ICON_DIR"
  cp -a "$UNPACKED_DIR"/. "$DESKTOP_INSTALL_ROOT"/
  ln -sf "../lib/$PACKAGE_NAME/desktop/$DESKTOP_BIN_NAME" "$BIN_DIR/$DESKTOP_BIN_NAME"
  install -m 0644 "$DESKTOP_ICON_SOURCE" "$ICON_DIR/sniff4hound.png"
  install -m 0644 "$DESKTOP_ENTRY_SOURCE" "$APPLICATIONS_DIR/sniff4hound.desktop"
fi

# The bundled Electron binaries are always architecture-specific, even when
# the vendored Python side happens to be pure-python ("all").
if [[ "$BUILD_DESKTOP" == "1" ]] || find "$VENDOR_DIR" -type f \( -name "*.so" -o -name "*.pyd" \) | grep -q .; then
  PACKAGE_ARCH="$(dpkg --print-architecture)"
else
  PACKAGE_ARCH="all"
fi

# The GUI libs and policykit-1/pkexec are only ever needed by the desktop
# app, which scripts/deb_postinst.sh prunes entirely on a machine with no
# graphical environment - Recommends (not Depends) so a headless install
# isn't forced to pull in graphics libraries it will never use. `sudo` is
# listed as a fallback for policykit-1/pkexec so the combined `sniff4hound`
# command can still self-elevate (see sniff4hound/manage.py's
# _ensure_running_as_root()) on a machine that skips both.
#
# `desktop/package.json`'s own "name" is "sniff4hound-desktop" - if that
# package is ever installed standalone (electron-builder's raw `deb`
# target, e.g. from dist/desktop/*.deb during dev), it ships its own
# /usr/share/applications/sniff4hound-desktop.desktop under /opt/Sniff4Hound,
# alongside this package's own desktop entry - two "Sniff4Hound" launcher
# icons, one of them stale. Conflicts+Replaces makes apt remove that
# standalone package automatically on install/upgrade instead of leaving
# both registered in dpkg (a bare `rm -f` in postinst was tried and
# reverted for exactly this: it deletes a file dpkg still believes a
# *different* package owns, without fixing that package's own record).
cat > "$DEBIAN_DIR/control" <<EOF
Package: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Section: net
Priority: optional
Architecture: $PACKAGE_ARCH
Maintainer: JorgelSC Dev
Depends: python3 (>= 3.12)
Recommends: python3-venv, policykit-1 | pkexec | sudo, libgtk-3-0, libnotify4, libnss3, libxss1, libxtst6, xdg-utils, libatspi2.0-0, libuuid1, libsecret-1-0
Conflicts: sniff4hound-desktop
Replaces: sniff4hound-desktop
Homepage: https://github.com/jorgelsc-dev/Sniff4Hound
Description: Native Python network sniffer with bundled web dashboard and desktop app
 Sniff4Hound captures local traffic, persists runtime data in SQLite, and
 serves the bundled dashboard and API from a single process. Installs the
 sniff4hound command always; also installs the Electron desktop app when
 the target machine has a graphical environment.
EOF

install -m 0644 "$LAUNCHER_SOURCE" "$INSTALL_ROOT/launcher.py"
install -m 0755 "$WRAPPER_SOURCE" "$BIN_DIR/sniff4hound"
install -m 0755 "$POSTINST_SOURCE" "$DEBIAN_DIR/postinst"
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
