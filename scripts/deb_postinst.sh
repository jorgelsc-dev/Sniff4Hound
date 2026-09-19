#!/bin/sh
set -e

# `regex` (a dependency of sniff4hound/regex_safety.py, used for
# timeout-bounded matching on the capture path) ships a compiled extension
# tied to one specific CPython ABI (e.g. cp312). It's vendored at build
# time under the interpreter that happened to run build_deb.sh - which is
# not necessarily /usr/bin/python3 on whatever machine later installs this
# .deb. When the two differ, the vendored .so can't be imported at all:
# Python reports it as a circular import ("cannot import name '_regex' from
# partially initialized module 'regex'") rather than a clear ABI mismatch,
# and sniff4hound refuses to start.
#
# Rather than have every install of this package depend on the build
# machine's Python version matching the target's, rebuild the vendored
# `regex` for whatever /usr/bin/python3 turns out to be on THIS machine,
# right after dpkg lays the files down - self-healing regardless of which
# Python built the release. The rebuild happens inside a throwaway venv
# rather than invoking the system pip directly as root: that keeps this
# entirely off the system Python's own site-packages (no risk of it or a
# later `apt` operation tripping over files pip put there) - only the
# built `regex` package is ever copied into sniff4hound's own vendor dir,
# and the venv is discarded immediately after.
VENDOR_DIR=/usr/lib/sniff4hound/vendor
PYTHON_BIN=/usr/bin/python3
REGEX_REQUIREMENT="regex>=2025.7.34"
DESKTOP_DIR=/usr/lib/sniff4hound/desktop
DESKTOP_ENTRY=/usr/share/applications/sniff4hound.desktop
DESKTOP_ICON=/usr/share/icons/hicolor/512x512/apps/sniff4hound.png
DESKTOP_BIN=/usr/bin/sniff4hound-desktop

rebuild_regex_via_venv() {
  tmp_root="$(mktemp -d)"
  trap 'rm -rf "$tmp_root"' EXIT INT TERM
  venv_dir="$tmp_root/venv"

  if ! "$PYTHON_BIN" -m venv "$venv_dir" >&2; then
    echo "sniff4hound: WARNING - '$PYTHON_BIN -m venv' failed (is python3-venv installed?). Install it with 'sudo apt install python3-venv' and then run 'sudo apt install --reinstall sniff4hound'." >&2
    return 1
  fi
  if ! "$venv_dir/bin/pip" install --disable-pip-version-check --no-compile --no-input "$REGEX_REQUIREMENT" >&2; then
    echo "sniff4hound: WARNING - could not download/build 'regex' inside a venv (no network access?). sniff4hound will not start until this is fixed - rerun 'sudo apt install --reinstall sniff4hound' once network access is available." >&2
    return 1
  fi

  site_packages="$(find "$venv_dir"/lib -maxdepth 1 -type d -name 'python*' -exec echo {}/site-packages \;)"
  if [ -z "$site_packages" ] || [ ! -d "$site_packages/regex" ]; then
    echo "sniff4hound: WARNING - built 'regex' but couldn't locate it inside the venv's site-packages ($site_packages)." >&2
    return 1
  fi

  rm -rf "$VENDOR_DIR"/regex "$VENDOR_DIR"/regex-*.dist-info
  cp -r "$site_packages"/regex "$VENDOR_DIR"/regex
  cp -r "$site_packages"/regex-*.dist-info "$VENDOR_DIR"/ 2>/dev/null || true
  find "$VENDOR_DIR"/regex -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
}

# The package always ships both the CLI and the desktop app's files (dpkg
# has no notion of "install this file only if..."), so this decides which
# ones actually stick around. postinst runs as root during `dpkg -i`/`apt
# install`, frequently from a plain non-graphical terminal even on a machine
# that does have a desktop environment installed - so this checks whether
# the SYSTEM is configured for a graphical session at all, not just whether
# this particular shell happens to have one.
machine_has_gui() {
  if command -v systemctl >/dev/null 2>&1; then
    if [ "$(systemctl get-default 2>/dev/null)" = "graphical.target" ]; then
      return 0
    fi
  fi
  for candidate in Xorg Xwayland X; do
    if command -v "$candidate" >/dev/null 2>&1; then
      return 0
    fi
  done
  # Covers an install run interactively from inside an already-graphical
  # terminal, where neither of the checks above may apply (e.g. a minimal
  # window manager with no display-manager/X-server package of its own).
  if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
    return 0
  fi
  return 1
}

case "$1" in
  configure)
    if [ -x "$PYTHON_BIN" ] && [ -d "$VENDOR_DIR" ]; then
      if ! "$PYTHON_BIN" -c "import sys; sys.path.insert(0, '$VENDOR_DIR'); import regex._regex" >/dev/null 2>&1; then
        echo "sniff4hound: the vendored 'regex' extension does not match $($PYTHON_BIN -c 'import sys; print(sys.version.split()[0])') - rebuilding it for this interpreter in a throwaway venv..." >&2
        if rebuild_regex_via_venv; then
          echo "sniff4hound: rebuilt 'regex' for $PYTHON_BIN." >&2
        fi
      fi
    fi

    if [ -d "$DESKTOP_DIR" ]; then
      if machine_has_gui; then
        echo "sniff4hound: graphical environment detected - keeping the desktop app (run it with 'sniff4hound-desktop' or from the applications menu)." >&2
        command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications 2>/dev/null || true
        command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true
      else
        echo "sniff4hound: no graphical environment detected - removing the bundled desktop app, keeping only the 'sniff4hound' command." >&2
        rm -rf "$DESKTOP_DIR"
        rm -f "$DESKTOP_ENTRY" "$DESKTOP_ICON" "$DESKTOP_BIN"
      fi
    fi
    ;;
esac

exit 0
