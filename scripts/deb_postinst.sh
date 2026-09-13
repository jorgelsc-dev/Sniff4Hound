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
    ;;
esac

exit 0
