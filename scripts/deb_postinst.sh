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
# Python built the release.
VENDOR_DIR=/usr/lib/sniff4hound/vendor
PYTHON_BIN=/usr/bin/python3
REGEX_REQUIREMENT="regex>=2025.7.34"

case "$1" in
  configure)
    if [ -x "$PYTHON_BIN" ] && [ -d "$VENDOR_DIR" ]; then
      if ! "$PYTHON_BIN" -c "import sys; sys.path.insert(0, '$VENDOR_DIR'); import regex._regex" >/dev/null 2>&1; then
        echo "sniff4hound: the vendored 'regex' extension does not match $($PYTHON_BIN -c 'import sys; print(sys.version.split()[0])') - rebuilding it for this interpreter..." >&2
        if "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
          rm -rf "$VENDOR_DIR"/regex "$VENDOR_DIR"/regex-*.dist-info
          if "$PYTHON_BIN" -m pip install --disable-pip-version-check --no-compile --target "$VENDOR_DIR" "$REGEX_REQUIREMENT" >&2; then
            echo "sniff4hound: rebuilt 'regex' for $PYTHON_BIN." >&2
          else
            echo "sniff4hound: WARNING - could not rebuild 'regex' automatically (no network access?). sniff4hound will not start until this is fixed - run 'sudo $PYTHON_BIN -m pip install --no-compile --target $VENDOR_DIR $REGEX_REQUIREMENT' manually once network access is available." >&2
          fi
        else
          echo "sniff4hound: WARNING - python3-pip is not installed, so the vendored 'regex' extension could not be rebuilt for this interpreter. Install it with 'sudo apt install python3-pip' and then run 'sudo apt install --reinstall sniff4hound'." >&2
        fi
      fi
    fi
    ;;
esac

exit 0
