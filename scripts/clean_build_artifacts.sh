#!/usr/bin/env bash
#
# Remove generated build/cache/test-artifact directories that build up in
# the working tree during normal development (dist/, build/, QA/,
# __pycache__/, .pytest_cache/, *.egg-info/) - see FAQA.md findings 1.9/8.4.
#
# These hold no captured traffic, credentials or other sensitive data - they
# just clutter the workspace and confuse a manual review. This is a
# deliberately separate script from clean_artifacts.sh (which only ever
# touches runtime data: DBs, logs, certs) rather than a flag added to it -
# build/cache cleanup and sensitive-data cleanup should never share one
# command that could delete more than an operator intended by asking for
# the other kind of cleanup.
#
# Defaults to a dry run (list only, delete nothing). Pass --yes to actually
# delete after listing.
#
#   ./scripts/clean_build_artifacts.sh            # list only (default)
#   ./scripts/clean_build_artifacts.sh --yes       # list, then delete
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --yes|-y) ASSUME_YES=1 ;;
        --dry-run|-n) ASSUME_YES=0 ;; # already the default; accepted for symmetry with clean_artifacts.sh
        --help|-h)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

mapfile -t FOUND < <(
    find . \
        \( -name node_modules -o -name .git -o -name .venv -o -name .venv-test -o -name site \) -prune -o \
        -type d \( -name dist -o -name build -o -name QA -o -name __pycache__ -o -name .pytest_cache -o -name '*.egg-info' \) -print |
        sort
)

if [ "${#FOUND[@]}" -eq 0 ]; then
    echo "No build/cache artifacts found in $ROOT_DIR"
    exit 0
fi

echo "Build/cache artifacts found in $ROOT_DIR:"
for path in "${FOUND[@]}"; do
    printf '  %s (%s)\n' "$path" "$(du -sh "$path" 2>/dev/null | cut -f1)"
done

if [ "$ASSUME_YES" -ne 1 ]; then
    echo
    echo "Dry run: nothing deleted. Re-run with --yes to delete the directories listed above."
    exit 0
fi

for path in "${FOUND[@]}"; do
    rm -rf -- "$path"
    echo "removed $path"
done
echo "Done."
