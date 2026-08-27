#!/usr/bin/env bash
#
# Remove Sniff4Hound runtime artifacts that older versions left inside the
# working tree (the runtime now always writes under SNIFF4HOUND_DATA_DIR, see
# settings.resolve_data_path).
#
# These files hold real captured traffic, so nothing is deleted without
# asking: run it, read the list, confirm. Pass --dry-run to only list, or
# --yes to skip the prompt.
#
#   ./scripts/clean_artifacts.sh --dry-run
#   ./scripts/clean_artifacts.sh
#
# The per-user data directory (~/.local/share/sniff4hound by default) is NEVER
# touched here - that is the live database of a working install.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --dry-run|-n) DRY_RUN=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --help|-h)
            sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

# Names only: matched anywhere under the repo, so the stray copies that ended
# up in frontend/ are caught too. Never a glob wide enough to reach source.
ARTIFACT_NAMES=(
    "Sniff4Hound.db"
    "Sniff4Hound.db-wal"
    "Sniff4Hound.db-shm"
    "Sniff4Hound.db-journal"
    "honeypot.log"
    "honeypot_events.db"
    "honeypot_key.pem"
    "honeypot_cert.pem"
    "service_listener.log"
    "service_events.db"
    "service_key.pem"
    "service_cert.pem"
)

FIND_ARGS=()
for name in "${ARTIFACT_NAMES[@]}"; do
    FIND_ARGS+=(-name "$name" -o)
done
unset 'FIND_ARGS[${#FIND_ARGS[@]}-1]'

mapfile -t FOUND < <(
    find . \
        -type d \( -name node_modules -o -name .git -o -name .venv-test -o -name dist -o -name site \) -prune -o \
        -type f \( "${FIND_ARGS[@]}" \) -print | sort
)

if [ "${#FOUND[@]}" -eq 0 ]; then
    echo "No runtime artifacts found in $ROOT_DIR"
    exit 0
fi

echo "Runtime artifacts found in $ROOT_DIR:"
for path in "${FOUND[@]}"; do
    printf '  %s (%s)\n' "$path" "$(du -h "$path" | cut -f1)"
done

if [ "$DRY_RUN" -eq 1 ]; then
    echo
    echo "Dry run: nothing deleted."
    exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
    echo
    echo "These files may contain real captured traffic."
    read -r -p "Delete them? [y/N] " answer
    case "$answer" in
        [yY]|[yY][eE][sS]) ;;
        *) echo "Aborted."; exit 0 ;;
    esac
fi

for path in "${FOUND[@]}"; do
    rm -f -- "$path"
    echo "removed $path"
done
echo "Done."
