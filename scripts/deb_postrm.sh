#!/bin/sh
set -e

# Sniff4Hound stores its runtime data (SQLite DB, honeypot log/events,
# TLS certs) under each user's $XDG_DATA_HOME/sniff4hound (default
# ~/.local/share/sniff4hound - see sniff4hound/settings.py:DATA_DIR).
# This is not tracked by dpkg, so it survives a plain `apt remove`; only
# clean it up on `apt purge`, per Debian policy convention for user data.
case "$1" in
  purge)
    getent passwd | awk -F: '($3 >= 1000 && $3 < 60000) || $3 == 0 { print $6 }' | sort -u | while IFS= read -r home_dir; do
      [ -n "$home_dir" ] || continue
      data_dir="$home_dir/.local/share/sniff4hound"
      if [ -d "$data_dir" ]; then
        rm -rf "$data_dir"
      fi
    done
    ;;
esac

exit 0
