#!/bin/sh
set -e

# Every module under /usr/lib/sniff4hound/vendor picks up a __pycache__
# directory the first time it's imported (nothing here passes
# PYTHONDONTWRITEBYTECODE, and the capture child runs as root so it can
# always write one). dpkg never tracked those .pyc files - it only shipped
# the .py sources - so it refuses to remove the now-nonempty
# __pycache__ directories on its own, leaving them behind after both
# `apt remove` and `apt purge`. They're disposable bytecode cache, not
# configuration or user data, so it's safe to clear the whole install root
# on either operation once dpkg is done removing what it does track.
case "$1" in
  remove|purge)
    rm -rf /usr/lib/sniff4hound
    ;;
esac

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
