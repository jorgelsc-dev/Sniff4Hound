#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-jorgelsc-dev/sniff4hound}"

if ! gh auth status -h github.com >/dev/null 2>&1; then
  echo "GitHub CLI is not authenticated for github.com."
  echo "Run: gh auth login -h github.com"
  exit 1
fi

gh repo edit "$REPO" \
  --description "Native Python packet sniffer with SQLite persistence, live statistics, and an HTTP/WebSocket runtime powered by wsbuilder." \
  --add-topic python \
  --add-topic cybersecurity \
  --add-topic network-scanner \
  --add-topic port-scanner \
  --add-topic banner-grabbing \
  --add-topic tcp \
  --add-topic udp \
  --add-topic icmp \
  --add-topic sctp \
  --add-topic sqlite \
  --add-topic websocket \
  --add-topic api \
  --add-topic threading \
  --add-topic security-audit \
  --add-topic pentest-tools

echo "Updated About metadata for $REPO"
