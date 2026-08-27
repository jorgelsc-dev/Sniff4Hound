#!/bin/sh
set -eu

export PYTHONPATH="/usr/lib/sniff4hound/vendor${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 /usr/lib/sniff4hound/launcher.py "$@"
