from __future__ import annotations

import runpy
import site
import sys
from pathlib import Path


INSTALL_ROOT = Path(__file__).resolve().parent
VENDOR_DIR = INSTALL_ROOT / "vendor"

if str(VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(VENDOR_DIR))
site.addsitedir(str(VENDOR_DIR))
sys.argv[0] = "sniff4hound"

try:
    runpy.run_module("sniff4hound.manage", run_name="__main__", alter_sys=True)
except ModuleNotFoundError as exc:
    missing_root = str(getattr(exc, "name", "") or "").split(".", 1)[0]
    if missing_root == "sniff4hound":
        raise SystemExit(
            "Sniff4Hound runtime is incomplete. Reinstall the Debian package with "
            "'sudo apt install --reinstall sniff4hound'."
        ) from exc
    raise
