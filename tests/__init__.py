"""Test-suite bootstrap: keep every test off the operator's live database.

`settings.DATA_DIR` deliberately resolves to a fixed per-user location
(`~/.local/share/sniff4hound`) rather than the process cwd, and
`settings.DB_PATH` follows it - so `SniffStore()` with no explicit path opens
the very database a running Sniff4Hound is capturing into. `sniff4hound/app.py`
constructs one at module scope (`store = SniffStore(DB_PATH)`), which means
merely *importing* it - as `tests/test_smoke.py` and friends do - is enough.

Running the suite while the app was up therefore opened the live database
read-write from a second process and held write transactions across it; the
running instance started answering `POST /api/runtime/` with
"database is locked" until the test run ended. Individual tests being careful
with temp dirs cannot prevent it, because the connection happens at import
time, before any test method runs.

This module is imported before any test module in the package, so pointing
SNIFF4HOUND_DATA_DIR at a
throwaway directory here happens before `sniff4hound.settings` is first
imported and its module-level constants are computed. An explicit
SNIFF4HOUND_DATA_DIR in the environment still wins, so a deliberate run
against a specific directory is unaffected.

IMPORTANT - the test command must be `unittest discover -t . -s tests`, not
`unittest discover -s tests`. Without `-t .`, discovery puts `tests/` itself
on sys.path and imports the modules top-level (`test_smoke`) instead of as
package members (`tests.test_smoke`), which skips this file entirely and
takes the guard with it. That is not hypothetical: it is how a full-suite run
ended up opening the operator's live database and wedging a running capture.
pytest imports them as package members either way.

Note this only redirects the *runtime* data directory (database, logs). The
packaged read-only catalogs - default_monitors.json, ip_registry.json - are
resolved separately by `runtime_paths.resolve_data_file()` against the
installed package, so they keep loading normally.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile

if not os.environ.get("SNIFF4HOUND_DATA_DIR"):
    _TEST_DATA_DIR = tempfile.mkdtemp(prefix="sniff4hound-tests-")
    os.environ["SNIFF4HOUND_DATA_DIR"] = _TEST_DATA_DIR
    os.environ.setdefault("SNIFF4HOUND_DB_PATH", os.path.join(_TEST_DATA_DIR, "Sniff4Hound.db"))
    # Without this the suite leaves a full SQLite database behind on every
    # run; 63 of them, 22 MB each, had accumulated in /tmp.
    atexit.register(shutil.rmtree, _TEST_DATA_DIR, ignore_errors=True)
