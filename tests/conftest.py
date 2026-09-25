"""Point DATABASE_PATH at a throwaway copy before anything imports the app.

`app/config.py` reads DATABASE_PATH once, at import, after `load_dotenv()` —
so whichever test module imports `app.*` first decides which database the
whole session talks to. That used to be tests/test_api_endpoints.py purely
because it sorted first alphabetically: it set the env var at module scope
before importing the app, and `load_dotenv()` does not override variables that
are already set. Adding any test file that sorts earlier and imports `app.*`
(tests/test_admin_scope.py did) moved that decision, `.env`'s own
DATABASE_PATH won instead, and the suite died at collection with "unable to
open database file".

pytest imports conftest before any test module, so doing it here makes the
ordering explicit rather than alphabetical luck. The real database is copied
rather than opened, so a test run can never write to it.
"""

import os
import shutil
import tempfile
from pathlib import Path

_REAL_DB = Path(__file__).resolve().parent.parent / "vulnapps.db"
TEST_DB = Path(tempfile.mkdtemp()) / "test_vulnapps.db"

if "DATABASE_PATH" not in os.environ:  # a caller (CI) may have chosen already
    if _REAL_DB.exists():
        shutil.copy2(_REAL_DB, TEST_DB)
        # WAL/SHM too, or the copy can be missing recently committed rows.
        for ext in ("-wal", "-shm"):
            sidecar = _REAL_DB.with_name(_REAL_DB.name + ext)
            if sidecar.exists():
                shutil.copy2(sidecar, TEST_DB.with_name(TEST_DB.name + ext))
    os.environ["DATABASE_PATH"] = str(TEST_DB)
