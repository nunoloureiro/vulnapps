import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
DATABASE_PATH = os.getenv("DATABASE_PATH", "vulnapps.db")
TOKEN_EXPIRY_HOURS = int(os.getenv("TOKEN_EXPIRY_HOURS", "24"))

# Where uploaded scan-state zips live (one file per scan). Default: a
# `scan-state` directory next to the database.
STATE_DIR = os.getenv("STATE_DIR") or str(Path(DATABASE_PATH).resolve().parent / "scan-state")

# Hard cap on a single scan-state upload (bytes). Default 100 MiB.
MAX_STATE_SIZE = int(os.getenv("MAX_STATE_SIZE", str(100 * 1024 * 1024)))
