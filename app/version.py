"""App version: v<major>.<minor>, where major is a hand-set number in
VERSION and minor is the number of commits to main.

The deployed Docker image has no .git (excluded from the build context, see
.dockerignore) to compute the commit count from at runtime, so build.sh
computes it on the host and passes it to `docker build` as a build arg,
which the Dockerfile bakes into COMMIT_COUNT inside the image. Local dev
(running uvicorn directly from a git checkout) has no such file, so it
falls back to asking git directly.
"""
import subprocess
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent


def _read_major() -> str:
    try:
        return (PROJECT_DIR / "VERSION").read_text().strip()
    except OSError:
        return "0"


def _read_minor() -> str:
    baked = PROJECT_DIR / "COMMIT_COUNT"
    if baked.exists():
        text = baked.read_text().strip()
        if text:
            return text

    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", "main"],
            cwd=PROJECT_DIR, capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "0"


def get_app_version() -> str:
    return f"v{_read_major()}.{_read_minor()}"
