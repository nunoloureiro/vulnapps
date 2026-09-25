#!/usr/bin/env python3
"""Write CHANGELOG.json for the Docker image to serve.

The deployed image has no .git (see .dockerignore), so the release history is
resolved on the build host and baked in — the same arrangement COMMIT_COUNT
uses. Run from the repo root before `docker build`; build.sh and the deploy
workflow both do.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.changelog import build_entries  # noqa: E402
from app.version import PROJECT_DIR  # noqa: E402


def main() -> int:
    entries = build_entries()
    if not entries:
        print("gen_changelog: git returned nothing — is this a checkout with history?",
              file=sys.stderr)
        return 1

    out = PROJECT_DIR / "CHANGELOG.json"
    out.write_text(json.dumps({"entries": entries}, indent=1))
    print(f"gen_changelog: {len(entries)} releases, newest {entries[0]['version']} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
