"""Release history: one entry per commit on main, keyed by the version it produced.

The app's version is ``v<major>.<minor>`` with minor = ``git rev-list --count
main`` (see app/version.py), so every commit on main *is* a release and the
changelog is just the commit log with the right version number attached.

The minor number of a given commit is its own ancestor count, which is NOT the
same as its position in ``git log``: with merge commits the log's order and the
DAG's ancestor counts diverge. So the counts are derived from the parent graph
rather than by enumerating the log, which keeps "v1.171" here pointing at the
same commit the running app reports as v1.171.

Like COMMIT_COUNT, this is computed on the build host and baked into the image
(tools/gen_changelog.py writes CHANGELOG.json), because the deployed image has
no .git to read — see .dockerignore. A git checkout falls back to asking git
directly, so local dev needs no build step.
"""
import json
import subprocess
from pathlib import Path

from app.version import PROJECT_DIR, _read_major

BAKED = PROJECT_DIR / "CHANGELOG.json"

# Field separator inside a record, and the record separator. Both are control
# characters that cannot occur in a commit message, so a subject or body
# containing newlines, pipes or quotes still parses.
_FIELD = "\x1f"
_RECORD = "\x1e"

_cache: list[dict] | None = None


def _git(args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args], cwd=PROJECT_DIR,
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _ancestor_counts(ref: str) -> dict[str, int]:
    """``{sha: number of commits reachable from it}`` — each commit's minor.

    One `git rev-list --parents` call, then reachability as integer bitmasks:
    a commit reaches itself plus everything its parents reach. Bitmasks rather
    than sets keep this cheap on a long history.
    """
    out = _git(["rev-list", "--parents", ref])
    if out is None:
        return {}

    parents: dict[str, list[str]] = {}
    order: list[str] = []  # newest first, as rev-list emits
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        parents[parts[0]] = parts[1:]
        order.append(parts[0])

    bit = {sha: index for index, sha in enumerate(order)}
    reach: dict[str, int] = {}
    for sha in reversed(order):  # oldest first, so parents resolve before children
        mask = 1 << bit[sha]
        for parent in parents.get(sha, ()):
            mask |= reach.get(parent, 0)
        reach[sha] = mask
    return {sha: mask.bit_count() for sha, mask in reach.items()}


def _resolve_ref(ref: str) -> str | None:
    """*ref* if it exists, else HEAD — a CI checkout of a pull request is
    detached and has no local `main`, and failing there would break the build
    over a page that is only cosmetic."""
    for candidate in (ref, "HEAD"):
        if _git(["rev-parse", "--verify", "--quiet", candidate]):
            return candidate
    return None


def build_entries(ref: str = "main") -> list[dict]:
    """Every commit on *ref*, newest first, with its version and release time."""
    resolved = _resolve_ref(ref)
    if resolved is None:
        return []
    ref = resolved

    counts = _ancestor_counts(ref)
    if not counts:
        return []

    fmt = _FIELD.join(["%H", "%cI", "%an", "%s", "%b"]) + _RECORD
    out = _git(["log", ref, f"--format={fmt}"])
    if out is None:
        return []

    major = _read_major()
    entries = []
    for record in out.split(_RECORD):
        record = record.strip("\n")
        if not record.strip():
            continue
        sha, date, author, subject, body = (record.split(_FIELD) + [""] * 5)[:5]
        minor = counts.get(sha)
        if minor is None:
            continue
        entries.append({
            "version": f"v{major}.{minor}",
            "minor": minor,
            "sha": sha[:9],
            "date": date,
            "author": author,
            "subject": subject,
            "body": body.strip(),
            # Merge commits still increment the version (rev-list counts them),
            # so they are kept rather than filtered — dropping them would make
            # the numbers here disagree with the running app. The UI can fold
            # them away; the data stays honest.
            "is_merge": len(subject) > 0 and subject.startswith("Merge "),
        })
    entries.sort(key=lambda e: e["minor"], reverse=True)
    return entries


def get_changelog() -> list[dict]:
    """Baked changelog if the image has one, else read the git checkout."""
    global _cache
    if _cache is not None:
        return _cache

    if BAKED.exists():
        try:
            _cache = json.loads(BAKED.read_text())["entries"]
            return _cache
        except (OSError, ValueError, KeyError):
            pass  # fall through to git rather than serving nothing

    _cache = build_entries()
    return _cache
