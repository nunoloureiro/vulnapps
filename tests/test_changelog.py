"""Release history derived from git, one entry per commit on main.

The app reports v<major>.<minor> with minor = the commit count, so the
changelog is only correct if the version it prints beside a commit is the
version the app would have reported at that commit. The subtle part is merge
commits: they count towards `rev-list --count` but a commit's position in
`git log` is not its ancestor count, so numbering the log top to bottom
silently skews every entry below the first merge.

These build throwaway repos with `git` so the numbering is checked against
real history shapes rather than a mock.
"""

import json
import subprocess
from pathlib import Path

import pytest

from app import changelog


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "GIT_AUTHOR_NAME": "Tester", "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "Tester", "GIT_COMMITTER_EMAIL": "t@example.com",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        },
    )
    return result.stdout.strip()


def commit(repo: Path, message: str, filename: str = "file.txt") -> None:
    (repo / filename).write_text(message)
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message, "--no-gpg-sign")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A git repo standing in for the project, with VERSION set to 1."""
    path = tmp_path / "proj"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    (path / "VERSION").write_text("1\n")
    commit(path, "Initial commit")

    monkeypatch.setattr(changelog, "PROJECT_DIR", path)
    monkeypatch.setattr(changelog, "BAKED", path / "CHANGELOG.json")
    monkeypatch.setattr(changelog, "_cache", None)
    # version.py reads VERSION from its own PROJECT_DIR.
    monkeypatch.setattr("app.version.PROJECT_DIR", path)
    return path


def test_linear_history_numbers_from_one(repo):
    commit(repo, "Second thing")
    commit(repo, "Third thing")

    entries = changelog.build_entries()

    assert [e["version"] for e in entries] == ["v1.3", "v1.2", "v1.1"]
    assert [e["subject"] for e in entries] == ["Third thing", "Second thing", "Initial commit"]


def test_version_matches_what_the_app_reports(repo):
    """The whole contract: the newest entry is the running version."""
    commit(repo, "Second thing")
    commit(repo, "Third thing")

    newest = changelog.build_entries()[0]
    count = git(repo, "rev-list", "--count", "main")

    assert newest["version"] == f"v1.{count}"


def test_merge_commits_do_not_skew_the_numbering(repo):
    """A commit's minor is its ancestor count, not its row in the log.

    Branch, commit on both sides, merge. The merge has 5 ancestors including
    itself; the side commits each have fewer. Numbering the log by position
    would hand the merge the wrong version and shift everything under it.
    """
    commit(repo, "Second thing")                        # 2 ancestors
    git(repo, "checkout", "-q", "-b", "side")
    commit(repo, "Side work", filename="side.txt")      # 3 on this line
    git(repo, "checkout", "-q", "main")
    commit(repo, "Main work", filename="main.txt")      # 3 on that line
    git(repo, "merge", "--no-ff", "-q", "side", "-m", "Merge side", "--no-gpg-sign")

    entries = changelog.build_entries()
    by_subject = {e["subject"]: e for e in entries}

    # Cross-check every entry against git's own answer for that commit.
    for entry in entries:
        expected = git(repo, "rev-list", "--count", entry["sha"])
        assert entry["version"] == f"v1.{expected}", entry["subject"]

    assert by_subject["Merge side"]["version"] == "v1.5"
    assert by_subject["Merge side"]["is_merge"] is True
    assert by_subject["Main work"]["is_merge"] is False
    # The two side-by-side commits genuinely share a number — they sit at the
    # same depth on different lines. The merge is what makes 5 reachable.
    assert by_subject["Side work"]["version"] == by_subject["Main work"]["version"] == "v1.3"


def test_entries_are_newest_first(repo):
    commit(repo, "Second thing")
    commit(repo, "Third thing")

    minors = [e["minor"] for e in changelog.build_entries()]

    assert minors == sorted(minors, reverse=True)


def test_body_is_kept_separate_from_subject(repo):
    (repo / "file.txt").write_text("x")
    git(repo, "add", "-A")
    git(repo, "commit", "--no-gpg-sign", "-m", "Short subject",
        "-m", "A longer explanation\nover two lines.")

    newest = changelog.build_entries()[0]

    assert newest["subject"] == "Short subject"
    assert newest["body"] == "A longer explanation\nover two lines."


def test_multiline_message_does_not_break_parsing(repo):
    """Commit text is user input: pipes, quotes and blank lines must not eat
    the record separators."""
    git(repo, "commit", "--allow-empty", "--no-gpg-sign",
        "-m", 'Weird | "quoted" \x7c subject',
        "-m", "body with\n\nblank lines and | pipes")

    entries = changelog.build_entries()

    assert entries[0]["subject"] == 'Weird | "quoted" | subject'
    assert "blank lines" in entries[0]["body"]
    assert len(entries) == 2, "the odd message must not swallow the commit below it"


def test_baked_file_is_preferred_over_git(repo):
    """What the deployed image does: read the file, never shell out."""
    (repo / "CHANGELOG.json").write_text(json.dumps(
        {"entries": [{"version": "v1.999", "subject": "From the image"}]}
    ))

    assert changelog.get_changelog() == [{"version": "v1.999", "subject": "From the image"}]


def test_corrupt_baked_file_falls_back_to_git(repo):
    """A broken file must not leave the page permanently empty."""
    (repo / "CHANGELOG.json").write_text("{not json")

    entries = changelog.get_changelog()

    assert entries and entries[0]["subject"] == "Initial commit"


def test_no_git_and_no_file_is_empty_not_an_error(tmp_path, monkeypatch):
    """An image built without the generator still serves; the page just says
    there is nothing, rather than 500ing."""
    monkeypatch.setattr(changelog, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(changelog, "BAKED", tmp_path / "CHANGELOG.json")
    monkeypatch.setattr(changelog, "_cache", None)

    assert changelog.get_changelog() == []
