"""Tests for app/version.py: v<major>.<minor>, where major comes from the
VERSION file and minor is the commit count to main -- baked in at Docker
build time (COMMIT_COUNT, since the deployed image has no .git), falling
back to asking git directly for local dev checkouts.
"""
import subprocess

import app.version as version_mod


def test_get_app_version_reads_major_and_baked_minor(tmp_path, monkeypatch):
    (tmp_path / "VERSION").write_text("3\n")
    (tmp_path / "COMMIT_COUNT").write_text("42\n")
    monkeypatch.setattr(version_mod, "PROJECT_DIR", tmp_path)

    assert version_mod.get_app_version() == "v3.42"


def test_get_app_version_falls_back_to_git_when_no_baked_file(tmp_path, monkeypatch):
    (tmp_path / "VERSION").write_text("1")
    monkeypatch.setattr(version_mod, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(
        version_mod.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="153\n"),
    )

    assert version_mod.get_app_version() == "v1.153"


def test_get_app_version_falls_back_to_git_when_baked_file_is_empty(tmp_path, monkeypatch):
    """The Docker build arg defaults to 0, so this shouldn't happen in
    practice, but an empty baked file must not silently win as "v<major>."
    (missing minor) over asking git."""
    (tmp_path / "VERSION").write_text("1")
    (tmp_path / "COMMIT_COUNT").write_text("")
    monkeypatch.setattr(version_mod, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(
        version_mod.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="99\n"),
    )

    assert version_mod.get_app_version() == "v1.99"


def test_get_app_version_defaults_to_zero_when_git_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(version_mod, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(
        version_mod.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 1),
    )

    assert version_mod.get_app_version() == "v0.0"


def test_get_app_version_handles_git_not_installed(tmp_path, monkeypatch):
    (tmp_path / "VERSION").write_text("2")
    monkeypatch.setattr(version_mod, "PROJECT_DIR", tmp_path)

    def _raise(*a, **k):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr(version_mod.subprocess, "run", _raise)

    assert version_mod.get_app_version() == "v2.0"
