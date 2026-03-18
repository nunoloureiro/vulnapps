from __future__ import annotations
from typing import Optional, Tuple, List


def app_visibility_filter(user: Optional[dict]) -> Tuple[str, List]:
    """Return a SQL WHERE clause and params for filtering apps by visibility."""
    if not user:
        return "apps.visibility = 'public'", []

    if user["role"] == "admin":
        return "1=1", []

    return (
        "(apps.visibility = 'public'"
        " OR (apps.visibility = 'private' AND apps.created_by = ?)"
        " OR (apps.visibility = 'team' AND apps.team_id IN"
        "     (SELECT team_id FROM team_members WHERE user_id = ?)))",
        [user["sub"], user["sub"]],
    )


def scan_visibility_filter(user: Optional[dict]) -> Tuple[str, List]:
    """Return a SQL WHERE clause and params for filtering scans by visibility.

    Includes public scans on public apps, user's own scans, and scans on team apps.
    """
    if not user:
        return "(scans.is_public=1 AND apps.visibility = 'public')", []

    if user["role"] == "admin":
        return "1=1", []

    return (
        "((scans.is_public=1 AND apps.visibility = 'public')"
        " OR scans.submitted_by=?"
        " OR (apps.visibility = 'team' AND apps.team_id IN"
        "     (SELECT team_id FROM team_members WHERE user_id = ?)))",
        [user["sub"], user["sub"]],
    )
