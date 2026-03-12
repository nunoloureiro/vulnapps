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
