"""An API key's scope must cap it even when its owner is an admin.

Role and scope are independent axes: `role` says who you are, `api_key_scope`
says what this particular credential may do. Every route in
app/routers/api/admin.py checked only the role, so a key minted with
scope='read' or 'vuln-mapper' by an admin reached all of them — listing and
editing users included. Found by probing the live /api/admin/changelog with a
vuln-mapper key and getting 200 where 403 was expected.

The gate is one helper, so it is tested directly rather than through HTTP:
tests/test_api_endpoints.py is the only HTTP-level suite and it needs a copy
of the real database, which is why CI skips it.
"""

import pytest
from fastapi import HTTPException

from app.dependencies import require_scope
from app.routers.api.admin import _require_admin


class FakeRequest:
    """Just enough Request for the helper: it only reads request.state.user."""

    def __init__(self, user):
        self.state = type("S", (), {"user": user})()


def admin(scope=None):
    """An admin, authenticated by an API key of *scope* (None = JWT/cookie)."""
    user = {"sub": 1, "name": "Nuno", "role": "admin"}
    if scope is not None:
        user["api_key_scope"] = scope
    return user


def test_session_admin_passes():
    """A browser session carries no scope and must keep working."""
    assert _require_admin(FakeRequest(admin()))["role"] == "admin"


def test_full_scope_key_passes():
    assert _require_admin(FakeRequest(admin("full")))["role"] == "admin"


@pytest.mark.parametrize("scope", ["read", "vuln-mapper"])
def test_narrow_key_is_refused_even_for_an_admin(scope):
    """The actual fix: owning the key is not the same as the key being allowed."""
    with pytest.raises(HTTPException) as excinfo:
        _require_admin(FakeRequest(admin(scope)))

    assert excinfo.value.status_code == 403
    assert scope in excinfo.value.detail, "the refusal should name the offending scope"


def test_non_admin_is_still_refused_on_role():
    """Role is checked before scope, so a full-scope key cannot buy admin."""
    user = {"sub": 2, "name": "Someone", "role": "user", "api_key_scope": "full"}

    with pytest.raises(HTTPException) as excinfo:
        _require_admin(FakeRequest(user))

    assert excinfo.value.status_code == 403
    assert excinfo.value.detail == "Admin access required"


def test_anonymous_is_401_not_403():
    with pytest.raises(HTTPException) as excinfo:
        _require_admin(FakeRequest(None))

    assert excinfo.value.status_code == 401


def test_every_admin_route_goes_through_the_gate():
    """A new route added without _require_admin would silently be public to any
    authenticated caller, so assert the wiring rather than trusting review."""
    import inspect
    from app.routers.api import admin as admin_module

    unguarded = [
        route.name for route in admin_module.router.routes
        if "_require_admin" not in inspect.getsource(route.endpoint)
    ]

    assert unguarded == [], f"admin routes missing the admin gate: {unguarded}"


def test_scope_ordering_still_lets_full_through_everywhere():
    """Guard the ladder itself: 'full' must satisfy every lower requirement, or
    tightening the admin gate would lock full-scope keys out of normal work."""
    for required in ("read", "vuln-mapper", "full"):
        require_scope({"api_key_scope": "full"}, required)  # must not raise
