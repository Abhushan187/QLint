"""Unit tests for the admin role gate and dashboard helpers."""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from auth import get_admin_user
from routers.admin_router import _iso, _worst


@pytest.mark.asyncio
async def test_get_admin_user_allows_admins():
    admin = {"_id": "1", "email": "a@b.dev", "role": "admin"}
    assert await get_admin_user(admin) is admin


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["user", "", "Admin", "superuser"])
async def test_get_admin_user_rejects_non_admins(role):
    with pytest.raises(HTTPException) as exc:
        await get_admin_user({"_id": "1", "email": "a@b.dev", "role": role})
    assert exc.value.status_code == 403
    assert exc.value.detail == "Admin access required"


@pytest.mark.asyncio
async def test_get_admin_user_treats_a_missing_role_as_plain_user():
    # Accounts created before F11 have no role field at all.
    with pytest.raises(HTTPException) as exc:
        await get_admin_user({"_id": "1", "email": "legacy@b.dev"})
    assert exc.value.status_code == 403


def test_worst_picks_the_most_serious_severity():
    assert _worst(["warning", "critical", "safe"]) == "critical"
    assert _worst(["safe", "warning"]) == "warning"
    assert _worst(["safe"]) == "safe"


def test_worst_falls_back_to_info_for_empty_or_unknown_input():
    assert _worst([]) == "info"
    assert _worst(["bogus", None]) == "info"


def test_iso_tags_naive_timestamps_as_utc():
    assert _iso(datetime(2026, 7, 19, 22, 32)) == "2026-07-19T22:32:00+00:00"
    aware = datetime(2026, 7, 19, 22, 32, tzinfo=timezone.utc)
    assert _iso(aware) == "2026-07-19T22:32:00+00:00"
    assert _iso(None) is None
