from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app


def _admin_headers() -> dict[str, str]:
    return {"X-ADMIN-KEY": "admin-test-key"}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))

    with TestClient(app) as test_client:
        yield test_client


def _create_store(
    client: TestClient,
    *,
    display_name: str,
    is_active: bool = True,
    address: str | None = None,
) -> dict:
    payload: dict[str, object] = {
        "display_name": display_name,
        "is_active": is_active,
    }
    if address is not None:
        payload["address"] = address

    response = client.post("/admin/v1/stores", json=payload, headers=_admin_headers())
    assert response.status_code == 201
    return response.json()


def test_create_store_returns_201_with_server_generated_store_id(client: TestClient):
    response = client.post(
        "/admin/v1/stores",
        json={
            "display_name": "  Downtown Flagship  ",
            "address": "  Main Street 42  ",
        },
        headers=_admin_headers(),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["store_id"].startswith("st_")
    assert body["display_name"] == "Downtown Flagship"
    assert body["address"] == "Main Street 42"
    assert body["is_active"] is True
    assert body["created_at"]
    assert body["updated_at"]


def test_list_stores_defaults_to_active_only(client: TestClient):
    active_store = _create_store(client, display_name="Active Store", is_active=True)
    inactive_store = _create_store(client, display_name="Inactive Store", is_active=False)

    default_list = client.get("/admin/v1/stores", headers=_admin_headers())
    assert default_list.status_code == 200
    default_ids = {item["store_id"] for item in default_list.json()["items"]}
    assert active_store["store_id"] in default_ids
    assert inactive_store["store_id"] not in default_ids

    all_list = client.get(
        "/admin/v1/stores?include_inactive=true",
        headers=_admin_headers(),
    )
    assert all_list.status_code == 200
    all_ids = {item["store_id"] for item in all_list.json()["items"]}
    assert active_store["store_id"] in all_ids
    assert inactive_store["store_id"] in all_ids


def test_deactivate_store_via_patch_is_returned_with_include_inactive(client: TestClient):
    store = _create_store(client, display_name="Patch Store", is_active=True)
    store_id = store["store_id"]

    response = client.patch(
        f"/admin/v1/stores/{store_id}",
        json={"is_active": False},
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is False

    list_response = client.get(
        "/admin/v1/stores?include_inactive=true",
        headers=_admin_headers(),
    )
    assert list_response.status_code == 200
    stores_by_id = {item["store_id"]: item for item in list_response.json()["items"]}
    assert stores_by_id[store_id]["is_active"] is False


def test_enroll_tokens_enforces_store_existence_and_activity(client: TestClient):
    unknown_store_response = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": "missing-store",
            "expires_in_sec": 600,
            "max_uses": 1,
        },
        headers=_admin_headers(),
    )
    assert unknown_store_response.status_code == 400
    assert unknown_store_response.json() == {"detail": "unknown_store"}

    inactive_store = _create_store(client, display_name="Inactive Enroll", is_active=False)
    inactive_store_response = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": inactive_store["store_id"],
            "expires_in_sec": 600,
            "max_uses": 1,
        },
        headers=_admin_headers(),
    )
    assert inactive_store_response.status_code == 400
    assert inactive_store_response.json() == {"detail": "store_inactive"}

    active_store = _create_store(client, display_name="Active Enroll", is_active=True)
    active_store_response = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": active_store["store_id"],
            "expires_in_sec": 600,
            "max_uses": 1,
        },
        headers=_admin_headers(),
    )
    assert active_store_response.status_code == 200
    body = active_store_response.json()
    assert body["enroll_token"]
    assert body["token_id"]
    assert body["expires_at"]
    assert body["max_uses"] == 1


def test_read_store_returns_404_when_not_found(client: TestClient):
    response = client.get("/admin/v1/stores/st_does_not_exist", headers=_admin_headers())
    assert response.status_code == 404
