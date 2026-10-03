"""验证授权规则与可重复重置；每个测试用自己的临时数据库。"""

from fastapi.testclient import TestClient

from app.db import get_connection, seed
from app.main import create_app


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

def test_a_can_read_own_ticket(tmp_path):
    app = create_app("P01_fixed", tmp_path / "a.sqlite")

    with TestClient(app) as client:
        response = client.get(
            "/tickets/101",
            headers={"Authorization": "Bearer lab-token-a"},
        )

    assert response.status_code == 200
    assert response.json()["body"] == "a-private-101"
def test_owner_can_read_private_ticket(tmp_path):
    with TestClient(create_app("P01_fixed", tmp_path / "owner.sqlite")) as client:
        response = client.get("/tickets/201", headers=_headers("lab-token-b"))
    assert response.status_code == 200
    assert response.json()["body"] == "b-private-201"
    assert response.json()["owner_id"] == "B"


def test_other_user_cannot_read_private_ticket(tmp_path):
    with TestClient(create_app("P01_fixed", tmp_path / "private.sqlite")) as client:
        response = client.get("/tickets/201", headers=_headers("lab-token-a"))
    assert response.status_code == 403
    assert "b-private-201" not in response.text


def test_shared_ticket_and_admin_access(tmp_path):
    with TestClient(create_app("P01_fixed", tmp_path / "shared.sqlite")) as client:
        shared = client.get("/tickets/301", headers=_headers("lab-token-a"))
        admin = client.get("/tickets/201", headers=_headers("lab-token-m"))
    assert shared.status_code == 200
    assert shared.json()["body"] == "b-shared-301"
    assert admin.status_code == 200
    assert admin.json()["body"] == "b-private-201"


def test_missing_and_bad_token_are_401(tmp_path):
    with TestClient(create_app("P01_fixed", tmp_path / "auth.sqlite")) as client:
        missing = client.get("/tickets/201")
        bad = client.get("/tickets/201", headers=_headers("wrong-token"))
    assert missing.status_code == 401
    assert bad.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"


def test_unknown_ticket_is_404(tmp_path):
    with TestClient(create_app("P01_fixed", tmp_path / "unknown.sqlite")) as client:
        response = client.get("/tickets/999", headers=_headers("lab-token-b"))
    assert response.status_code == 404


def test_seed_restores_initial_state(tmp_path):
    path = tmp_path / "reset.sqlite"
    seed(path)
    conn = get_connection(path)
    try:
        with conn:
            conn.execute("UPDATE tickets SET status = 'closed' WHERE id = 201")
    finally:
        conn.close()
    seed(path)
    conn = get_connection(path)
    try:
        status = conn.execute("SELECT status FROM tickets WHERE id = 201").fetchone()["status"]
        count = conn.execute("SELECT COUNT(*) AS n FROM tickets").fetchone()["n"]
    finally:
        conn.close()
    assert status == "open"
    assert count == 3
