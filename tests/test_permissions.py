import sqlite3
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def lab(tmp_path):
    db_path = tmp_path / "case.sqlite"
    application = create_app("P01_fixed", str(db_path))

    with TestClient(application) as client:
        yield client, db_path


def auth(identity: str) -> dict[str, str]:
    return {"Authorization": f"Bearer lab-token-{identity}"}


def ticket_status(db_path, ticket_id: int) -> str:
    with closing(sqlite3.connect(db_path)) as conn:
        row = conn.execute(
            "SELECT status FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        assert row is not None
        return row[0]


def test_owner_can_read_ticket(lab):
    client, _ = lab
    response = client.get("/tickets/101", headers=auth("a"))

    assert response.status_code == 200
    assert response.json()["owner_id"] == "A"


def test_outsider_cannot_read_private_ticket(lab):
    client, _ = lab
    response = client.get("/tickets/201", headers=auth("a"))

    assert response.status_code == 403


def test_admin_can_read_ticket(lab):
    client, _ = lab
    response = client.get("/tickets/201", headers=auth("m"))

    assert response.status_code == 200


def test_shared_user_can_read_ticket_but_not_private_comments(lab):
    client, _ = lab

    ticket = client.get("/tickets/301", headers=auth("a"))
    comments = client.get("/tickets/301/comments", headers=auth("a"))

    assert ticket.status_code == 200
    assert ticket.json()["body"] == "b-shared-301"
    assert comments.status_code == 403


def test_owner_can_read_private_comments(lab):
    client, _ = lab
    response = client.get("/tickets/301/comments", headers=auth("b"))

    assert response.status_code == 200
    assert response.json()[0]["body"] == "comment-private-301"


def test_admin_can_read_private_comments(lab):
    client, _ = lab
    response = client.get("/tickets/201/comments", headers=auth("m"))

    assert response.status_code == 200
    assert response.json()[0]["body"] == "comment-private-201"


def test_missing_ticket_returns_404(lab):
    client, _ = lab

    assert client.get("/tickets/901", headers=auth("b")).status_code == 404
    assert client.get(
        "/tickets/901/comments", headers=auth("b")
    ).status_code == 404
    assert client.post(
        "/tickets/901/close", headers=auth("b")
    ).status_code == 404


def test_outsider_cannot_close_or_change_database(lab):
    client, db_path = lab

    assert ticket_status(db_path, 201) == "open"

    response = client.post("/tickets/201/close", headers=auth("a"))

    assert response.status_code == 403
    assert ticket_status(db_path, 201) == "open"


def test_shared_user_cannot_close_ticket(lab):
    client, db_path = lab

    response = client.post("/tickets/301/close", headers=auth("a"))

    assert response.status_code == 403
    assert ticket_status(db_path, 301) == "open"


def test_owner_closes_ticket_and_can_repeat(lab):
    client, db_path = lab

    assert ticket_status(db_path, 201) == "open"

    first = client.post("/tickets/201/close", headers=auth("b"))

    assert first.status_code == 200
    assert first.json()["status"] == "closed"
    assert ticket_status(db_path, 201) == "closed"

    second = client.post("/tickets/201/close", headers=auth("b"))

    assert second.status_code == 200
    assert ticket_status(db_path, 201) == "closed"


def test_admin_can_close_ticket(lab):
    client, db_path = lab

    response = client.post("/tickets/101/close", headers=auth("m"))

    assert response.status_code == 200
    assert ticket_status(db_path, 101) == "closed"

def test_admin_can_close_ticket3(lab):
    client, db_path = lab

    response = client.post("/tickets/301/close", headers=auth("m"))

    assert response.status_code == 200
    assert ticket_status(db_path, 301) == "closed"

def test_admin_can_close_ticket2(lab):
    client, db_path = lab

    response = client.post("/tickets/201/close", headers=auth("m"))

    assert response.status_code == 200
    assert ticket_status(db_path, 201) == "closed"