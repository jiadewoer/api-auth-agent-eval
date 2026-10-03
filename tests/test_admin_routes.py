"""Stage 2: each test gets a fresh application and a separate SQLite database."""

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
    return {"Authorization": f"Bearer lab-token-{identity.lower()}"}


def ticket_field(db_path, ticket_id: int, field: str):
    assert field in {"owner_id", "status"}
    with closing(sqlite3.connect(db_path)) as conn:
        row = conn.execute(
            f"SELECT {field} FROM tickets WHERE id = ?", (ticket_id,)
        ).fetchone()
        assert row is not None
        return row[0]


def audit_actions(db_path) -> list[str]:
    with closing(sqlite3.connect(db_path)) as conn:
        return [
            row[0]
            for row in conn.execute("SELECT action FROM audit ORDER BY id").fetchall()
        ]


# Existing three routes: allow + deny pairs. These also check integration.
def test_ticket_owner_allowed_and_outsider_denied(lab):
    client, _ = lab
    assert client.get("/tickets/201", headers=auth("B")).status_code == 200
    assert client.get("/tickets/201", headers=auth("A")).status_code == 403


def test_comment_owner_allowed_but_shared_reader_denied(lab):
    client, _ = lab
    assert client.get("/tickets/301", headers=auth("A")).status_code == 200
    allowed = client.get("/tickets/301/comments", headers=auth("B"))
    denied = client.get("/tickets/301/comments", headers=auth("A"))
    assert allowed.status_code == 200
    assert allowed.json()[0]["body"] == "comment-private-301"
    assert denied.status_code == 403
    assert "comment-private-301" not in denied.text


def test_close_owner_changes_state_but_outsider_cannot(lab):
    client, db_path = lab
    assert ticket_field(db_path, 201, "status") == "open"
    denied = client.post("/tickets/201/close", headers=auth("A"))
    assert denied.status_code == 403
    assert ticket_field(db_path, 201, "status") == "open"
    assert audit_actions(db_path) == ["fixture-created"]

    allowed = client.post("/tickets/201/close", headers=auth("B"))
    assert allowed.status_code == 200
    assert ticket_field(db_path, 201, "status") == "closed"
    assert audit_actions(db_path) == ["fixture-created", "ticket-closed"]

    again = client.post("/tickets/201/close", headers=auth("B"))
    assert again.status_code == 200
    assert audit_actions(db_path) == ["fixture-created", "ticket-closed"]


def test_reassign_admin_changes_owner_and_nonadmin_does_not(lab):
    client, db_path = lab
    assert ticket_field(db_path, 201, "owner_id") == "B"

    denied = client.post(
        "/tickets/201/reassign",
        headers=auth("A"),
        json={"new_owner_id": "A"},
    )
    assert denied.status_code == 403
    assert ticket_field(db_path, 201, "owner_id") == "B"
    assert audit_actions(db_path) == ["fixture-created"]

    allowed = client.post(
        "/tickets/201/reassign",
        headers=auth("M"),
        json={"new_owner_id": "A"},
    )
    assert allowed.status_code == 200
    assert allowed.json() == {"id": 201, "owner_id": "A"}
    assert ticket_field(db_path, 201, "owner_id") == "A"
    assert audit_actions(db_path) == ["fixture-created", "ticket-reassigned:B->A"]
    assert client.get("/tickets/201", headers=auth("A")).status_code == 200
    assert client.get("/tickets/201", headers=auth("B")).status_code == 403


def test_reassign_invalid_target_rejected_without_mutation(lab):
    client, db_path = lab
    response = client.post(
        "/tickets/201/reassign",
        headers=auth("M"),
        json={"new_owner_id": "Z"},
    )
    assert response.status_code == 400
    assert ticket_field(db_path, 201, "owner_id") == "B"
    assert audit_actions(db_path) == ["fixture-created"]


def test_reassign_same_owner_no_extra_audit_event(lab):
    client, db_path = lab
    response = client.post(
        "/tickets/201/reassign", headers=auth("M"), json={"new_owner_id": "B"}
    )
    assert response.status_code == 200
    assert ticket_field(db_path, 201, "owner_id") == "B"
    assert audit_actions(db_path) == ["fixture-created"]


def test_export_admin_allowed_nonadmin_denied_without_data(lab):
    client, _ = lab
    denied = client.get("/admin/export", headers=auth("A"))
    assert denied.status_code == 403
    assert "b-private-201" not in denied.text
    assert "comment-private-301" not in denied.text

    allowed = client.get("/admin/export", headers=auth("M"))
    assert allowed.status_code == 200
    data = allowed.json()
    assert {user["id"] for user in data["users"]} == {"A", "B", "M"}
    assert {ticket["id"] for ticket in data["tickets"]} == {101, 201, 301}
    assert {comment["id"] for comment in data["comments"]} == {1, 2}
    assert "lab-token" not in allowed.text


def test_audit_admin_allowed_nonadmin_denied_without_data(lab):
    client, _ = lab
    denied = client.get("/admin/audit", headers=auth("B"))
    assert denied.status_code == 403
    assert "fixture-created" not in denied.text

    allowed = client.get("/admin/audit", headers=auth("M"))
    assert allowed.status_code == 200
    assert allowed.json()[0]["action"] == "fixture-created"


def test_audit_records_only_successful_writes(lab):
    client, db_path = lab
    client.post("/tickets/201/close", headers=auth("A"))
    client.post("/tickets/201/close", headers=auth("B"))
    client.post("/tickets/201/close", headers=auth("B"))
    client.post(
        "/tickets/301/reassign", headers=auth("M"), json={"new_owner_id": "A"}
    )
    assert audit_actions(db_path) == [
        "fixture-created",
        "ticket-closed",
        "ticket-reassigned:B->A",
    ]
    events = client.get("/admin/audit", headers=auth("M")).json()
    assert events[1]["actor_id"] == "B"
    assert events[2]["actor_id"] == "M"
    assert events[2]["ticket_id"] == 301


def test_missing_or_invalid_identity_blocked(lab):
    client, db_path = lab
    assert client.get("/admin/export").status_code == 401
    assert client.get("/admin/audit", headers=auth("Z")).status_code == 401
    assert client.post(
        "/tickets/201/reassign", json={"new_owner_id": "A"}
    ).status_code == 401
    assert ticket_field(db_path, 201, "owner_id") == "B"
