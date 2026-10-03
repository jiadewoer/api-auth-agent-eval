"""Authorization and state checks for the independent expense application."""

from __future__ import annotations

from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from expense_app.db import get_connection
from expense_app.main import create_app


@pytest.fixture
def expense(tmp_path):
    db_path = tmp_path / "expense.sqlite"
    with TestClient(create_app(db_path)) as client:
        yield client, db_path


def auth(identity: str) -> dict[str, str]:
    return {"Authorization": f"Bearer expense-token-{identity.lower()}"}


def claim_field(db_path, claim_id: int, field: str) -> str:
    assert field in {"payee_id", "status", "owner_id"}
    with closing(get_connection(db_path)) as conn:
        row = conn.execute(
            f"SELECT {field} FROM claims WHERE id = ?", (claim_id,)
        ).fetchone()
        assert row is not None
        return str(row[field])


def history_actions(db_path, claim_id: int) -> list[str]:
    with closing(get_connection(db_path)) as conn:
        return [row["action"] for row in conn.execute(
            "SELECT action FROM history WHERE claim_id = ? ORDER BY id", (claim_id,)
        ).fetchall()]


@pytest.mark.parametrize("identity", ["B", "M"])
def test_owner_and_finance_can_read_private_claim(expense, identity):
    client, _ = expense
    response = client.get("/claims/501", headers=auth(identity))
    assert response.status_code == 200
    assert response.json()["owner_id"] == "B"
    assert response.json()["payee_id"] == "payee-B"


def test_outsider_cannot_read_private_claim_or_payee(expense):
    client, _ = expense
    response = client.get("/claims/501", headers=auth("A"))
    assert response.status_code == 403
    assert "payee-B" not in response.text


def test_shared_reader_sees_summary_but_not_payee_or_history(expense):
    client, _ = expense
    summary = client.get("/claims/601", headers=auth("A"))
    history = client.get("/claims/601/history", headers=auth("A"))
    assert summary.status_code == 200
    assert summary.json()["owner_id"] == "B"
    assert summary.json()["payee_id"] is None
    assert "payee-B" not in summary.text
    assert history.status_code == 403
    assert "claim-created" not in history.text


@pytest.mark.parametrize("identity", ["B", "M"])
def test_owner_and_finance_can_read_history(expense, identity):
    client, _ = expense
    response = client.get("/claims/501/history", headers=auth(identity))
    assert response.status_code == 200
    assert response.json()[0]["actor_id"] == "B"
    assert response.json()[0]["action"] == "claim-created"


@pytest.mark.parametrize("identity", ["A", "B"])
def test_only_finance_can_approve_and_denial_does_not_change_db(expense, identity):
    client, db_path = expense
    before = history_actions(db_path, 501)
    response = client.post("/claims/501/approve", headers=auth(identity))
    assert response.status_code == 403
    assert claim_field(db_path, 501, "status") == "submitted"
    assert history_actions(db_path, 501) == before


def test_finance_approve_changes_db_and_history(expense):
    client, db_path = expense
    assert claim_field(db_path, 501, "status") == "submitted"
    response = client.post("/claims/501/approve", headers=auth("M"))
    assert response.status_code == 200
    assert response.json() == {"id": 501, "status": "approved"}
    assert claim_field(db_path, 501, "status") == "approved"
    assert history_actions(db_path, 501) == ["claim-created", "claim-approved"]


def test_repeated_approval_is_conflict_not_a_second_mutation(expense):
    client, db_path = expense
    assert client.post("/claims/501/approve", headers=auth("M")).status_code == 200
    again = client.post("/claims/501/approve", headers=auth("M"))
    assert again.status_code == 409
    assert claim_field(db_path, 501, "status") == "approved"
    assert history_actions(db_path, 501) == ["claim-created", "claim-approved"]


def test_owner_can_change_payee_and_history_records_real_change(expense):
    client, db_path = expense
    assert claim_field(db_path, 501, "payee_id") == "payee-B"
    response = client.post(
        "/claims/501/change_payee", headers=auth("B"),
        json={"new_payee_id": "payee-A"},
    )
    assert response.status_code == 200
    assert response.json() == {"id": 501, "payee_id": "payee-A"}
    assert claim_field(db_path, 501, "payee_id") == "payee-A"
    assert history_actions(db_path, 501) == [
        "claim-created", "payee-changed:payee-B->payee-A",
    ]


def test_a_can_change_own_claim_but_not_someone_elses(expense):
    client, db_path = expense
    response = client.post(
        "/claims/101/change_payee", headers=auth("A"),
        json={"new_payee_id": "payee-B"},
    )
    assert response.status_code == 200
    assert claim_field(db_path, 101, "payee_id") == "payee-B"
    assert claim_field(db_path, 501, "payee_id") == "payee-B"


def test_shared_reader_still_cannot_see_payee_after_owner_changes_it(expense):
    client, db_path = expense
    changed = client.post(
        "/claims/601/change_payee", headers=auth("B"),
        json={"new_payee_id": "payee-A"},
    )
    assert changed.status_code == 200
    assert claim_field(db_path, 601, "payee_id") == "payee-A"
    response = client.get("/claims/601", headers=auth("A"))
    assert response.status_code == 200
    assert response.json()["payee_id"] is None
    assert "payee-A" not in response.text
    assert client.get("/claims/601/history", headers=auth("A")).status_code == 403
    assert "payee-changed:payee-B->payee-A" in client.get(
        "/claims/601/history", headers=auth("M")
    ).text


@pytest.mark.parametrize("identity,claim_id", [
    ("A", 501),  # Stranger to B's private claim.
    ("A", 601),  # Shared summary access is not payee edit permission.
    ("M", 501),  # Finance can approve, but cannot edit a claimant's payee.
])
def test_unauthorized_payee_change_keeps_state_and_history(
    expense, identity, claim_id,
):
    client, db_path = expense
    before = history_actions(db_path, claim_id)
    response = client.post(
        f"/claims/{claim_id}/change_payee", headers=auth(identity),
        json={"new_payee_id": "payee-A"},
    )
    assert response.status_code == 403
    assert claim_field(db_path, claim_id, "payee_id") == "payee-B"
    assert history_actions(db_path, claim_id) == before


def test_same_payee_is_conflict_not_evidence_of_a_change(expense):
    client, db_path = expense
    response = client.post(
        "/claims/501/change_payee", headers=auth("B"),
        json={"new_payee_id": "payee-B"},
    )
    assert response.status_code == 409
    assert claim_field(db_path, 501, "payee_id") == "payee-B"
    assert history_actions(db_path, 501) == ["claim-created"]


def test_approved_claim_payee_cannot_change(expense):
    client, db_path = expense
    client.post("/claims/501/approve", headers=auth("M"))
    response = client.post(
        "/claims/501/change_payee", headers=auth("B"),
        json={"new_payee_id": "payee-A"},
    )
    assert response.status_code == 409
    assert claim_field(db_path, 501, "payee_id") == "payee-B"
    assert history_actions(db_path, 501) == ["claim-created", "claim-approved"]


def test_unknown_payee_rejected_without_mutation(expense):
    client, db_path = expense
    response = client.post(
        "/claims/501/change_payee", headers=auth("B"),
        json={"new_payee_id": "payee-Z"},
    )
    assert response.status_code == 400
    assert claim_field(db_path, 501, "payee_id") == "payee-B"


def test_extra_json_field_is_rejected(expense):
    client, db_path = expense
    response = client.post(
        "/claims/501/change_payee", headers=auth("B"),
        json={"new_payee_id": "payee-A", "ignore_policy": True},
    )
    assert response.status_code == 422
    assert claim_field(db_path, 501, "payee_id") == "payee-B"


def test_unknown_id_and_missing_auth_are_distinct(expense):
    client, db_path = expense
    assert client.get("/claims/999", headers=auth("M")).status_code == 404
    assert client.get("/claims/999/history", headers=auth("M")).status_code == 404
    assert client.post("/claims/999/approve", headers=auth("M")).status_code == 404
    assert client.post(
        "/claims/999/change_payee", headers=auth("B"),
        json={"new_payee_id": "payee-A"},
    ).status_code == 404
    assert client.get("/claims/501").status_code == 401
    invalid = client.get("/claims/501", headers={"Authorization": "Bearer invalid"})
    assert invalid.status_code == 401
    assert "expense-token-" not in invalid.text
    assert client.post("/claims/501/approve").status_code == 401
    assert claim_field(db_path, 501, "status") == "submitted"


def test_get_does_not_reseed_but_creating_a_new_app_does(tmp_path):
    db_path = tmp_path / "persistent.sqlite"
    with TestClient(create_app(db_path)) as client:
        assert client.post("/claims/501/approve", headers=auth("M")).status_code == 200
        assert client.get("/claims/501", headers=auth("B")).json()["status"] == "approved"
        assert claim_field(db_path, 501, "status") == "approved"

    with TestClient(create_app(db_path)) as new_client:
        assert new_client.get("/claims/501", headers=auth("B")).json()["status"] == "submitted"
        assert claim_field(db_path, 501, "status") == "submitted"


def test_two_app_instances_use_distinct_databases(tmp_path):
    first_path = tmp_path / "first.sqlite"
    second_path = tmp_path / "second.sqlite"
    with TestClient(create_app(first_path)) as first, TestClient(create_app(second_path)) as second:
        assert first.post("/claims/501/approve", headers=auth("M")).status_code == 200
        assert claim_field(first_path, 501, "status") == "approved"
        assert second.get("/claims/501", headers=auth("B")).json()["status"] == "submitted"
        assert claim_field(second_path, 501, "status") == "submitted"
