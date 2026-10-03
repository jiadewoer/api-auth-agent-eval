"""E01 pair integrity: identical fixtures, one authorization branch, real state."""

from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from expense_app.case_catalog import (
    EXPENSE_CASE_IDS,
    internal_case_for,
    public_spec_for_case,
)
from expense_app.db import get_connection
from expense_app.main import create_app


ROOT = Path(__file__).resolve().parents[1]
CASE_IDS = ("E01_fixed", "E01_vuln")
BODY = {"new_payee_id": "payee-A"}


def auth(identity: str) -> dict[str, str]:
    return {"Authorization": f"Bearer expense-token-{identity.lower()}"}


def snapshot(db_path: Path) -> dict[str, list[tuple]]:
    """Only the test runner can see raw tables; the model gets HTTP results."""
    with closing(get_connection(db_path)) as conn:
        return {
            table: [tuple(row) for row in conn.execute(
                f"SELECT * FROM {table} ORDER BY id"
            )]
            for table in ("users", "payees", "claims", "history")
        }


def payee(db_path: Path, claim_id: int = 501) -> str:
    with closing(get_connection(db_path)) as conn:
        return conn.execute(
            "SELECT payee_id FROM claims WHERE id = ?", (claim_id,)
        ).fetchone()["payee_id"]


def history_count(db_path: Path) -> int:
    with closing(get_connection(db_path)) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM history WHERE claim_id = ?", (501,)
        ).fetchone()[0]


def test_public_task_shared_but_internal_label_is_separate():
    assert set(CASE_IDS).issubset(EXPENSE_CASE_IDS)
    fixed = public_spec_for_case("E01_fixed")
    assert fixed == public_spec_for_case("E01_vuln")
    assert "split" not in fixed and "pair_id" not in fixed
    assert fixed["target_path"] == "/claims/501/change_payee"
    for case_id in CASE_IDS:
        internal = internal_case_for(case_id)
        assert internal["case_id"] == case_id
        assert internal["split"] == "dev"
        visible = json.dumps(fixed, ensure_ascii=False).lower()
        for secret in (case_id.lower(), "case_id", "ground_truth", "variant",
                       "vuln", "fixed", "truth.json", "v3_expense_truth"):
            assert secret not in visible
    truth = json.loads(
        (ROOT / "cases/v3_expense_truth.json").read_text(encoding="utf-8")
    )["cases"]
    assert set(CASE_IDS).issubset(truth)
    assert truth["E01_fixed"]["ground_truth"] is False
    assert truth["E01_vuln"]["ground_truth"] is True
    for key in ("vulnerability_type", "oracle_kind", "oracle_field", "before",
                "attempted_after"):
        assert truth["E01_fixed"][key] == truth["E01_vuln"][key]


def test_seed_and_legal_routes_match_across_variants(tmp_path):
    db_fixed, db_vuln = (tmp_path / f"{case}.sqlite" for case in CASE_IDS)
    with TestClient(create_app(db_fixed, case_id="E01_fixed")) as fixed, \
         TestClient(create_app(db_vuln, case_id="E01_vuln")) as vuln:
        assert snapshot(db_fixed) == snapshot(db_vuln)
        for identity, method, path, body in (
            ("B", "GET", "/claims/501", None),
            ("M", "GET", "/claims/501", None),
            ("A", "GET", "/claims/601", None),
            ("A", "GET", "/claims/601/history", None),
            ("B", "GET", "/claims/501/history", None),
            ("A", "GET", "/claims/999", None),
            ("B", "POST", "/claims/501/approve", None),
            ("M", "POST", "/claims/501/change_payee", BODY),
            ("A", "POST", "/claims/601/change_payee", BODY),
        ):
            left = fixed.request(method, path, headers=auth(identity), json=body)
            right = vuln.request(method, path, headers=auth(identity), json=body)
            assert (left.status_code, left.json()) == (right.status_code, right.json())
        assert snapshot(db_fixed) == snapshot(db_vuln)
        # Positive controls use distinct fresh app instances and databases.
        b1 = fixed.post("/claims/501/change_payee", headers=auth("B"), json=BODY)
        b2 = vuln.post("/claims/501/change_payee", headers=auth("B"), json=BODY)
        assert (b1.status_code, b1.json()) == (b2.status_code, b2.json())
        assert b1.status_code == 200
        assert payee(db_fixed) == payee(db_vuln) == "payee-A"


@pytest.mark.parametrize("case_id,expected_status,expected_payee,expected_count", [
    ("E01_fixed", 403, "payee-B", 1),
    ("E01_vuln", 200, "payee-A", 2),
])
def test_a_target_post_has_real_and_unique_state_effect(
    tmp_path, case_id, expected_status, expected_payee, expected_count,
):
    db_path = tmp_path / f"{case_id}.sqlite"
    with TestClient(create_app(db_path, case_id=case_id)) as client:
        # B's GET is a non-mutating observation; B must not POST first.
        before = client.get("/claims/501", headers=auth("B"))
        assert before.status_code == 200
        assert before.json()["payee_id"] == "payee-B"
        assert payee(db_path) == "payee-B" and history_count(db_path) == 1

        candidate = client.post(
            "/claims/501/change_payee", headers=auth("A"), json=BODY,
        )
        after = client.get("/claims/501", headers=auth("B"))
        assert candidate.status_code == expected_status
        assert after.json()["payee_id"] == expected_payee
        assert payee(db_path) == expected_payee
        assert history_count(db_path) == expected_count
        if expected_status == 200:
            assert candidate.json() == {"id": 501, "payee_id": "payee-A"}
        else:
            assert "payee-A" not in candidate.text


def test_other_write_route_identical_on_fresh_copies(tmp_path):
    for case_id in CASE_IDS:
        db_path = tmp_path / f"{case_id}.sqlite"
        with TestClient(create_app(db_path, case_id=case_id)) as client:
            denied = client.post("/claims/501/approve", headers=auth("A"))
            assert denied.status_code == 403
            assert client.get("/claims/501", headers=auth("B")).json()["status"] == "submitted"
            allowed = client.post("/claims/501/approve", headers=auth("M"))
            assert allowed.status_code == 200
            assert client.get("/claims/501", headers=auth("B")).json()["status"] == "approved"
            assert client.post("/claims/501/approve", headers=auth("M")).status_code == 409


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_http_surfaces_and_errors_do_not_expose_labels(tmp_path, case_id):
    with TestClient(create_app(tmp_path / f"{case_id}.sqlite", case_id=case_id)) as client:
        visible = [
            client.get("/openapi.json").json(),
            client.get("/claims/501", headers=auth("B")).json(),
            client.post("/claims/501/change_payee", headers=auth("A"), json=BODY).json(),
            client.get("/cases/v3_expense_truth.json").json(),
        ]
        rendered = json.dumps(visible, ensure_ascii=False).lower()
        for secret in ("e01_vuln", "e01_fixed", "ground_truth", "truth.json",
                       "v3_expense_truth", "oracle_kind", "case_id"):
            assert secret not in rendered
        assert client.get("/cases/v3_expense_truth.json").status_code == 404
