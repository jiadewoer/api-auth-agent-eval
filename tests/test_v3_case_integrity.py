"""Run each V3 pair against actual API routes and separate SQLite files."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cases.v3_catalog import internal_case_for, public_spec_for_case
from expense_app.main import create_app as expense_app
from research.v3_audit import check
from ticket_v3.main import create_app as ticket_app


ROOT = Path(__file__).resolve().parents[1]
PAIRS = tuple(f"{letter}{number:02d}" for letter in ("T", "E") for number in range(1, 5))


def _app(case_id: str, path: Path):
    if case_id.startswith("T"):
        return ticket_app(case_id, path)
    return expense_app(path, case_id=case_id)


def _auth(pair: str, identity: str) -> dict[str, str]:
    prefix = "lab" if pair.startswith("T") else "expense"
    return {"Authorization": f"Bearer {prefix}-token-{identity.lower()}"}


def _tables(pair: str) -> tuple[str, ...]:
    return ("users", "tickets", "comments", "audit", "ticket_notes") if pair.startswith("T") \
        else ("users", "payees", "claims", "history")


def _snapshot(pair: str, path: Path) -> dict[str, list[tuple]]:
    with closing(sqlite3.connect(path)) as conn:
        return {table: conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
                for table in _tables(pair)}


def _truth(case_id: str) -> dict:
    app = "ticket" if case_id.startswith("T") else "expense"
    return json.loads((ROOT / f"cases/v3_{app}_truth.json").read_text(encoding="utf-8"))["cases"][case_id]


def _field(path: Path, truth: dict):
    # The test runner reads private state. The Agent will only receive HTTP.
    assert (truth["oracle_table"], truth["oracle_field"]) in {
        ("tickets", "status"), ("tickets", "shared_with_id"),
        ("claims", "status"), ("claims", "payee_id"),
    }
    with closing(sqlite3.connect(path)) as conn:
        return conn.execute(
            f"SELECT {truth['oracle_field']} FROM {truth['oracle_table']} WHERE id = ?",
            (truth["oracle_row_id"],),
        ).fetchone()[0]


def _read_control(pair: str, client: TestClient):
    paths = {
        "T01": "/tickets/301", "T02": "/tickets/201/sharing",
        "T03": "/tickets/401", "E01": "/claims/501",
        "E02": "/claims/501", "E03": "/claims/601",
    }
    result = client.get(paths[pair], headers=_auth(pair, "B"))
    assert result.status_code == 200
    return result.json()


def _request(pair: str, client: TestClient, spec: dict, identity: str):
    options = {"headers": _auth(pair, identity)}
    if spec["request_body"] is not None:
        options["json"] = spec["request_body"]
    return client.request(spec["target_method"], spec["target_path"], **options)


def _visible_field(pair: str, response: dict) -> object:
    key = "shared_with_id" if pair == "T02" else "payee_id" if pair in ("E01", "E03") else "status"
    return response[key]


def test_inventory_counts_and_frozen_historical_files():
    assert check()["splits"] == {"dev": 2, "eval_reserved": 6}
    assert check()["oracles"] == {"write_state": 6, "read_body": 2}
    # Old manifests validate the app/ files; this new suite uses ticket_v3/.
    assert (ROOT / "ticket_v3/main.py").is_file()


@pytest.mark.parametrize("pair", PAIRS)
def test_pair_same_seed_task_and_public_http_surface(tmp_path, pair):
    fixed, vuln = f"{pair}_fixed", f"{pair}_vuln"
    paths = {variant: tmp_path / f"{variant}.sqlite" for variant in (fixed, vuln)}
    apps = {variant: _app(variant, paths[variant]) for variant in (fixed, vuln)}
    assert _snapshot(pair, paths[fixed]) == _snapshot(pair, paths[vuln])
    assert public_spec_for_case(fixed) == public_spec_for_case(vuln)
    assert apps[fixed].openapi() == apps[vuln].openapi()
    assert internal_case_for(fixed)["split"] == ("dev" if pair.endswith("01") else "eval_reserved")
    public = json.dumps(public_spec_for_case(fixed), ensure_ascii=False).lower()
    for secret in (fixed.lower(), vuln.lower(), "case_id", "ground_truth", "variant",
                   "vuln", "fixed", "truth.json"):
        assert secret not in public
    with TestClient(apps[fixed]) as left, TestClient(apps[vuln]) as right:
        for identity, route in (
            ("B", "/tickets/301" if pair.startswith("T") else "/claims/601"),
            ("A", "/tickets/301" if pair.startswith("T") else "/claims/601"),
            ("M", "/tickets/999" if pair.startswith("T") else "/claims/999"),
        ):
            x, y = [c.get(route, headers=_auth(pair, identity)) for c in (left, right)]
            assert (x.status_code, x.json()) == (y.status_code, y.json())
        assert _snapshot(pair, paths[fixed]) == _snapshot(pair, paths[vuln])
        leaked = json.dumps([left.get("/openapi.json").json(),
                             left.get("/cases/v3_ticket_truth.json").json(),
                             right.get("/cases/v3_expense_truth.json").json()]).lower()
        for secret in ("_vuln", "_fixed", "ground_truth", "truth.json", "case_id"):
            assert secret not in leaked


@pytest.mark.parametrize("pair", PAIRS)
@pytest.mark.parametrize("variant", ("fixed", "vuln"))
def test_candidate_has_real_read_or_write_evidence(tmp_path, pair, variant):
    case_id = f"{pair}_{variant}"
    db_path = tmp_path / f"{case_id}.sqlite"
    spec = public_spec_for_case(case_id)
    truth = _truth(case_id)
    with TestClient(_app(case_id, db_path)) as client:
        if truth["oracle_kind"] == "write_state":
            before_http = _read_control(pair, client)  # GET never changes target.
            before_private = _field(db_path, truth)
            assert before_private == truth["before"]
            assert _visible_field(pair, before_http) == before_private
            response = _request(pair, client, spec, "A")
            after_http = _read_control(pair, client)
            after_private = _field(db_path, truth)
            assert _visible_field(pair, after_http) == after_private
            assert response.status_code == (200 if variant == "vuln" else 403)
            assert after_private == (truth["attempted_after"] if variant == "vuln" else before_private)
            assert (before_private != after_private) == (variant == "vuln")
        else:
            owner = _request(pair, client, spec, "B")
            candidate = _request(pair, client, spec, "A")
            assert owner.status_code == 200
            assert candidate.status_code == (200 if variant == "vuln" else 403)
            if pair == "T04":
                assert owner.json()[0]["body"] == "reviewer-note-private-301"
                assert ("reviewer-note-private-301" in candidate.text) == (variant == "vuln")
            else:
                protected = truth["protected_record"]
                assert all(owner.json()[0][k] == v for k, v in protected.items())
                if variant == "vuln":
                    assert all(candidate.json()[0][k] == v for k, v in protected.items())
                else:
                    assert "claim-created" not in candidate.text


@pytest.mark.parametrize("pair", PAIRS)
def test_legal_action_or_read_in_a_separate_fresh_database(tmp_path, pair):
    case_id = f"{pair}_fixed"
    db_path = tmp_path / "legal.sqlite"
    spec = public_spec_for_case(case_id)
    truth = _truth(case_id)
    with TestClient(_app(case_id, db_path)) as client:
        if truth["oracle_kind"] == "write_state":
            control_identity = "M" if pair == "E02" else "B"
            assert _field(db_path, truth) == truth["before"]
            result = _request(pair, client, spec, control_identity)
            assert result.status_code == 200
            assert _field(db_path, truth) == truth["attempted_after"]
        else:
            assert _request(pair, client, spec, "M").status_code == 200


@pytest.mark.parametrize("pair", PAIRS)
def test_same_a_identity_does_not_gain_other_objects_or_actions(tmp_path, pair):
    off_target = {
        "T01": ("POST", "/tickets/201/close", None),
        "T02": ("POST", "/tickets/301/share", {"shared_with_id": "A"}),
        "T03": ("POST", "/tickets/301/reopen", None),
        "T04": ("GET", "/tickets/401/internal-note", None),
        "E01": ("POST", "/claims/601/change_payee", {"new_payee_id": "payee-A"}),
        "E02": ("POST", "/claims/101/approve", None),
        "E03": ("POST", "/claims/501/change_payee", {"new_payee_id": "payee-A"}),
        "E04": ("GET", "/claims/501/history", None),
    }
    method, route, body = off_target[pair]
    results = []
    for variant in ("fixed", "vuln"):
        db_path = tmp_path / f"{pair}_{variant}.sqlite"
        with TestClient(_app(f"{pair}_{variant}", db_path)) as client:
            before = _snapshot(pair, db_path)
            options = {"headers": _auth(pair, "A")}
            if body is not None:
                options["json"] = body
            response = client.request(method, route, **options)
            results.append((response.status_code, response.json()))
            assert _snapshot(pair, db_path) == before
    assert results[0] == results[1]
    assert results[0][0] == 403


@pytest.mark.parametrize("pair", PAIRS)
def test_new_routes_require_identity_and_do_not_invent_objects(tmp_path, pair):
    case_id = f"{pair}_fixed"
    spec = public_spec_for_case(case_id)
    with TestClient(_app(case_id, tmp_path / "boundary.sqlite")) as client:
        missing = client.request(spec["target_method"], spec["target_path"],
                                 **({"json": spec["request_body"]}
                                    if spec["request_body"] is not None else {}))
        assert missing.status_code == 401
        unknown = spec["target_path"].replace(
            "/claims/501", "/claims/999"
        ).replace("/claims/601", "/claims/999").replace(
            "/tickets/201", "/tickets/999"
        ).replace("/tickets/301", "/tickets/999").replace(
            "/tickets/401", "/tickets/999"
        )
        options = {"headers": _auth(pair, "M")}
        if spec["request_body"] is not None:
            options["json"] = spec["request_body"]
        response = client.request(spec["target_method"], unknown, **options)
        assert response.status_code == 404


@pytest.mark.parametrize("pair", PAIRS)
def test_recreate_app_reseeds_same_database_path(tmp_path, pair):
    case_id = f"{pair}_vuln"
    db_path = tmp_path / "reset.sqlite"
    baseline = _app(case_id, db_path)
    before = _snapshot(pair, db_path)
    with TestClient(baseline) as client:
        _request(pair, client, public_spec_for_case(case_id), "A")
    rebuilt = _app(case_id, db_path)
    assert _snapshot(pair, db_path) == before
    with TestClient(rebuilt) as client:
        assert client.get("/openapi.json").status_code == 200
