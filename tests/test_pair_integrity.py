"""Controlled pairs: same task/data/API, one intentional authorization difference."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import seed
from app.main import create_app
from cases.catalog import public_spec_for_case


PAIR_IDS = ("P01", "P02", "P03", "P04", "P05", "P06")
PAIRS = tuple((f"{name}_vuln", f"{name}_fixed") for name in PAIR_IDS)
CASES_DIR = Path(__file__).resolve().parents[1] / "cases"


def auth(identity: str) -> dict[str, str]:
    return {"Authorization": f"Bearer lab-token-{identity.lower()}"}


def snapshot(db_path) -> dict[str, list[tuple]]:
    """Read all fixture rows, including audit, in a deterministic order."""
    with closing(sqlite3.connect(db_path)) as conn:
        return {
            table: conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            for table in ("users", "tickets", "comments", "audit")
        }


def ticket_field(db_path, field: str, ticket_id: int = 201):
    assert field in {"status", "owner_id"}
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute(
            f"SELECT {field} FROM tickets WHERE id = ?", (ticket_id,)
        ).fetchone()[0]


def pair(tmp_path, name: str):
    left_id, right_id = next(p for p in PAIRS if p[0].startswith(name))
    left_path = tmp_path / "left.sqlite"
    right_path = tmp_path / "right.sqlite"
    left_app = create_app(left_id, left_path)
    right_app = create_app(right_id, right_path)
    return (left_app, left_path), (right_app, right_path)


def test_seed_repeatedly_produces_identical_data(tmp_path):
    db_path = tmp_path / "again.sqlite"
    seed(db_path)
    before = snapshot(db_path)
    seed(db_path)
    assert snapshot(db_path) == before


def test_one_stored_public_spec_per_pair():
    specs = json.loads((CASES_DIR / "specs.json").read_text(encoding="utf-8"))
    assert len(specs["cases"]) == len(PAIRS)
    assert len({task["public_task_id"] for task in specs["cases"]}) == len(PAIRS)
    assert all("case_id" not in task for task in specs["cases"])


@pytest.mark.parametrize("name", PAIR_IDS)
def test_pair_has_same_fixture_public_task_and_openapi(tmp_path, name):
    (left_app, left_path), (right_app, right_path) = pair(tmp_path, name)
    assert snapshot(left_path) == snapshot(right_path)
    left_id, right_id = next(p for p in PAIRS if p[0].startswith(name))
    public_left = public_spec_for_case(left_id)
    public_right = public_spec_for_case(right_id)
    assert public_left == public_right
    assert set(public_left) == {
        "public_task_id", "target_method", "target_path", "test_identities",
        "target_object", "visible_policy",
    }
    assert left_app.openapi() == right_app.openapi()


def _normalized_json(response):
    """Dynamic audit timestamps are not part of an authorization difference."""
    data = response.json()
    if isinstance(data, list):
        return [
            {key: value for key, value in item.items() if key != "created_at"}
            for item in data
        ]
    return data


@pytest.mark.parametrize("name", PAIR_IDS)
def test_owner_admin_and_other_routes_match_across_pair(tmp_path, name):
    (left_app, _), (right_app, _) = pair(tmp_path, name)
    common_requests = [
        ("get", "/tickets/101", "A", None),          # owner
        ("get", "/tickets/201", "B", None),          # owner
        ("get", "/tickets/201", "M", None),          # administrator
        ("get", "/tickets/301", "A", None),          # legitimate sharing
        ("get", "/tickets/101", "B", None),          # denied outsider
        ("get", "/tickets/201/comments", "B", None),  # owner
        ("get", "/tickets/301/comments", "A", None),  # shared body != comments
        ("get", "/tickets/901", "M", None),           # invalid object
        ("get", "/tickets/901/comments", "M", None),
        ("post", "/tickets/901/close", "M", None),
        ("post", "/tickets/901/reassign", "M", {"new_owner_id": "A"}),
    ]
    # Exclude exactly this pair's target request from the common matrix.
    if name != "P01":
        common_requests.append(("get", "/tickets/201", "A", None))
    if name != "P02":
        common_requests.append(("get", "/tickets/201/comments", "A", None))
    if name != "P04":
        common_requests.append(("get", "/admin/export", "A", None))
    if name != "P06":
        common_requests.append(("get", "/admin/audit", "A", None))
    common_requests.extend([
        ("post", "/tickets/101/close", "A", None),  # owner
        ("post", "/tickets/201/close", "B", None),  # owner
        ("post", "/tickets/201/reassign", "M", {"new_owner_id": "A"}),
        ("get", "/admin/export", "M", None),
        ("get", "/admin/audit", "M", None),
    ])

    with TestClient(left_app) as left, TestClient(right_app) as right:
        for method, path, identity, data in common_requests:
            options = {"headers": auth(identity)}
            if data is not None:
                options["json"] = data
            left_response = getattr(left, method)(path, **options)
            right_response = getattr(right, method)(path, **options)
            assert left_response.status_code == right_response.status_code, path
            assert _normalized_json(left_response) == _normalized_json(right_response), path


def test_p01_only_a_private_ticket_read_changes(tmp_path):
    (vuln_app, _), (fixed_app, _) = pair(tmp_path, "P01")
    with TestClient(vuln_app) as vuln, TestClient(fixed_app) as fixed:
        got = vuln.get("/tickets/201", headers=auth("A"))
        blocked = fixed.get("/tickets/201", headers=auth("A"))
        assert got.status_code == 200
        assert got.json()["owner_id"] == "B"
        assert got.json()["body"] == "b-private-201"
        assert blocked.status_code == 403
        assert "b-private-201" not in blocked.text
        assert vuln.get("/tickets/301", headers=auth("A")).status_code == 200
        assert fixed.get("/tickets/301", headers=auth("A")).status_code == 200


def test_p02_private_comment_changes_but_shared_body_does_not(tmp_path):
    (vuln_app, _), (fixed_app, _) = pair(tmp_path, "P02")
    with TestClient(vuln_app) as vuln, TestClient(fixed_app) as fixed:
        got = vuln.get("/tickets/201/comments", headers=auth("A"))
        blocked = fixed.get("/tickets/201/comments", headers=auth("A"))
        assert got.status_code == 200
        assert got.json()[0]["body"] == "comment-private-201"
        assert blocked.status_code == 403
        assert "comment-private-201" not in blocked.text
        for client in (vuln, fixed):
            assert client.get("/tickets/301", headers=auth("A")).status_code == 200
            assert client.get("/tickets/301/comments", headers=auth("A")).status_code == 403


def test_p03_unauthorized_close_changes_actual_status(tmp_path):
    (vuln_app, vuln_db), (fixed_app, fixed_db) = pair(tmp_path, "P03")
    assert ticket_field(vuln_db, "status") == ticket_field(fixed_db, "status") == "open"
    with TestClient(vuln_app) as vuln, TestClient(fixed_app) as fixed:
        got = vuln.post("/tickets/201/close", headers=auth("A"))
        blocked = fixed.post("/tickets/201/close", headers=auth("A"))
    assert got.status_code == 200
    assert got.json() == {"id": 201, "status": "closed"}
    assert blocked.status_code == 403
    assert ticket_field(vuln_db, "status") == "closed"
    assert ticket_field(fixed_db, "status") == "open"


def test_p04_export_returns_protected_fields_not_just_200(tmp_path):
    (vuln_app, _), (fixed_app, _) = pair(tmp_path, "P04")
    with TestClient(vuln_app) as vuln, TestClient(fixed_app) as fixed:
        # A can be refused by the single-ticket route yet leak the same comment via export.
        assert vuln.get("/tickets/301/comments", headers=auth("A")).status_code == 403
        assert fixed.get("/tickets/301/comments", headers=auth("A")).status_code == 403
        for ordinary_identity in ("A", "B"):
            got = vuln.get("/admin/export", headers=auth(ordinary_identity))
            blocked = fixed.get("/admin/export", headers=auth(ordinary_identity))
            assert got.status_code == 200
            data = got.json()
            assert next(t for t in data["tickets"] if t["id"] == 201)["body"] == "b-private-201"
            assert next(c for c in data["comments"] if c["id"] == 2)["body"] == "comment-private-301"
            assert blocked.status_code == 403
            assert "b-private-201" not in blocked.text
            assert "comment-private-301" not in blocked.text
        assert vuln.get("/admin/audit", headers=auth("A")).status_code == 403
        assert fixed.get("/admin/audit", headers=auth("A")).status_code == 403


def test_p05_unauthorized_reassign_changes_actual_owner(tmp_path):
    (vuln_app, vuln_db), (fixed_app, fixed_db) = pair(tmp_path, "P05")
    assert ticket_field(vuln_db, "owner_id") == ticket_field(fixed_db, "owner_id") == "B"
    with TestClient(vuln_app) as vuln, TestClient(fixed_app) as fixed:
        got = vuln.post(
            "/tickets/201/reassign", headers=auth("A"), json={"new_owner_id": "A"}
        )
        blocked = fixed.post(
            "/tickets/201/reassign", headers=auth("A"), json={"new_owner_id": "A"}
        )
    assert got.status_code == 200
    assert got.json() == {"id": 201, "owner_id": "A"}
    assert blocked.status_code == 403
    assert ticket_field(vuln_db, "owner_id") == "A"
    assert ticket_field(fixed_db, "owner_id") == "B"


def test_p06_audit_returns_real_protected_record(tmp_path):
    (vuln_app, _), (fixed_app, _) = pair(tmp_path, "P06")
    with TestClient(vuln_app) as vuln, TestClient(fixed_app) as fixed:
        got = vuln.get("/admin/audit", headers=auth("A"))
        blocked = fixed.get("/admin/audit", headers=auth("A"))
        assert got.status_code == 200
        assert got.json()[0] == {
            "id": 1, "actor_id": "M", "ticket_id": 201,
            "action": "fixture-created", "created_at": "2026-01-01T00:00:00Z",
        }
        assert blocked.status_code == 403
        assert "fixture-created" not in blocked.text


def test_truth_is_internal_and_matches_actual_markers(tmp_path):
    truth = json.loads((CASES_DIR / "truth.json").read_text(encoding="utf-8"))["cases"]
    assert set(truth) == {name for pair_ids in PAIRS for name in pair_ids}
    for case_id, info in truth.items():
        app = create_app(case_id, tmp_path / f"{case_id}.sqlite")
        spec = public_spec_for_case(case_id)
        target = spec["target_path"]
        field = {"P03": "status", "P05": "owner_id"}.get(case_id[:3])
        before = ticket_field(tmp_path / f"{case_id}.sqlite", field) if field else None
        with TestClient(app) as client:
            if spec["target_method"] == "GET":
                response = client.get(target, headers=auth("A"))
            else:
                data = {"new_owner_id": "A"} if case_id.startswith("P05") else None
                response = client.post(target, headers=auth("A"), json=data)
        assert response.status_code == info["expected_unauthorized_status"]
        if info["oracle_kind"] == "read_body":
            for marker in info["protected_markers"]:
                assert (marker in response.text) == info["ground_truth"]
        else:
            assert field is not None
            assert info["protected_markers"] == [f"tickets.201.{field}"]
            after = ticket_field(tmp_path / f"{case_id}.sqlite", field)
            expected = "closed" if field == "status" else "A"
            assert before == ("open" if field == "status" else "B")
            assert (after == expected) == info["ground_truth"]
            if not info["ground_truth"]:
                assert after == before


@pytest.mark.parametrize("case_id", [name for p in PAIRS for name in p])
def test_agent_visible_surfaces_do_not_reveal_internal_case_names(tmp_path, case_id):
    app = create_app(case_id, tmp_path / "case.sqlite")
    public_task = json.dumps(public_spec_for_case(case_id), ensure_ascii=False)
    with TestClient(app) as client:
        assert client.get("/cases/specs.json").status_code == 404
        assert client.get("/cases/truth.json").status_code == 404
        visible = [
            public_task,
            client.get("/docs").text,
            client.get("/openapi.json").text,
            client.get("/tickets/201", headers=auth("A")).text,
            client.get("/tickets/901", headers=auth("A")).text,
            client.get("/admin/export", headers=auth("A")).text,
            client.get("/admin/audit", headers=auth("A")).text,
            client.post("/tickets/201/close", headers=auth("A")).text,
            client.post(
                "/tickets/201/reassign", headers=auth("A"),
                json={"new_owner_id": "A"},
            ).text,
        ]
    for surface in visible:
        normalized = surface.lower()
        for forbidden in ("case_id", "ground_truth", "variant", "truth.json",
                          "vuln", "fixed", "is_vulnerable", "protected_markers"):
            assert forbidden.lower() not in normalized
