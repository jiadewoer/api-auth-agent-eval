"""The four new development pairs exercise actual HTTP authorization and state."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from v4_lab.apps import create_app
from v4_lab.catalog import DEV_PAIRS, public_spec_for_case, truth_for_case


def _auth(pair: str, identity: str) -> dict:
    prefix = "lab" if pair.startswith("T") else "expense"
    return {"Authorization": f"Bearer {prefix}-token-{identity.lower()}"}


def _value(path: Path, truth: dict):
    with sqlite3.connect(path) as conn:
        return conn.execute(
            f"SELECT {truth['oracle_field']} FROM {truth['oracle_table']} WHERE id = ?",
            (truth["oracle_row_id"],),
        ).fetchone()[0]


def _snapshot(path: Path, pair: str):
    with sqlite3.connect(path) as conn:
        table = "tickets" if pair.startswith("T") else "claims"
        return conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()


@pytest.mark.parametrize("pair", DEV_PAIRS)
def test_equal_seed_public_surface_and_label_separation(tmp_path, pair):
    fixed, vuln = f"{pair}_fixed", f"{pair}_vuln"
    paths = {variant: tmp_path / f"{variant}.sqlite" for variant in (fixed, vuln)}
    apps = {variant: create_app(variant, paths[variant]) for variant in (fixed, vuln)}
    assert _snapshot(paths[fixed], pair) == _snapshot(paths[vuln], pair)
    assert public_spec_for_case(fixed) == public_spec_for_case(vuln)
    assert apps[fixed].openapi() == apps[vuln].openapi()
    public_text = json.dumps(public_spec_for_case(fixed), ensure_ascii=False).lower()
    assert all(word not in public_text for word in
               ("_fixed", "_vuln", "ground_truth", "vulnerability_type", "truth.json"))
    with TestClient(apps[fixed]) as left, TestClient(apps[vuln]) as right:
        assert left.get("/openapi.json").json() == right.get("/openapi.json").json()
        for identity in ("A", "B", "M"):
            spec = public_spec_for_case(fixed)
            path = spec["control_path"]
            a, b = (client.get(path, headers=_auth(pair, identity)) for client in (left, right))
            assert (a.status_code, a.json()) == (b.status_code, b.json())


@pytest.mark.parametrize("pair", DEV_PAIRS)
@pytest.mark.parametrize("variant", ("fixed", "vuln"))
def test_target_real_state_change_and_visible_control(tmp_path, pair, variant):
    case_id = f"{pair}_{variant}"
    path = tmp_path / f"{case_id}.sqlite"
    spec, truth = public_spec_for_case(case_id), truth_for_case(case_id)
    with TestClient(create_app(case_id, path)) as client:
        before = client.get(spec["control_path"], headers=_auth(pair, "B"))
        assert before.status_code == 200
        assert before.json()[truth["oracle_field"]] == truth["before"]
        assert _value(path, truth) == truth["before"]
        args = {"headers": _auth(pair, "A")}
        if spec["request_body"] is not None:
            args["json"] = spec["request_body"]
        candidate = client.request(spec["target_method"], spec["target_path"], **args)
        assert candidate.status_code == (200 if variant == "vuln" else 403)
        expected = truth["attempted_after"] if variant == "vuln" else truth["before"]
        after = client.get(spec["control_path"], headers=_auth(pair, "B"))
        assert after.status_code == 200
        assert after.json()[truth["oracle_field"]] == expected == _value(path, truth)


@pytest.mark.parametrize("pair", DEV_PAIRS)
def test_legal_actor_and_off_target_behavior(tmp_path, pair):
    spec = public_spec_for_case(f"{pair}_fixed")
    truth = truth_for_case(f"{pair}_fixed")
    legal = "M" if pair in ("T06", "E06") else "B"
    for variant in ("fixed", "vuln"):
        path = tmp_path / f"{pair}_{variant}.sqlite"
        with TestClient(create_app(f"{pair}_{variant}", path)) as client:
            opts = {"headers": _auth(pair, "A")}
            if spec["request_body"] is not None:
                opts["json"] = spec["request_body"]
            # The bad authorization decision is narrowly scoped to the
            # predeclared object, not every route with the same suffix.
            off_target = spec["target_path"].replace(str(truth["oracle_row_id"]), "999")
            result = client.request("POST", off_target, **opts)
            assert result.status_code in (403, 404)
            assert _value(path, truth) == truth["before"]
            opts["headers"] = _auth(pair, legal)
            assert client.request("POST", spec["target_path"], **opts).status_code == 200
            assert _value(path, truth) == truth["attempted_after"]
