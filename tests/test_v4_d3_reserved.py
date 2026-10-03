"""New D3 reserved case isolation, real HTTP state, and runner plumbing."""

from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from v4_lab.apps import create_app
from v4_lab.catalog import (
    D3_RESERVED_CASE_IDS, D3_RESERVED_PAIRS, DEV_CASE_IDS, RESERVED_CASE_IDS,
    internal_case_for, public_spec_for_case, truth_for_case,
)
from v4_lab.dev_manifest import snapshot
from v4_lab.prompts import CONDITIONS
from v4_lab.run_ab_dev import deterministic_stub
from v4_lab.run_d3_reserved import planned_keys, run_d3_reserved


def _auth(pair: str, identity: str) -> dict:
    prefix = "lab" if pair.startswith("T") else "expense"
    return {"Authorization": f"Bearer {prefix}-token-{identity.lower()}"}


def _state(db_path, truth: dict) -> str:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(
            f"SELECT {truth['oracle_field']} FROM {truth['oracle_table']} WHERE id = ?",
            (truth["oracle_row_id"],),
        ).fetchone()[0]


def test_new_cohort_is_disjoint_balanced_and_manifested() -> None:
    assert len(D3_RESERVED_PAIRS) == 12
    assert len(D3_RESERVED_CASE_IDS) == 24
    assert not set(D3_RESERVED_CASE_IDS) & (set(DEV_CASE_IDS) | set(RESERVED_CASE_IDS))
    previous_ids = {public_spec_for_case(case_id)["target_object"]["id"]
                    for case_id in DEV_CASE_IDS + RESERVED_CASE_IDS}
    new_ids = {public_spec_for_case(case_id)["target_object"]["id"]
               for case_id in D3_RESERVED_CASE_IDS}
    assert len(new_ids) == 12 and not (new_ids & previous_ids)
    assert sum(truth_for_case(f"{pair}_vuln")["vulnerability_type"] == "BOLA"
               for pair in D3_RESERVED_PAIRS) == 6
    assert sum(truth_for_case(f"{pair}_vuln")["vulnerability_type"] == "BFLA"
               for pair in D3_RESERVED_PAIRS) == 6
    keys = planned_keys()
    assert len(keys) == len(set(keys)) == 192
    assert {case_id for case_id, _, _ in keys} == set(D3_RESERVED_CASE_IDS)
    manifest = snapshot("stub", split="d3_reserved")
    assert manifest["phase"] == "V4_D3_reserved_evaluation"
    assert manifest["cases"] == list(D3_RESERVED_CASE_IDS)
    assert manifest["repeats"] == 2 and manifest["planned_runs"] == 192


@pytest.mark.parametrize("pair", D3_RESERVED_PAIRS)
def test_fixed_vulnerable_public_surface_and_state(tmp_path, pair: str) -> None:
    fixed, vuln = f"{pair}_fixed", f"{pair}_vuln"
    spec = public_spec_for_case(fixed)
    assert spec == public_spec_for_case(vuln)
    assert internal_case_for(fixed)["split"] == "d3_reserved"
    assert internal_case_for(vuln)["split"] == "d3_reserved"
    public_text = json.dumps(spec, ensure_ascii=False).lower()
    assert all(marker not in public_text for marker in
               ("_fixed", "_vuln", "ground_truth", "vulnerability_type", "truth.json"))
    fixed_db, vuln_db = tmp_path / "fixed.sqlite", tmp_path / "vuln.sqlite"
    with TestClient(create_app(fixed, fixed_db)) as left, TestClient(create_app(vuln, vuln_db)) as right:
        assert left.get("/openapi.json").json() == right.get("/openapi.json").json()
        for identity in ("A", "B", "M"):
            a = left.get(spec["control_path"], headers=_auth(pair, identity))
            b = right.get(spec["control_path"], headers=_auth(pair, identity))
            assert (a.status_code, a.json()) == (b.status_code, b.json())
        for case_id, client, path, expected in (
            (fixed, left, fixed_db, 403), (vuln, right, vuln_db, 200)
        ):
            truth = truth_for_case(case_id)
            before = client.get(spec["control_path"], headers=_auth(pair, "B"))
            assert before.status_code == 200
            assert before.json()[truth["oracle_field"]] == truth["before"]
            args = {"headers": _auth(pair, "A")}
            if spec["request_body"] is not None:
                args["json"] = spec["request_body"]
            assert client.request("POST", spec["target_path"], **args).status_code == expected
            after = client.get(spec["control_path"], headers=_auth(pair, "B"))
            state = truth["attempted_after"] if expected == 200 else truth["before"]
            assert after.status_code == 200
            assert after.json()[truth["oracle_field"]] == state == _state(path, truth)


def test_stub_and_immutable_resume(tmp_path) -> None:
    path = tmp_path / "d3_stub"
    summary = run_d3_reserved(output=path, provider="stub", chat_fn=deterministic_stub)
    assert (summary["rows"], summary["new_rows"], summary["run_errors"]) == (192, 192, 0)
    assert summary["protocol_id"] == "V4-D3-R1"
    for condition in CONDITIONS:
        assert summary["per_condition"][condition]["stage_counts"]["s4"] == [24, 24]
        assert summary["per_condition"][condition]["fixed_false_positives"] == [0, 24]
        assert summary["per_condition"][condition]["fixed_correct"] == [24, 24]
        assert summary["per_condition"][condition]["paired_success"] == [24, 24]
    resumed = run_d3_reserved(output=path, provider="stub", chat_fn=deterministic_stub)
    assert (resumed["rows"], resumed["new_rows"], resumed["skipped"]) == (192, 0, 192)
    with pytest.raises(ValueError, match="manifest mismatch"):
        run_d3_reserved(output=path, provider="ollama", chat_fn=deterministic_stub)
