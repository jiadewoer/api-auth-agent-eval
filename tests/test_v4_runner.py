"""V4 four-arm development only: public protocol, state, evidence and resume."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from v4_lab.apps import create_app
from v4_lab.catalog import DEV_CASE_IDS, public_spec_for_case, truth_for_case
from v4_lab.dev_manifest import snapshot
from v4_lab.prompts import CONDITIONS, ROOT as PROMPT_ROOT, render_prompt
from v4_lab.run_ab_dev import deterministic_stub, planned_keys, run_development
from v4_lab.runner import run_case
from v4_lab.stages import score_write_stages
from v4_lab.tools import V4Tools


def test_factorial_prompts_vary_only_by_two_public_fragments():
    base, order, types = tuple(
        (PROMPT_ROOT / name).read_text(encoding="utf-8").strip()
        for name in ("base.txt", "order.txt", "types.txt")
    )
    assert render_prompt("R0C0") == base
    assert render_prompt("R1C0") == base + "\n" + order
    assert render_prompt("R0C1") == base + "\n" + types
    assert render_prompt("R1C1") == base + "\n" + order + "\n" + types
    with pytest.raises(ValueError):
        render_prompt("A")
    assert snapshot("stub")["planned_runs"] == 32
    assert len(planned_keys()) == len(set(planned_keys())) == 32
    assert set(key[0] for key in planned_keys()) == set(DEV_CASE_IDS)


def test_tool_surface_is_bounded_and_evidence_gate_ignores_type(tmp_path):
    public = public_spec_for_case("T05_vuln")
    db_path, log_path = tmp_path / "lab.sqlite", tmp_path / "trace.jsonl"
    with TestClient(create_app("T05_vuln", db_path)) as client:
        tool = V4Tools(client, app_id="ticket_lab_v4", public=public,
                       db_path=db_path, log_path=log_path, run_id="testing")
        spec = tool.read_api_spec()
        assert "ground_truth" not in json.dumps(spec)
        assert "T05_vuln" not in json.dumps(spec)
        assert tool.send_request("A", "GET", "http://localhost/tickets/501/priority")["error"]["code"] == "INVALID_ROUTE"
        assert tool.send_request("A", "POST", public["target_path"], {"priority": "other"})["error"]["code"] == "INVALID_BODY"
        first = tool.send_request("B", "GET", public["control_path"])
        target = tool.send_request("A", "POST", public["target_path"], public["request_body"])
        last = tool.send_request("B", "GET", public["control_path"])
        assert [first["body"]["priority"], last["body"]["priority"]] == ["normal", "high"]
        assert tool.write_observations[0]["before"] == "normal"
        assert tool.write_observations[0]["after"] == "high"
        wrong_type = {"verdict": "vulnerable", "vulnerability_type": "BFLA",
                      "identity": "A", "resource": "ticket_501",
                      "evidence_request_ids": [first["request_id"], target["request_id"], last["request_id"]],
                      "explanation": "The shared reader changed the owner's priority."}
        assert tool.submit_finding(**wrong_type) == {"accepted": True}
        record = {"run_id": "testing", "case_id": "T05_vuln", "status": "submitted",
                  "finding": tool.finding, "write_observations": tool.write_observations}
        trace = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        score = score_write_stages(public=public, truth=truth_for_case("T05_vuln"),
                                   record=record, trace=trace)
        assert [score[f"s{i}"] for i in range(1, 5)] == [True, True, True, False]
        assert "token" not in log_path.read_text(encoding="utf-8").lower()


def test_uncited_sequence_is_rejected_by_gate(tmp_path):
    public = public_spec_for_case("E06_vuln")
    db_path, log_path = tmp_path / "lab.sqlite", tmp_path / "trace.jsonl"
    with TestClient(create_app("E06_vuln", db_path)) as client:
        tool = V4Tools(client, app_id="expense_lab_v4", public=public,
                       db_path=db_path, log_path=log_path, run_id="testing")
        target = tool.send_request("A", "POST", public["target_path"], None)
        finding = {"verdict": "vulnerable", "vulnerability_type": "BFLA",
                   "identity": "A", "resource": "claim_702",
                   "evidence_request_ids": [target["request_id"]], "explanation": "Observed change"}
        result = tool.submit_finding(**finding)
        assert result["error"]["code"] == "EVIDENCE_CHECK_FAILED"
        assert "cite_clean_B_GET_A_POST_B_GET_sequence" in result["error"]["issues"]
        assert tool.write_observations[0]["before"] != tool.write_observations[0]["after"]


def test_stub_development_all_arms_and_immutable_resume(tmp_path):
    seen = []
    def chat(**kwargs):
        public_text = kwargs["messages"][1]["content"]
        assert "ground_truth" not in public_text and "case_id" not in public_text
        assert "_fixed" not in public_text and "_vuln" not in public_text
        seen.append(kwargs["messages"][0]["content"])
        return deterministic_stub(**kwargs)
    first = run_development(output=tmp_path / "run", provider="stub", chat_fn=chat)
    assert (first["rows"], first["new_rows"], first["run_errors"]) == (32, 32, 0)
    assert len(set(seen)) == 4
    assert all(first["per_condition"][arm]["stage_counts"]["s4"] == [4, 4]
               for arm in CONDITIONS)
    second = run_development(output=tmp_path / "run", provider="stub", chat_fn=chat)
    assert second["rows"] == 32 and second["new_rows"] == 0 and second["skipped"] == 32
    with pytest.raises(ValueError, match="manifest mismatch"):
        run_development(output=tmp_path / "run", provider="ollama", chat_fn=chat)
    path = tmp_path / "run/results.jsonl"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(path.read_text(encoding="utf-8").splitlines()[0] + "\n")
    with pytest.raises(ValueError, match="Invalid V4 result row"):
        run_development(output=tmp_path / "run", provider="stub", chat_fn=chat)


def test_real_write_remains_in_timeout_record(tmp_path):
    decisions = 0
    def chat(**kwargs):
        nonlocal decisions
        decisions += 1
        if decisions == 5:
            raise TimeoutError("synthetic model timeout after visible state change")
        return deterministic_stub(**kwargs)
    record = run_case("E05_vuln", chat, tmp_path, condition="R1C1")
    assert record["status"] == "run_error"
    assert record["run_error"]["category"] == "model_timeout"
    trace = [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]
    score = score_write_stages(public=public_spec_for_case("E05_vuln"),
                               truth=truth_for_case("E05_vuln"), record=record, trace=trace)
    assert score["s1"] and score["s2"] and not score["s3"] and not score["s4"]
