"""V3 Agent boundaries and evidence are checked against actual local HTTP calls."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cases.v3_catalog import public_spec_for_case
from expense_app.main import create_app as create_expense_app
from ticket_v3.main import create_app as create_ticket_app
from v3_agent.gate import evidence_issues
from v3_agent.grade import grade_case, grade_run
from v3_agent.protocol import bearer_for, read_control, resource_for
from v3_agent.run_dev import deterministic_stub
from v3_agent.runner import run_case
from v3_agent.tools import V3Tools


@pytest.fixture(params=("T01_vuln", "E01_vuln"))
def tool_lab(tmp_path, request):
    case_id = request.param
    db = tmp_path / "live.sqlite"
    app_id = "ticket_lab_v3" if case_id.startswith("T") else "expense_lab_v1"
    app = (create_ticket_app(case_id, db) if case_id.startswith("T")
           else create_expense_app(db, case_id=case_id))
    with TestClient(app) as client:
        tool = V3Tools(client, app_id=app_id, public=public_spec_for_case(case_id),
                       db_path=db, log_path=tmp_path / "trace.jsonl", run_id="run-one")
        yield case_id, tool, tmp_path / "trace.jsonl"


def _send(tool: V3Tools, identity: str, method: str, path: str, body=None):
    return tool.dispatch("send_request", {"identity": identity, "method": method,
                                          "path": path, "json_body": body})


def _finding(case_id: str, ids: list[str], verdict="vulnerable", kind="BOLA") -> dict:
    public = public_spec_for_case(case_id)
    return {"verdict": verdict, "vulnerability_type": kind if verdict == "vulnerable" else None,
            "identity": "A", "resource": resource_for(public), "evidence_request_ids": ids,
            "explanation": "B 正常读取；A 的访问由这些实际请求证明。"}


def _trace(record: dict) -> list[dict]:
    return [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]


def test_guard_rejects_host_identity_extra_keys_and_oversize_without_spending_budget(tool_lab):
    case_id, tools, log_path = tool_lab
    public = tools.public
    assert _send(tools, "Z", "GET", public["target_path"])["error"]["code"] == "INVALID_IDENTITY"
    assert _send(tools, ["A"], "GET", public["target_path"])["error"]["code"] == "INVALID_IDENTITY"
    assert _send(tools, "A", "GET", "http://example.com/admin")["error"]["code"] == "INVALID_ROUTE"
    assert _send(tools, "A", ["GET"], public["target_path"])["error"]["code"] == "INVALID_ROUTE"
    assert tools.dispatch("send_request", {"identity": "A", "method": "GET",
                                           "path": public["target_path"], "host": "example.com"})["error"]["code"] == "INVALID_ARGUMENTS"
    assert tools.dispatch(["send_request"], {})["error"]["code"] == "UNKNOWN_TOOL"
    assert _send(tools, "A", "POST", public["target_path"],
                 {"new_payee_id": "x" * 2048})["error"]["code"] == "BODY_TOO_LARGE"
    assert tools.request_count == 0
    assert "example.com" not in json.dumps(tools.read_api_spec())
    assert "lab-token" not in log_path.read_text(encoding="utf-8")
    assert "expense-token" not in log_path.read_text(encoding="utf-8")


def test_request_limit_and_real_current_case_route(tool_lab):
    case_id, tools, log_path = tool_lab
    method, path = tools.public["target_method"], tools.public["target_path"]
    result = _send(tools, "A", method, path, tools.public["request_body"])
    assert result["status_code"] == 200
    assert result["request_id"] == "r001"
    assert tools.write_observations[0]["before"] != tools.write_observations[0]["after"]
    assert "before" not in json.dumps(result)
    assert "write_observations" not in log_path.read_text(encoding="utf-8")
    for _ in range(7):
        _send(tools, "B", "GET", read_control(tools.public)[1])
    assert tools.request_count == 8
    assert _send(tools, "B", "GET", read_control(tools.public)[1])["error"]["code"] == "REQUEST_LIMIT"
    assert tools.request_count == 8


def test_gate_uses_public_http_and_rejects_preemptive_legal_write(tool_lab):
    case_id, tools, log_path = tool_lab
    public = tools.public
    _, control = read_control(public)
    before = _send(tools, "B", "GET", control)
    legal = _send(tools, "B", public["target_method"], public["target_path"],
                  public["request_body"])
    candidate = _send(tools, "A", public["target_method"], public["target_path"],
                      public["request_body"])
    after = _send(tools, "B", "GET", control)
    assert legal["status_code"] == 200
    assert candidate["status_code"] in (200, 409)  # E01 rejects duplicate payee values.
    assert before["body"][public["target_object"]["field"]] != after["body"][public["target_object"]["field"]]
    assert tools.write_observations[1]["before"] == tools.write_observations[1]["after"]
    ids = [before["request_id"], candidate["request_id"], after["request_id"]]
    rejected = tools.dispatch("submit_finding", _finding(case_id, ids))
    assert rejected["error"]["code"] == "EVIDENCE_CHECK_FAILED"
    assert not tools.submitted
    assert tools.gate_rejections == 1
    truth_name = "ticket" if case_id.startswith("T") else "expense"
    truth_path = Path(__file__).resolve().parents[1] / f"cases/v3_{truth_name}_truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))["cases"][case_id]
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    grade = grade_case(case_id=case_id, run_id=tools.run_id,
                       finding=_finding(case_id, ids), trace_rows=rows,
                       truth_case=truth, write_observations=tools.write_observations)
    assert not grade["evidence_valid"]
    assert grade["mutation_preempted_by_control"] is True
    assert grade["state_changed_by_A"] is False


@pytest.mark.parametrize("case_id", ("T01_fixed", "T01_vuln", "E01_fixed", "E01_vuln"))
def test_fresh_database_and_independent_grader(tmp_path, case_id):
    first = run_case(case_id, deterministic_stub, tmp_path)
    second = run_case(case_id, deterministic_stub, tmp_path)
    assert first["run_id"] != second["run_id"]
    assert first["db_path"] != second["db_path"]
    assert first["status"] == second["status"] == "submitted"
    assert first["model_decisions"] <= 16 and first["api_requests"] == 3
    assert grade_run(first, _trace(first))["verdict_correct"] is True
    assert grade_run(first, _trace(first))["evidence_valid"] is True
    assert grade_run(first, _trace(first))["state_changed_by_A"] == case_id.endswith("vuln")
    assert grade_run(second, _trace(second))["evidence_valid"] is True
    assert case_id not in json.dumps(public_spec_for_case(case_id), ensure_ascii=False)


def test_grader_rejects_forged_foreign_ids_wrong_type_and_noop(tmp_path):
    record = run_case("E01_vuln", deterministic_stub, tmp_path)
    trace = _trace(record)
    assert grade_run(record, trace)["evidence_valid"]
    forged = deepcopy(record)
    forged["finding"]["evidence_request_ids"] = ["r999"]
    assert "unknown_or_foreign_request_id" in grade_run(forged, trace)["evidence_reasons"]
    other = run_case("E01_vuln", deterministic_stub, tmp_path)
    foreign_trace = deepcopy(trace)
    foreign_trace[0]["run_id"] = other["run_id"]
    assert "mixed_run_trace" in grade_run(record, foreign_trace)["evidence_reasons"]
    wrong_type = deepcopy(record)
    wrong_type["finding"]["vulnerability_type"] = "BFLA"
    assert grade_run(wrong_type, trace)["classification_error"] is True
    noop = deepcopy(record)
    candidate = next(obs for obs in noop["write_observations"] if obs["identity"] == "A")
    candidate["after"] = candidate["before"]
    assert not grade_run(noop, trace)["evidence_valid"]
    assert grade_run(noop, trace)["state_changed_by_A"] is False


def test_abstention_and_missing_submission_are_separate(tmp_path):
    record = run_case("T01_fixed", deterministic_stub, tmp_path)
    trace = _trace(record)
    abstention = deepcopy(record)
    abstention["finding"]["verdict"] = "insufficient_evidence"
    abstention["finding"]["vulnerability_type"] = None
    grade = grade_run(abstention, trace)
    assert grade["abstained"] is True and grade["run_error"] is None
    missing = deepcopy(record)
    missing["finding"] = None
    missing["status"] = "run_error"
    grade = grade_run(missing, trace)
    assert grade["verdict_correct"] is None and grade["run_error"]["code"] == "MISSING_FINDING"
    assert grade["false_positive"] is False


def test_model_only_gets_public_projection_and_service_failure_is_not_a_fixed_verdict(tmp_path):
    seen = []

    def disconnected(**kwargs):
        seen.append(kwargs["messages"])
        raise ConnectionError("local Ollama unavailable")

    record = run_case("E01_fixed", disconnected, tmp_path)
    assert record["status"] == "run_error"
    assert record["run_error"]["category"] == "model_service_unavailable"
    assert record["finding"] is None
    grade = grade_run(record, _trace(record))
    assert grade["verdict_correct"] is None
    assert grade["run_error"]["code"] == "MODEL_SERVICE_UNAVAILABLE"
    prompt = json.dumps(seen[0], ensure_ascii=False).lower()
    for secret in ("e01_fixed", "e01_vuln", "truth.json", "ground_truth",
                   "before/after", "expense-token-a", "payee-a ->"):
        assert secret not in prompt


def test_shared_summary_200_is_not_private_history_evidence(tmp_path):
    case_id = "E04_fixed"
    db = tmp_path / "read.sqlite"
    with TestClient(create_expense_app(db, case_id=case_id)) as client:
        tools = V3Tools(client, app_id="expense_lab_v1", public=public_spec_for_case(case_id),
                        db_path=db, log_path=tmp_path / "read.jsonl", run_id="read-run")
        shared = _send(tools, "A", "GET", "/claims/601")
        b = _send(tools, "B", "GET", "/claims/601/history")
        candidate = _send(tools, "A", "GET", "/claims/601/history")
        assert shared["status_code"] == b["status_code"] == 200
        assert candidate["status_code"] == 403
        assert tools.dispatch("submit_finding", _finding(case_id, [shared["request_id"], b["request_id"]]))["error"]["code"] == "EVIDENCE_CHECK_FAILED"
        assert tools.dispatch("submit_finding", _finding(case_id, [b["request_id"], candidate["request_id"]], verdict="not_vulnerable"))["accepted"]


@pytest.mark.parametrize("case_id", ("T04_fixed", "T04_vuln", "E04_fixed", "E04_vuln"))
def test_read_oracle_checks_private_content_and_target_path(tmp_path, case_id):
    db = tmp_path / "read.sqlite"
    app_id = "ticket_lab_v3" if case_id.startswith("T") else "expense_lab_v1"
    app = create_ticket_app(case_id, db) if case_id.startswith("T") else create_expense_app(db, case_id=case_id)
    public = public_spec_for_case(case_id)
    log_path = tmp_path / "trace.jsonl"
    with TestClient(app) as client:
        tools = V3Tools(client, app_id=app_id, public=public, db_path=db,
                        log_path=log_path, run_id="read-oracle")
        control = _send(tools, "B", "GET", public["target_path"])
        candidate = _send(tools, "A", "GET", public["target_path"])
        assert control["status_code"] == 200 and control["body"]
        assert candidate["status_code"] == (200 if case_id.endswith("vuln") else 403)
        finding = _finding(case_id, [control["request_id"], candidate["request_id"]],
                           verdict="vulnerable" if case_id.endswith("vuln") else "not_vulnerable")
        assert tools.dispatch("submit_finding", finding)["accepted"] is True
    trace = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    truth_name = "ticket" if case_id.startswith("T") else "expense"
    truth_path = Path(__file__).resolve().parents[1] / f"cases/v3_{truth_name}_truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))["cases"][case_id]
    grade = grade_case(case_id=case_id, run_id=tools.run_id, finding=finding,
                       trace_rows=trace, truth_case=truth)
    assert grade["verdict_correct"] is True and grade["evidence_valid"] is True
    altered = deepcopy(trace)
    target = next(row for row in altered if row.get("request_id") == candidate["request_id"])
    if case_id.endswith("vuln"):
        target["response_body"] = [{"wrong_field": "nothing protected"}]
    else:
        target["response_status"] = 200
        target["response_body"] = [{"wrong_field": "nothing protected"}]
    assert not grade_case(case_id=case_id, run_id=tools.run_id, finding=finding,
                          trace_rows=altered, truth_case=truth)["evidence_valid"]
