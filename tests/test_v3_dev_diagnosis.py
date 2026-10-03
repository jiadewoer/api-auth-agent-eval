"""One safe normalization and observable failures for the real-model dev run."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cases.v3_catalog import public_spec_for_case
from expense_app.main import create_app as expense_app
from ticket_v3.main import create_app as ticket_app
from v3_agent.diagnose_dev import diagnose
from v3_agent.grade import grade_run
from v3_agent.run_dev import deterministic_stub
from v3_agent import run_dev
from v3_agent.runner import run_case
from v3_agent.tools import V3Tools


def _native(name, arguments):
    return SimpleNamespace(message=SimpleNamespace(
        content="", tool_calls=[SimpleNamespace(function=SimpleNamespace(
            name=name, arguments=arguments))]
    ))


@pytest.mark.parametrize("case_id", ("T01_fixed", "E01_vuln"))
def test_null_arguments_for_noarg_spec_then_real_http(tmp_path, case_id):
    def model(**kwargs):
        if not any(isinstance(item, dict) and item.get("role") == "tool"
                   for item in kwargs["messages"]):
            return _native("read_api_spec", None)
        return deterministic_stub(**kwargs)

    record = run_case(case_id, model, tmp_path)
    trace = [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]
    assert record["status"] == "submitted"
    assert record["api_requests"] == 3
    assert [event["tool_name"] for event in trace].count("tool_argument_normalization") == 1
    assert grade_run(record, trace)["evidence_valid"] is True


@pytest.mark.parametrize("case_id", ("T01_fixed", "T01_vuln", "E01_fixed", "E01_vuln"))
def test_observed_qwen_path_argument_is_bound_to_public_target(tmp_path, case_id):
    def model(**kwargs):
        public = json.loads(kwargs["messages"][1]["content"])
        if not any(isinstance(item, dict) and item.get("role") == "tool"
                   for item in kwargs["messages"]):
            return _native("read_api_spec", {"path": public["target_path"]})
        return deterministic_stub(**kwargs)

    record = run_case(case_id, model, tmp_path)
    trace = [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]
    assert record["status"] == "submitted"
    assert trace[1]["tool_name"] == "read_api_spec"
    assert trace[1]["arguments"] == {"path": public_spec_for_case(case_id)["target_path"]}
    assert record["api_requests"] == 3
    assert grade_run(record, trace)["verdict_correct"] is True
    assert grade_run(record, trace)["evidence_valid"] is True


@pytest.mark.parametrize("case_id", ("T01_vuln", "E01_fixed"))
def test_read_spec_rejects_other_path_host_and_extra_arguments(tmp_path, case_id):
    public = public_spec_for_case(case_id)
    db = tmp_path / "fresh.sqlite"
    app = ticket_app(case_id, db) if case_id.startswith("T") else expense_app(db, case_id=case_id)
    app_id = "ticket_lab_v3" if case_id.startswith("T") else "expense_lab_v1"
    with TestClient(app) as client:
        tools = V3Tools(client, app_id=app_id, public=public, db_path=db,
                        log_path=tmp_path / "trace.jsonl")
        assert "spec" in tools.dispatch("read_api_spec", {"path": public["target_path"]})
        assert tools.dispatch("read_api_spec", {"path": "/admin/export"})["error"]["code"] == "INVALID_ROUTE"
        assert tools.dispatch("read_api_spec", {"path": "http://evil.example"})["error"]["code"] == "INVALID_ROUTE"
        assert tools.dispatch("read_api_spec", {"path": public["target_path"],
                                                "host": "evil.example"})["error"]["code"] == "INVALID_ARGUMENTS"
        assert tools.request_count == 0


def test_missing_request_arguments_still_rejected_and_diagnosed(tmp_path):
    record = run_case("E01_vuln", lambda **_: _native("send_request", {"identity": "A"}), tmp_path)
    assert record["status"] == "run_error"
    assert record["run_error"]["code"] == "INVALID_ARGUMENTS"
    assert record["api_requests"] == 0
    summary = diagnose(tmp_path)
    assert summary["run_error_count"] == 1
    first = summary["failures"][0]["first_failed_call"]
    assert first == {"step": 2, "tool_name": "send_request",
                     "arguments": {"identity": "A"}, "error": "INVALID_ARGUMENTS"}
    assert "ground_truth" not in json.dumps(summary)


def test_dev_cli_exits_nonzero_after_saving_a_failed_result(tmp_path, monkeypatch, capsys):
    trace_path = tmp_path / "agent_failure.jsonl"
    trace_path.write_text('', encoding="utf-8")
    monkeypatch.setattr(run_dev, "run_case", lambda *_args, **_kwargs: {
        "run_id": "failure", "case_id": "E01_fixed", "status": "run_error",
        "run_error": {"category": "tool_parameter_error", "code": "INVALID_ARGUMENTS"},
        "finding": None, "api_requests": 0, "log_path": str(trace_path),
    })
    monkeypatch.setattr(run_dev, "grade_run", lambda *_args: {
        "verdict_correct": None, "evidence_valid": False,
    })
    monkeypatch.setattr(sys, "argv", ["run_dev", "--provider", "stub",
                                      "--case-id", "E01_fixed", "--output", str(tmp_path)])
    with pytest.raises(SystemExit) as outcome:
        run_dev.main()
    assert outcome.value.code == 2
    assert json.loads(capsys.readouterr().out)["run_errors"] == 1
    assert (tmp_path / "grade_failure.json").is_file()
