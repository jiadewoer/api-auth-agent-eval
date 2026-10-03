"""Structured findings and technical failure accounting, with a fake chat model."""

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent.finding import Finding
from agent.runner import ModelDigestMismatchError, run_case
from scripts.run_dev_cases import run_dev_suite


def tool_call(name, arguments):
    call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=arguments))
    return SimpleNamespace(message=SimpleNamespace(role="assistant", content="", tool_calls=[call]))


def test_pydantic_rejects_unknown_verdict_type_and_extra_fields():
    valid = {"verdict": "vulnerable", "vulnerability_type": "BOLA",
             "identity": "A", "resource": "ticket_201", "evidence_request_ids": ["r001"],
             "explanation": "A actually read B's body"}
    assert Finding.model_validate(valid).verdict == "vulnerable"
    for changed in ({"verdict": "maybe"}, {"vulnerability_type": "RCE"},
                    {"verdict": "not_vulnerable"}, {"unexpected": "secret"}):
        with pytest.raises(ValidationError):
            Finding.model_validate({**valid, **changed})
    assert Finding.model_validate({**valid, "verdict": "insufficient_evidence",
                                   "vulnerability_type": ""}).vulnerability_type is None


def test_verbose_finding_is_graded_instead_of_becoming_a_format_failure():
    valid = {"verdict": "vulnerable", "vulnerability_type": "BOLA",
             "identity": "A", "resource": "ticket_201",
             "evidence_request_ids": ["r001"], "explanation": "x" * 1523}
    assert len(Finding.model_validate(valid).explanation) == 1523
    with pytest.raises(ValidationError):
        Finding.model_validate({**valid, "explanation": "x" * 4097})


def evidence_driven_chat(*, model, messages, tools, options):
    assert options == {"temperature": 0.2, "num_ctx": 4096}
    public = json.loads(messages[1]["content"])
    assert "case_id" not in public
    target = public["target_path"]
    history = [json.loads(item["content"]) for item in messages
               if isinstance(item, dict) and item.get("role") == "tool"]
    if not history:
        return tool_call("send_request", {
            "identity": "B" if target.startswith("/tickets/") else "M",
            "method": "GET", "path": target,
        })
    if len(history) == 1:
        return tool_call("send_request", {"identity": "A", "method": "GET", "path": target})
    candidate = history[1]
    marker = "b-private-201" if target.startswith("/tickets/") else "comment-private-301"
    observed = marker in json.dumps(candidate["body"], ensure_ascii=False)
    return tool_call("submit_finding", {
        "verdict": "vulnerable" if observed else "not_vulnerable",
        "vulnerability_type": ("BOLA" if target.startswith("/tickets/") else "BFLA") if observed else None,
        "identity": "A", "resource": "ticket_201" if target.startswith("/tickets/") else "admin_export",
        "evidence_request_ids": [history[0]["request_id"], candidate["request_id"]],
        "explanation": f"A response contained {marker}" if observed else "A was denied; protected content absent",
    })


def test_four_dev_variants_are_separate_and_results_and_databases_persist(tmp_path):
    sheet = run_dev_suite(evidence_driven_chat, tmp_path)
    assert sheet["all_submitted"] is True
    assert {r["case_id"] for r in sheet["cases"]} == {
        "P01_vuln", "P01_fixed", "P04_vuln", "P04_fixed"}
    assert all(r["legitimate_before_candidate"] for r in sheet["cases"])
    assert all(len(r["cited_request_ids"]) == 2 for r in sheet["cases"])
    assert [r["verdict"] for r in sheet["cases"]] == [
        "vulnerable", "not_vulnerable", "vulnerable", "not_vulnerable"]
    assert len({r["run_id"] for r in sheet["cases"]}) == 4
    for row in sheet["cases"]:
        assert Path(row["log_path"]).exists()
        assert Path(row["result_path"]).exists()
        with sqlite3.connect(row["db_path"]) as conn:
            assert conn.execute("SELECT owner_id FROM tickets WHERE id=201").fetchone()[0] == "B"


@pytest.mark.parametrize("bad_args,expected_category,expected_code", [
    ('{"identity":', "invalid_json", "INVALID_JSON"),
    ({"identity": "A", "method": "GET", "path": "/cases/truth.json"},
     "tool_parameter_error", "INVALID_ROUTE"),
])
def test_bad_tool_call_becomes_run_error(tmp_path, bad_args, expected_category, expected_code):
    result = run_case("P01_fixed", lambda **_: tool_call("send_request", bad_args), tmp_path)
    assert result["status"] == "run_error" and result["finding"] is None
    assert result["run_error"] == {"category": expected_category, "code": expected_code}
    lines = [json.loads(s) for s in Path(result["log_path"]).read_text(encoding="utf-8").splitlines()]
    assert lines[-1]["tool_name"] == "run_error"


@pytest.mark.parametrize("vuln_type,ids,expected", [
    ("RCE", ["r001"], "INVALID_FINDING"),
    ("BOLA", ["req_999"], "UNKNOWN_EVIDENCE"),
])
def test_invalid_finding_on_fixed_case_never_counts_as_correct(tmp_path, vuln_type, ids, expected):
    def chat(**kwargs):
        got = [m for m in kwargs["messages"] if isinstance(m, dict) and m.get("role") == "tool"]
        if not got:
            return tool_call("send_request", {"identity": "A", "method": "GET", "path": "/tickets/201"})
        return tool_call("submit_finding", {
            "verdict": "vulnerable", "vulnerability_type": vuln_type,
            "identity": "A", "resource": "ticket_201",
            "evidence_request_ids": ids, "explanation": "Invalid evidence",
        })

    result = run_case("P01_fixed", chat, tmp_path)
    assert result["status"] == "run_error" and result["finding"] is None
    assert result["run_error"] == {"category": "finding_validation_error", "code": expected}


def test_timeout_no_conclusion_and_model_version_are_distinct_run_errors(tmp_path):
    def timeout(**_kwargs):
        raise TimeoutError("simulated timeout")

    def no_tools(**_kwargs):
        return SimpleNamespace(message=SimpleNamespace(tool_calls=[], content="plain answer"))

    def wrong_version(**_kwargs):
        raise ModelDigestMismatchError("installed digest changed")

    def out_of_memory(**_kwargs):
        raise RuntimeError("requires more system memory")

    def connection_refused(**_kwargs):
        raise ConnectionError("local service unavailable")

    for chat, category, code, decisions in (
        (timeout, "model_timeout", "MODEL_TIMEOUT", 1),
        (no_tools, "no_conclusion", "NO_CONCLUSION", 16),
        (wrong_version, "model_version_mismatch", "MODEL_VERSION_MISMATCH", 1),
        (out_of_memory, "model_resource_error", "MODEL_RESOURCE_ERROR", 1),
        (connection_refused, "model_service_unavailable", "MODEL_SERVICE_UNAVAILABLE", 1),
    ):
        result = run_case("P04_fixed", chat, tmp_path)
        assert result["status"] == "run_error"
        assert result["finding"] is None
        assert result["model_decisions"] == decisions
        assert result["run_error"] == {"category": category, "code": code}
        assert Path(result["db_path"]).exists()
        if code == "NO_CONCLUSION":
            trace = [json.loads(s) for s in Path(result["log_path"]).read_text(encoding="utf-8").splitlines()]
            assert any(row["tool_name"] == "model_text" and
                       row["response_body"]["content"] == "plain answer" for row in trace)


def test_agent_can_explicitly_abstain_with_real_evidence(tmp_path):
    def chat(**kwargs):
        seen = [m for m in kwargs["messages"] if isinstance(m, dict) and m.get("role") == "tool"]
        if not seen:
            return tool_call("send_request", {"identity": "A", "method": "GET", "path": "/admin/export"})
        request_id = json.loads(seen[-1]["content"])["request_id"]
        return tool_call("submit_finding", {
            "verdict": "insufficient_evidence", "vulnerability_type": "",
            "identity": "A", "resource": "admin_export",
            "evidence_request_ids": [request_id], "explanation": "Cannot conclude from one request",
        })

    result = run_case("P04_fixed", chat, tmp_path)
    assert result["status"] == "submitted"
    assert result["finding"]["verdict"] == "insufficient_evidence"
    assert result["finding"]["vulnerability_type"] is None
    assert result["run_error"] is None


def test_lab_initialization_exception_has_its_own_failure_record(tmp_path, monkeypatch):
    def broken_app(*_args, **_kwargs):
        raise RuntimeError("fake seed problem")

    monkeypatch.setattr("agent.runner.create_app", broken_app)
    result = run_case("P01_fixed", lambda **_: None, tmp_path)
    assert result["status"] == "run_error" and result["finding"] is None
    assert result["run_error"] == {"category": "lab_exception", "code": "LAB_INIT_EXCEPTION:RuntimeError"}
    assert Path(result["log_path"]).exists()
    assert Path(result["result_path"]).exists()


def test_ninth_api_request_is_a_budget_run_error(tmp_path):
    def repetitive_chat(**_kwargs):
        return tool_call("send_request", {
            "identity": "B", "method": "GET", "path": "/tickets/201",
        })

    result = run_case("P01_fixed", repetitive_chat, tmp_path)
    assert result["status"] == "run_error" and result["finding"] is None
    assert result["api_requests"] == 8
    assert result["model_decisions"] == 9
    assert result["run_error"] == {"category": "budget_exceeded", "code": "REQUEST_LIMIT"}
