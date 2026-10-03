"""The repair runs in isolation and still enforces the old tool boundary."""

from __future__ import annotations

import json
from types import SimpleNamespace

from followup_v2.run import run_batch
from followup_v2.runner import run_condition
from followup_v2.summarize import summarize
from followup_v2.text_tool import parse_text_tool_call


def text_response(content: str):
    return SimpleNamespace(message=SimpleNamespace(role="assistant", content=content, tool_calls=[]))


def native_tool(name: str, arguments: dict):
    call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=arguments))
    return SimpleNamespace(message=SimpleNamespace(role="assistant", content="", tool_calls=[call]))


def scripted(*responses):
    steps = iter(responses)

    def chat(**_kwargs):
        return next(steps)

    return chat


def finding(ids, verdict="vulnerable", kind="BOLA"):
    return {"verdict": verdict, "vulnerability_type": kind,
            "identity": "A", "resource": "ticket_201",
            "evidence_request_ids": ids, "explanation": "Cited request observations"}


def test_parser_rejects_prose_multiple_objects_and_extra_envelope_fields():
    valid = '{"name":"inspect_response","arguments":{"request_id":"r001"}}'
    assert parse_text_tool_call(valid) == ("inspect_response", {"request_id": "r001"})
    for value in ("```json\n" + valid + "\n```", valid + valid,
                  json.dumps({"name": "inspect_response", "arguments": {}, "secret": True}),
                  '{"verdict":"vulnerable"}', "not JSON"):
        assert parse_text_tool_call(value) is None


def test_textual_submit_is_actually_dispatched_and_graded(tmp_path):
    chat = scripted(
        native_tool("send_request", {"identity": "B", "method": "GET", "path": "/tickets/201"}),
        native_tool("send_request", {"identity": "A", "method": "GET", "path": "/tickets/201"}),
        text_response(json.dumps({"name": "submit_finding", "arguments": finding(["r001", "r002"])})),
    )
    raw = run_condition("P01_vuln", "T1E0", chat, tmp_path)
    assert raw["status"] == "submitted"
    assert raw["finding"]["verdict"] == "vulnerable"
    assert raw["api_requests"] == 2 and raw["model_decisions"] == 3
    trace = [json.loads(s) for s in (tmp_path / f"agent_{raw['run_id']}.jsonl").read_text().splitlines()]
    assert [e["tool_name"] for e in trace].count("text_tool_adapter") == 1
    assert [e["tool_name"] for e in trace].count("submit_finding") == 1


def test_textual_request_uses_actual_local_api_and_budget(tmp_path):
    chat = scripted(
        text_response(json.dumps({"name": "send_request", "arguments":
                                  {"identity": "A", "method": "GET", "path": "/tickets/201"}})),
        native_tool("submit_finding", finding(["r001"])),
    )
    raw = run_condition("P01_vuln", "T0E0", chat, tmp_path)
    trace = [json.loads(s) for s in (tmp_path / f"agent_{raw['run_id']}.jsonl").read_text().splitlines()]
    sent = next(e for e in trace if e["tool_name"] == "send_request")
    assert raw["status"] == "submitted" and raw["api_requests"] == 1
    assert sent["identity"] == "A" and sent["response_status"] == 200
    assert sent["response_body"]["body"] == "b-private-201"


def test_unknown_tool_and_extra_arguments_cannot_escape_dispatch(tmp_path):
    for idx, envelope in enumerate((
        {"name": "shell", "arguments": {"cmd": "echo no"}},
        {"name": "send_request", "arguments": {"identity": "A", "method": "GET",
                                                 "path": "/tickets/201", "host": "outside"}},
    )):
        raw = run_condition("P01_vuln", "T1E0", scripted(text_response(json.dumps(envelope))),
                            tmp_path / str(idx))
        assert raw["status"] == "run_error" and raw["api_requests"] == 0
        assert raw["run_error"]["category"] == "tool_parameter_error"
        assert raw["run_error"]["code"] in {"UNKNOWN_TOOL", "INVALID_ARGUMENTS"}


def test_repeated_unparsed_text_is_recorded_as_error_not_a_negative(tmp_path):
    raw = run_condition("P01_fixed", "T1E0", scripted(*[text_response("not JSON")] * 3), tmp_path)
    assert raw["status"] == "run_error" and raw["finding"] is None
    assert raw["run_error"]["code"] == "REPEATED_UNPARSED_TEXT"
    assert raw["model_decisions"] == 3 and raw["api_requests"] == 0


def test_evidence_gate_still_rejects_a_wrong_textual_finding(tmp_path):
    wrong = {"name": "submit_finding", "arguments": finding(["r001", "r002"])}
    corrected = finding(["r001", "r002"], verdict="not_vulnerable", kind=None)
    chat = scripted(
        native_tool("send_request", {"identity": "B", "method": "GET", "path": "/tickets/201"}),
        native_tool("send_request", {"identity": "A", "method": "GET", "path": "/tickets/201"}),
        text_response(json.dumps(wrong)), native_tool("submit_finding", corrected),
    )
    raw = run_condition("P01_fixed", "T0E1", chat, tmp_path)
    assert raw["status"] == "submitted" and raw["gate_rejections"] == 1
    assert raw["finding"]["verdict"] == "not_vulnerable"


def test_repeating_the_same_rejected_claim_stops_without_a_fabricated_verdict(tmp_path):
    claim = finding(["r001", "r002"])
    chat = scripted(
        native_tool("send_request", {"identity": "B", "method": "GET", "path": "/tickets/201"}),
        native_tool("send_request", {"identity": "A", "method": "GET", "path": "/tickets/201"}),
        native_tool("submit_finding", claim), native_tool("submit_finding", claim),
        native_tool("submit_finding", claim),
    )
    raw = run_condition("P01_fixed", "T0E1", chat, tmp_path)
    assert raw["status"] == "run_error" and raw["finding"] is None
    assert raw["run_error"]["code"] == "REPEATED_EVIDENCE_REJECTION"
    assert raw["gate_rejections"] == 3 and raw["model_decisions"] == 5


def test_separate_v2_manifest_and_complete_dev_grid_with_stub(tmp_path):
    # Minimal fake model: explicitly abstain after one real request. This tests
    # bookkeeping and completeness, not vulnerability-finding quality.
    def chat(**kwargs):
        history = [m for m in kwargs["messages"] if isinstance(m, dict) and m.get("role") == "tool"]
        if not history:
            return native_tool("send_request", {"identity": "A", "method": "GET",
                                                "path": "/tickets/201"})
        return native_tool("submit_finding", finding(["r001"],
                                                     verdict="insufficient_evidence", kind=None))

    root = tmp_path / "v2"
    result = run_batch("dev", 1, root, chat_fn=chat)
    assert result["new_rows"] == 16
    summary = summarize(root)
    assert summary["experiment"] == "followup-v2-text-adapter"
    assert summary["rows"] == 16 and summary["independent_pairs"] == 2
