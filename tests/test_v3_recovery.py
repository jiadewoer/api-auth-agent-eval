"""A rejected tool call is visible, bounded, and never silently corrected."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from v3_agent.run_dev import _native, deterministic_stub
from v3_agent.runner import MAX_TOOL_REJECTIONS, run_case


@pytest.mark.parametrize("condition", ["A", "B"])
def test_invalid_get_route_can_be_corrected_by_model(tmp_path, condition):
    injected = False

    def chat(**kwargs):
        nonlocal injected
        messages = kwargs["messages"]
        has_spec = any(isinstance(m, dict) and m.get("tool_name") == "read_api_spec"
                       for m in messages)
        if has_spec and not injected:
            injected = True
            return _native("send_request", {
                "identity": "B", "method": "GET",
                "path": "/claims/501/change_payee", "json_body": None,
            })
        return deterministic_stub(**kwargs)

    record = run_case("E01_vuln", chat, tmp_path / condition, condition=condition)
    trace = [json.loads(line) for line in Path(record["log_path"]).read_text().splitlines()]
    rejected = [e for e in trace if e["tool_name"] == "send_request"
                and e["error"] == "INVALID_ROUTE"]
    assert len(rejected) == 1
    assert rejected[0]["request_id"] is None
    assert record["status"] == "submitted"
    assert record["api_requests"] == 3
    assert record["finding"]["verdict"] == "vulnerable"


def test_repeated_invalid_calls_remain_a_recorded_failure(tmp_path):
    attempts = 0

    def chat(**_kwargs):
        nonlocal attempts
        attempts += 1
        return _native("send_request", {
            "identity": "B", "method": "GET",
            "path": "/claims/501/change_payee", "json_body": None,
        })

    record = run_case("E01_fixed", chat, tmp_path)
    trace = [json.loads(line) for line in Path(record["log_path"]).read_text().splitlines()]
    assert record["status"] == "run_error"
    assert record["run_error"]["code"] == "INVALID_ROUTE"
    assert record["api_requests"] == 0
    assert attempts == MAX_TOOL_REJECTIONS
    assert sum(e["tool_name"] == "send_request" and e["error"] == "INVALID_ROUTE" for e in trace) == attempts


def test_bare_verdict_is_prompted_to_use_submit_tool(tmp_path):
    seen = []

    def chat(**kwargs):
        seen.append(list(kwargs["messages"]))
        if len(seen) == 1:
            return SimpleNamespace(message=SimpleNamespace(
                content="insufficient_evidence", tool_calls=[]))
        raise ConnectionError("stop after inspecting the feedback")

    record = run_case("T01_fixed", chat, tmp_path)
    assert record["status"] == "run_error"
    assert len(seen) == 2
    assert "submit_finding" in seen[1][-1]["content"]
    assert "vulnerability_type" in seen[1][-1]["content"]
