"""Tool boundary, budgets, real routes, and audit evidence."""

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from agent.runner import run_case
from agent.tools import AgentTools
from app.main import create_app


@pytest.fixture
def lab(tmp_path):
    with TestClient(create_app("P02_vuln", tmp_path / "lab.sqlite")) as client:
        tools = AgentTools(client, tmp_path / "trace.jsonl", run_id="RUN-TEST")
        yield tools


def rows(lab):
    return [json.loads(line) for line in lab.log_path.read_text(encoding="utf-8").splitlines()]


def test_unlisted_path_is_rejected_without_request(lab):
    result = lab.send_request("A", "GET", "/cases/truth.json")
    assert result["error"]["code"] == "INVALID_ROUTE"
    assert lab.send_request("A", "GET", "http://evil.example/tickets/201")["error"]["code"] == "INVALID_ROUTE"
    assert lab.request_count == 0
    assert rows(lab)[0]["request_id"] is None
    assert rows(lab)[0]["error"] == "INVALID_ROUTE"
    assert set(rows(lab)[0]) == {
        "run_id", "step", "tool_name", "arguments", "identity", "request_id",
        "response_status", "response_body", "elapsed_ms", "error",
    }


def test_invalid_identity_is_rejected_without_request(lab):
    result = lab.send_request("Z", "GET", "/tickets/201/comments")
    assert result["error"]["code"] == "INVALID_IDENTITY"
    assert lab.request_count == 0
    assert rows(lab)[0]["response_status"] is None


def test_eight_real_requests_then_ninth_rejected(lab):
    for number in range(1, 9):
        got = lab.send_request("B", "GET", "/tickets/201/comments")
        assert got["request_id"] == f"r{number:03d}"
        assert got["status_code"] == 200
    assert lab.send_request("B", "GET", "/tickets/201/comments")["error"]["code"] == "REQUEST_LIMIT"
    assert lab.request_count == 8
    # Inspecting an already observed result is a tool call, not another API request.
    assert lab.inspect_response("r001")["body"][0]["body"] == "comment-private-201"
    assert lab.request_count == 8


def test_uses_current_case_real_route_not_canned_reply(tmp_path):
    for variant, expected in (("P02_vuln", 200), ("P02_fixed", 403)):
        with TestClient(create_app(variant, tmp_path / f"{variant}.sqlite")) as client:
            tools = AgentTools(client, tmp_path / f"{variant}.jsonl")
            got = tools.send_request("A", "GET", "/tickets/201/comments")
            assert got["status_code"] == expected
            if expected == 200:
                assert got["body"][0]["body"] == "comment-private-201"
            else:
                assert "comment-private-201" not in str(got["body"])
            assert json.loads(tools.log_path.read_text(encoding="utf-8"))["response_status"] == expected


def test_extra_args_large_body_and_token_are_recorded_safely(lab):
    extra = lab.dispatch("send_request", {
        "identity": "A", "method": "GET", "path": "/tickets/201", "host": "evil.example",
    })
    assert extra["error"]["code"] == "INVALID_ARGUMENTS"
    assert lab.send_request("A", "GET", "/tickets/201", host="evil.example")["error"]["code"] == "INVALID_ARGUMENTS"
    big = lab.send_request("A", "POST", "/tickets/201/reassign", {
        "new_owner_id": "A", "padding": "x" * 1200,
        "sensitive": "lab-token-a",
    })
    assert big["error"]["code"] == "BODY_TOO_LARGE"
    assert lab.request_count == 0
    assert "lab-token-a" not in lab.log_path.read_text(encoding="utf-8")


def test_submit_checks_real_evidence_and_stops(lab):
    assert lab.submit_finding("vulnerable", "BOLA", "A", "ticket_201", ["made-up"], "found it")["error"]["code"] == "UNKNOWN_EVIDENCE"
    request = lab.send_request("A", "GET", "/tickets/201/comments")
    assert lab.submit_finding("vulnerable", "BOLA", "A", "ticket_201", [request["request_id"]], "A read B comments") == {"accepted": True}
    assert lab.submitted
    assert lab.send_request("B", "GET", "/tickets/201/comments")["error"]["code"] == "ALREADY_SUBMITTED"
    assert lab.request_count == 1
    assert rows(lab)[-2]["tool_name"] == "submit_finding"


def test_model_decision_limit_and_exception_logged_separately(lab):
    for _ in range(16):
        assert lab.model_step(lambda: "ok") == "ok"
    with pytest.raises(RuntimeError, match="limit"):
        lab.model_step(lambda: "should never run")
    assert lab.decision_count == 16
    assert rows(lab)[-1]["error"] == "DECISION_LIMIT"


def test_model_timeout_is_logged_without_consuming_api_requests(lab):
    class LocalTimeout(Exception):
        pass

    def timed_out():
        raise LocalTimeout("temporary failure")

    with pytest.raises(LocalTimeout):
        lab.model_step(timed_out)
    assert lab.decision_count == 1
    assert lab.request_count == 0
    assert rows(lab)[-1]["tool_name"] == "model_decision"
    assert rows(lab)[-1]["error"] == "MODEL_TIMEOUT"


def test_runner_submits_after_real_tool_result_and_leaves_labels_out_of_prompt(tmp_path):
    prompts = []

    def fake_chat(*, model, messages, tools, options):
        prompts.append(messages)
        if len(prompts) == 1:
            assert "P02_vuln" not in json.dumps(messages, ensure_ascii=False)
            args = {"identity": "A", "method": "GET", "path": "/tickets/201/comments"}
            name = "send_request"
        else:
            actual = json.loads(messages[-1]["content"])
            assert actual["status_code"] == 200
            assert actual["body"][0]["body"] == "comment-private-201"
            args = {"verdict": "vulnerable", "vulnerability_type": "BOLA",
                    "identity": "A", "resource": "ticket_201",
                    "evidence_request_ids": [actual["request_id"]], "explanation": "A read B's comment"}
            name = "submit_finding"
        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=args))
        return SimpleNamespace(message=SimpleNamespace(role="assistant", content="", tool_calls=[call]))

    result = run_case("P02_vuln", fake_chat, tmp_path)
    assert result["status"] == "submitted"
    assert result["api_requests"] == 1
    assert result["model_decisions"] == 2
    assert result["finding"]["verdict"] == "vulnerable"
    assert result["db_path"] != result["log_path"]
    assert [json.loads(line)["tool_name"] for line in (tmp_path / f"agent_{result['run_id']}.jsonl").read_text(encoding="utf-8").splitlines()] == [
        "model_decision", "send_request", "model_decision", "submit_finding"
    ]
