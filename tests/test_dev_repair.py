"""Reproduce the two distinct mistakes observed in the user's P01 dev trace."""

import json
from pathlib import Path
from types import SimpleNamespace

from agent.config import PROMPTS
from agent.runner import run_case
from eval.grade import grade_run


def call(name, arguments):
    return SimpleNamespace(message=SimpleNamespace(
        content="", tool_calls=[SimpleNamespace(
            function=SimpleNamespace(name=name, arguments=arguments))]))


def mistaken_chat(*, model, messages, tools, options):
    seen = [json.loads(item["content"]) for item in messages
            if isinstance(item, dict) and item.get("role") == "tool"]
    if not seen:
        return call("send_request", {"identity": "A", "method": "GET", "path": "/tickets/201"})
    return call("submit_finding", {
        "verdict": "not_vulnerable", "vulnerability_type": None,
        "identity": "A", "resource": "/tickets/201",
        "evidence_request_ids": [seen[0]["request_id"]],
        "explanation": "A saw B's private body, but I concluded no vulnerability",
    })


def test_path_resource_rejected_and_wrong_verdict_is_separate_error(tmp_path):
    bad_shape = run_case("P01_vuln", mistaken_chat, tmp_path / "bad")
    assert bad_shape["run_error"]["code"] == "INVALID_FINDING"

    def correct_shape_wrong_decision(**kwargs):
        reply = mistaken_chat(**kwargs)
        arguments = reply.message.tool_calls[0].function.arguments
        if reply.message.tool_calls[0].function.name == "submit_finding":
            arguments["resource"] = "ticket_201"
        return reply

    wrong_decision = run_case("P01_vuln", correct_shape_wrong_decision, tmp_path / "wrong")
    trace = [json.loads(line) for line in Path(wrong_decision["log_path"]).read_text().splitlines()]
    score = grade_run(wrong_decision, trace)
    assert wrong_decision["status"] == "submitted"
    assert score["verdict_correct"] is False
    assert score["evidence_valid"] is False


def test_ab_prompts_have_identical_shared_instructions():
    a = PROMPTS["baseline"].read_text(encoding="utf-8")
    b = PROMPTS["evidence"].read_text(encoding="utf-8")
    assert b.startswith(a)
