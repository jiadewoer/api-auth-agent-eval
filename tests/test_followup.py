"""Meaningful controls for the two follow-up interventions, without Ollama."""

from __future__ import annotations

import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.main import create_app
from cases.catalog import public_spec_for_case
from followup.conditions import CONDITIONS, model_tools
from followup.gate import FollowupTools
from followup.run import run_batch
from followup.runner import run_condition
from followup.summarize import summarize


def _finding(verdict, kind, resource, ids):
    return dict(verdict=verdict, vulnerability_type=kind, identity="A",
                resource=resource, evidence_request_ids=ids,
                explanation="Conclusion from cited requests")


def _tool(name, args):
    call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=args))
    return SimpleNamespace(message=SimpleNamespace(role="assistant", content="", tool_calls=[call]))


def _scripted_chat(*, model, messages, tools, options):
    """Stub chooses by public task and observations, never by hidden case ID."""
    public = json.loads(messages[1]["content"])
    path, method = public["target_path"], public["target_method"]
    legal = "M" if path.startswith("/admin/") or path.endswith("/reassign") else "B"
    history = [json.loads(m["content"]) for m in messages
               if isinstance(m, dict) and m.get("role") == "tool"]
    if method == "POST":
        read_path = "/tickets/201"
        if len(history) == 0:
            return _tool("send_request", dict(identity=legal, method="GET",
                                              path=read_path, json_body=None))
        if len(history) == 1:
            body = {"new_owner_id": "A"} if path.endswith("/reassign") else None
            return _tool("send_request", dict(identity="A", method="POST",
                                              path=path, json_body=body))
        if len(history) == 2:
            return _tool("send_request", dict(identity=legal, method="GET",
                                              path=read_path, json_body=None))
        before, candidate, after = history[:3]
        field = "owner_id" if path.endswith("/reassign") else "status"
        changed = before["body"][field] != after["body"][field]
        verdict = "vulnerable" if changed and candidate["status_code"] == 200 else "not_vulnerable"
    else:
        if len(history) == 0:
            return _tool("send_request", dict(identity=legal, method="GET",
                                              path=path, json_body=None))
        if len(history) == 1:
            return _tool("send_request", dict(identity="A", method="GET",
                                              path=path, json_body=None))
        candidate = history[1]
        verdict = "vulnerable" if candidate["status_code"] == 200 else "not_vulnerable"
    kind = ("BFLA" if path.startswith("/admin/") or path.endswith("/reassign")
            else "BOLA") if verdict == "vulnerable" else None
    target = public["target_object"]["kind"]
    resource = ("ticket_comments_201" if target == "ticket_comments" else
                "ticket_201" if target == "ticket" else target)
    return _tool("submit_finding", _finding(verdict, kind, resource,
                                             [r["request_id"] for r in history[:3 if method == "POST" else 2]]))


def test_t_only_changes_schema_and_never_the_backend():
    base, guided = model_tools(CONDITIONS["T0E0"]), model_tools(CONDITIONS["T1E0"])
    assert base != guided
    assert [x["function"]["name"] for x in base] == [x["function"]["name"] for x in guided]
    b = next(x["function"] for x in base if x["function"]["name"] == "send_request")
    g = next(x["function"] for x in guided if x["function"]["name"] == "send_request")
    assert "json_body" not in b["parameters"]["required"]
    assert "json_body" in g["parameters"]["required"]
    assert '"new_owner_id":"A"' in g["description"]


def test_e_gate_blocks_a_false_positive_then_accepts_correct_finding(tmp_path):
    public = public_spec_for_case("P02_fixed")
    with TestClient(create_app("P02_fixed", tmp_path / "lab.sqlite")) as client:
        tools = FollowupTools(client, tmp_path / "trace.jsonl", public=public, evidence_gate=True)
        control = tools.send_request("B", "GET", "/tickets/201/comments")
        denied = tools.send_request("A", "GET", "/tickets/201/comments")
        ids = [control["request_id"], denied["request_id"]]
        wrong = tools.submit_finding(**_finding("vulnerable", "BOLA", "ticket_comments_201", ids))
        assert wrong["error"]["code"] == "EVIDENCE_CHECK_FAILED"
        assert tools.gate_rejections == 1 and not tools.submitted
        assert tools.request_count == 2  # A rejected submission is not an API request.
        assert tools.submit_finding(**_finding("not_vulnerable", None, "ticket_comments_201", ids)) == {"accepted": True}


def test_e_gate_rejects_200_write_with_no_visible_state_change(tmp_path):
    public = public_spec_for_case("P03_vuln")
    with TestClient(create_app("P03_vuln", tmp_path / "lab.sqlite")) as client:
        tools = FollowupTools(client, tmp_path / "trace.jsonl", db_path=tmp_path / "lab.sqlite",
                              public=public, evidence_gate=True)
        # A legitimate write contaminates the target before A attempts it.
        tools.send_request("B", "POST", "/tickets/201/close")
        before = tools.send_request("B", "GET", "/tickets/201")
        candidate = tools.send_request("A", "POST", "/tickets/201/close")
        after = tools.send_request("B", "GET", "/tickets/201")
        assert candidate["status_code"] == 200
        assert before["body"]["status"] == after["body"]["status"] == "closed"
        ids = [before["request_id"], candidate["request_id"], after["request_id"]]
        result = tools.submit_finding(**_finding("vulnerable", "BOLA", "ticket_201", ids))
        assert result["error"]["code"] == "EVIDENCE_CHECK_FAILED"


def test_e_gate_accepts_visible_write_change_without_truth_lookup(tmp_path):
    public = public_spec_for_case("P05_vuln")
    with TestClient(create_app("P05_vuln", tmp_path / "lab.sqlite")) as client:
        tools = FollowupTools(client, tmp_path / "trace.jsonl", db_path=tmp_path / "lab.sqlite",
                              public=public, evidence_gate=True)
        before = tools.send_request("M", "GET", "/tickets/201")
        candidate = tools.send_request("A", "POST", "/tickets/201/reassign", {"new_owner_id": "A"})
        after = tools.send_request("M", "GET", "/tickets/201")
        ids = [before["request_id"], candidate["request_id"], after["request_id"]]
        assert tools.submit_finding(**_finding("vulnerable", "BFLA", "ticket_201", ids)) == {"accepted": True}
        assert tools.gate_rejections == 0


def test_four_arms_are_independent_and_truth_is_not_in_model_messages(tmp_path):
    seen = []

    def chat(**kwargs):
        content = json.dumps(kwargs["messages"], ensure_ascii=False, default=str)
        assert "P01_vuln" not in content and "ground_truth" not in content
        seen.append(kwargs["tools"])
        return _scripted_chat(**kwargs)

    for arm in CONDITIONS:
        record = run_condition("P01_vuln", arm, chat, tmp_path / arm)
        assert record["status"] == "submitted" and record["api_requests"] == 2
        assert record["finding"]["verdict"] == "vulnerable"
        assert record["config"]["condition"] == arm
    assert seen


def test_batch_resume_and_summary_on_dev_with_stub(tmp_path):
    root = tmp_path / "dev"
    first = run_batch("dev", 1, root, planned_repeats=2, chat_fn=_scripted_chat)
    assert first["new_rows"] == 16 and first["skipped"] == 0
    second = run_batch("dev", 2, root, planned_repeats=2, chat_fn=_scripted_chat)
    assert second["new_rows"] == 16 and second["skipped"] == 16
    report = summarize(root)
    assert report["rows"] == 32 and report["independent_pairs"] == 2
    for arm in CONDITIONS:
        assert report["per_condition"][arm]["vulnerability_detected"] == [4, 4]
        assert report["per_condition"][arm]["fixed_false_positives"] == [0, 4]
