"""The formal schedule and completeness checks use a fake chat, not model scores."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from eval.preflight import check
from eval.run_cases import run_batch
from eval.summarize import summarize


def call(name, arguments):
    return SimpleNamespace(message=SimpleNamespace(
        content="", tool_calls=[SimpleNamespace(
            function=SimpleNamespace(name=name, arguments=arguments))]))


def scripted_chat(*, model, messages, tools, options):
    task = json.loads(messages[1]["content"])
    seen = [json.loads(m["content"]) for m in messages
            if isinstance(m, dict) and m.get("role") == "tool"]
    path, method = task["target_path"], task["target_method"]
    if not seen:
        legal_identity = "B" if path.startswith("/tickets/") else "M"
        legal_path = "/tickets/201" if method == "POST" else path
        return call("send_request", {"identity": legal_identity,
                                     "method": "GET", "path": legal_path})
    if len(seen) == 1:
        args = {"identity": "A", "method": method, "path": path}
        if path.endswith("/reassign"):
            args["json_body"] = {"new_owner_id": "A"}
        return call("send_request", args)
    positive = seen[-1]["status_code"] == 200
    kind = "BOLA" if path.startswith("/tickets/") and not path.endswith("/reassign") else "BFLA"
    resource = ("ticket_comments_201" if path.endswith("/comments") else
                "admin_export" if path.endswith("/export") else
                "admin_audit" if path.endswith("/audit") else "ticket_201")
    return call("submit_finding", {
        "verdict": "vulnerable" if positive else "not_vulnerable",
        "vulnerability_type": kind if positive else None,
        "identity": "A", "resource": resource,
        "evidence_request_ids": [seen[-1]["request_id"]],
        "explanation": "scripted test only",
    })


def test_two_day_schedule_checks_32_rows_and_resumes(tmp_path):
    dev, formal = tmp_path / "dev", tmp_path / "formal"
    run_batch("dev", "both", 1, dev, chat_fn=scripted_chat)
    assert check(dev, formal)["ok"] is True
    first = run_batch("holdout", "both", 1, formal, chat_fn=scripted_chat,
                      planned_repeats=2)
    assert first["new_rows"] == 16 and first["errors"] == 0
    with pytest.raises(ValueError, match="Expected 32"):
        summarize(formal)
    second = run_batch("holdout", "both", 2, formal, chat_fn=scripted_chat,
                       planned_repeats=2)
    assert second["new_rows"] == 16 and second["skipped"] == 16
    assert run_batch("holdout", "both", 2, formal, chat_fn=scripted_chat,
                     planned_repeats=2)["new_rows"] == 0
    rows = [json.loads(line) for line in (formal / "results.jsonl").read_text().splitlines()]
    assert len(rows) == 32
    assert [(r["case_id"], r["agent_name"]) for r in rows[:4]] == [
        ("P02_vuln", "baseline"), ("P02_vuln", "evidence"),
        ("P02_fixed", "baseline"), ("P02_fixed", "evidence")]
    summary = summarize(formal)
    for agent in ("baseline", "evidence"):
        assert summary["agents"][agent]["vulnerability_detected"] == [8, 8]
        assert summary["agents"][agent]["paired_correct"] == [8, 8]
        assert summary["agents"][agent]["valid_evidence_among_vulnerability_reports"] == [8, 8]
    assert len({r["db_path"] for r in rows}) == 32


def test_preflight_keeps_model_failures_but_blocks_system_failures(tmp_path):
    dev, formal = tmp_path / "dev", tmp_path / "formal"

    def sometimes_no_conclusion(*, model, messages, tools, options):
        task = json.loads(messages[1]["content"])
        evidence_prompt = "逐项核对" in messages[0]["content"]
        if task["public_task_id"] == "TASK-9C4" and evidence_prompt:
            return SimpleNamespace(message=SimpleNamespace(content="plain text", tool_calls=[]))
        return scripted_chat(model=model, messages=messages, tools=tools, options=options)

    run_batch("dev", "both", 1, dev, chat_fn=sometimes_no_conclusion)
    gated = check(dev, formal)
    assert gated["ok"] is True
    assert gated["dev_graded"] == 6
    assert gated["dev_agent_failures"] == {"no_conclusion": 2}

    path = dev / "results.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    failed = next(row for row in rows if row["status"] == "run_error")
    failed["run_error"] = {"category": "lab_exception", "code": "HTTP_EXCEPTION:RuntimeError"}
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="system or unrecorded failure"):
        check(dev, formal)


def test_resume_rejects_changed_planned_repeat_count(tmp_path):
    root = tmp_path / "formal"
    run_batch("holdout", "both", 1, root, chat_fn=scripted_chat,
              planned_repeats=2)
    with pytest.raises(ValueError, match="Manifest differs"):
        run_batch("holdout", "both", 2, root, chat_fn=scripted_chat,
                  planned_repeats=3)


def test_summary_rejects_foreign_trace(tmp_path):
    root = tmp_path / "formal"
    run_batch("holdout", "both", 2, root, chat_fn=scripted_chat,
              planned_repeats=2)
    rows = [json.loads(line) for line in (root / "results.jsonl").read_text().splitlines()]
    log = Path(rows[0]["log_path"])
    trace = [json.loads(line) for line in log.read_text().splitlines()]
    trace[0]["run_id"] = rows[1]["run_id"]
    log.write_text("\n".join(json.dumps(t) for t in trace) + "\n")
    with pytest.raises(ValueError, match="Mixed request trace"):
        summarize(root)
