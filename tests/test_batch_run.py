"""End-to-end dev batch uses real lab responses with deterministic fake chat."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.runner import run_case
from eval.grade import grade_run
from eval.manifest import manifest_template
from eval.run_cases import run_batch


def call(name, arguments):
    item = SimpleNamespace(function=SimpleNamespace(name=name, arguments=arguments))
    return SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[item]))


def evidence_chat(*, model, messages, tools, options):
    task = json.loads(messages[1]["content"])
    assert "case_id" not in task
    seen = [json.loads(m["content"]) for m in messages
            if isinstance(m, dict) and m.get("role") == "tool"]
    path = task["target_path"]
    if not seen:
        identity = "B" if path.startswith("/tickets/") else "M"
        return call("send_request", {"identity": identity, "method": "GET", "path": path})
    if len(seen) == 1:
        return call("send_request", {"identity": "A", "method": "GET", "path": path})
    marker = "b-private-201" if path.startswith("/tickets/") else "comment-private-301"
    leaked = marker in json.dumps(seen[1]["body"], ensure_ascii=False)
    return call("submit_finding", {
        "verdict": "vulnerable" if leaked else "not_vulnerable",
        "vulnerability_type": ("BOLA" if path.startswith("/tickets/") else "BFLA") if leaked else None,
        "identity": "A", "resource": "ticket_201" if path.startswith("/tickets/") else "admin_export",
        "evidence_request_ids": [seen[0]["request_id"], seen[1]["request_id"]],
        "explanation": f"Checked observed content {marker}" if leaked else "A denied after legal control",
    })


def test_dev_batch_resumes_and_keeps_ab_only_prompt_change(tmp_path):
    stored_template = json.loads((Path(__file__).resolve().parents[1] / "eval" /
                                  "experiment_manifest.json").read_text(encoding="utf-8"))
    assert stored_template == manifest_template()
    root = tmp_path / "dev"
    first = run_batch("dev", "baseline", 1, root, chat_fn=evidence_chat)
    assert first["new_rows"] == 4 and first["skipped"] == 0
    again = run_batch("dev", "baseline", 1, root, chat_fn=evidence_chat)
    assert again["new_rows"] == 0 and again["skipped"] == 4
    second = run_batch("dev", "evidence", 1, root, chat_fn=evidence_chat)
    assert second["new_rows"] == 4 and second["skipped"] == 0
    rows = [json.loads(line) for line in Path(first["results_path"]).read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 8
    assert len({(r["case_id"], r["agent_name"], r["repeat_index"]) for r in rows}) == 8
    assert all(r["status"] == "graded" and r["grade"]["verdict_correct"] is True
               and r["grade"]["evidence_valid"] is True for r in rows)
    assert len({r["run_id"] for r in rows}) == 8
    assert len({r["db_path"] for r in rows}) == 8

    a = json.loads(Path(rows[0]["result_path"]).read_text(encoding="utf-8"))["config"]
    b = json.loads(Path(rows[4]["result_path"]).read_text(encoding="utf-8"))["config"]
    assert a["prompt_sha256"] != b["prompt_sha256"]
    for key in ("model", "model_digest_prefix", "temperature", "num_ctx",
                "request_limit", "decision_limit", "timeout_seconds", "tool_spec_sha256"):
        assert a[key] == b[key]
    manifest = json.loads(Path(first["manifest_path"]).read_text(encoding="utf-8"))
    assert manifest["selected_split"] == "dev" and manifest["runs_per_case"] == 1
    with pytest.raises(ValueError, match="Manifest differs"):
        run_batch("dev", "baseline", 2, root, chat_fn=evidence_chat)


def test_failed_run_is_saved_and_skipped_on_resume(tmp_path):
    def timeout(**_kwargs):
        raise TimeoutError("simulated timeout")

    root = tmp_path / "failures"
    run_batch("dev", "baseline", 1, root, chat_fn=timeout)
    resumed = run_batch("dev", "baseline", 1, root, chat_fn=evidence_chat)
    assert resumed["new_rows"] == 0 and resumed["skipped"] == 4
    rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 4
    assert all(row["status"] == "run_error" and row["grade"]["verdict_correct"] is None
               for row in rows)
    assert all(Path(row["result_path"]).exists() for row in rows)


def test_incomplete_last_jsonl_line_is_preserved_and_resumed(tmp_path):
    root = tmp_path / "interrupted"
    first = run_batch("dev", "baseline", 1, root, chat_fn=evidence_chat)
    with Path(first["results_path"]).open("ab") as stream:
        stream.write(b'{"case_id":')  # Simulate a process killed in the middle of append.
    resumed = run_batch("dev", "baseline", 1, root, chat_fn=evidence_chat)
    assert resumed["new_rows"] == 0 and resumed["skipped"] == 4
    assert len(Path(first["results_path"]).read_text(encoding="utf-8").splitlines()) == 4
    backups = list(root.glob("results.jsonl.partial.*"))
    assert len(backups) == 1 and backups[0].read_bytes() == b'{"case_id":'


def test_real_post_uses_private_before_after_snapshot_not_response_text(tmp_path):
    def close_then_submit(*, model, messages, tools, options):
        seen = [json.loads(m["content"]) for m in messages
                if isinstance(m, dict) and m.get("role") == "tool"]
        if not seen:
            return call("send_request", {"identity": "A", "method": "POST",
                                         "path": "/tickets/201/close"})
        return call("submit_finding", {
            "verdict": "vulnerable", "vulnerability_type": "BOLA",
            "identity": "A", "resource": "ticket_201",
            "evidence_request_ids": [seen[-1]["request_id"]],
            "explanation": "A closed B's ticket",
        })

    run = run_case("P03_vuln", close_then_submit, tmp_path)
    obs = run["write_observations"]
    assert len(obs) == 1
    assert (obs[0]["before"], obs[0]["after"], obs[0]["field"]) == ("open", "closed", "status")
    log_text = Path(run["log_path"]).read_text(encoding="utf-8")
    assert "write_observations" not in log_text  # The model did not see private oracle data.
    graded = grade_run(run, [json.loads(line) for line in log_text.splitlines()])
    assert graded["verdict_correct"] is True and graded["evidence_valid"] is True
