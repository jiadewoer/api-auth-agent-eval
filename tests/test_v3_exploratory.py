"""Verify the amended lock and reserved scheduler without running reserved cases."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from v3_agent.exploratory_lock import lock_development, require_lock
from v3_agent.freeze_dev import freeze_development
from v3_agent.model_client import MODEL_DIGEST_PREFIX
from v3_agent.run_ab_dev import run_development
from v3_agent.run_ab_eval import EVAL_PAIRS, REPEATS, pending_file, planned_keys, result_rows, run_evaluation
from v3_agent.run_dev import deterministic_stub
from v3_agent.runner import PROMPTS


def _baseline_stalls_after_real_read(**kwargs):
    baseline = PROMPTS["A"].read_text(encoding="utf-8").strip()
    if kwargs["messages"][0]["content"] != baseline:
        return deterministic_stub(**kwargs)
    actual_requests = [m for m in kwargs["messages"]
                       if isinstance(m, dict) and m.get("role") == "tool"
                       and m.get("tool_name") == "send_request"]
    if not actual_requests:
        return deterministic_stub(**kwargs)
    return SimpleNamespace(message=SimpleNamespace(content="stalled", tool_calls=[]))


def test_post_dev_amendment_retains_zero_submission_baseline(tmp_path):
    dev = tmp_path / "dev"
    summary = run_development(output=dev, provider="ollama",
                              chat_fn=_baseline_stalls_after_real_read,
                              runtime={"provider": "synthetic_test_only",
                                       "model_digest": MODEL_DIGEST_PREFIX + "a" * 52})
    assert summary["rows"] == 8 and summary["run_errors"] == 4
    with pytest.raises(ValueError, match="Condition A has no completed"):
        freeze_development(dev)
    lock = lock_development(dev)
    assert lock["post_dev_amendment"] is True
    assert lock["original_freeze_passed"] is False
    assert lock["submitted_and_failures"]["A"]["submitted"] == 0
    assert lock["submitted_and_failures"]["A"]["run_errors"] == 4
    assert lock["submitted_and_failures"]["B"]["submitted"] == 4
    assert require_lock(dev) == lock_development(dev)
    path = dev / "results.jsonl"
    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace("\n", " \n", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        require_lock(dev)


def test_reserved_plan_is_48_distinct_keys_and_balances_order():
    keys = planned_keys()
    assert len(keys) == len(set(keys)) == 48
    assert len(EVAL_PAIRS) == 6 and REPEATS == 2
    assert all(not key[0].startswith(("T01_", "E01_")) for key in keys)
    assert {key[2] for key in keys} == {0, 1}
    assert [key[1] for key in keys[:2]] == ["A", "B"]
    assert [key[1] for key in keys[2:4]] == ["B", "A"]
    assert [key[1] for key in keys[24:26]] == ["B", "A"]
    assert len([key for key in keys if key[1] == "A"]) == 24
    assert len([key for key in keys if key[1] == "B"]) == 24


def test_result_integrity_and_pending_marker_prevent_silent_retries(tmp_path):
    out = tmp_path / "eval"
    out.mkdir()
    key = planned_keys()[0]
    for name in ("result.json", "trace.jsonl", "grade.json", "case.sqlite"):
        (out / name).write_text("{}", encoding="utf-8")
    row = {"case_id": key[0], "condition": key[1], "repeat_index": key[2],
           "manifest_sha256": "manifest", "status": "run_error", "run_id": "run-1",
           "db_path": str(out / "case.sqlite"), "result_path": str(out / "result.json"),
           "log_path": str(out / "trace.jsonl"), "grade_path": str(out / "grade.json")}
    path = out / "results.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert result_rows(out, "manifest")[key]["status"] == "run_error"
    pending = pending_file(out, planned_keys()[1])
    assert pending.name.startswith("pending_")
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed reserved result row 2"):
        result_rows(out, "manifest")


def test_uncommitted_attempt_stops_before_model_call(tmp_path, monkeypatch):
    import v3_agent.run_ab_eval as module

    dev, out = tmp_path / "dev", tmp_path / "eval"
    dev.mkdir()
    out.mkdir()
    (out / "experiment_manifest.json").write_text("{}", encoding="utf-8")
    pending_file(out, planned_keys()[0]).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(module, "ensure_eval_manifest", lambda *_args: {})
    monkeypatch.setattr(module, "local_chat", lambda: pytest.fail("model must not be called"))
    with pytest.raises(ValueError, match="Uncommitted attempt"):
        run_evaluation(dev_input=dev, output=out)


def test_reserved_summary_keeps_24_run_denominators_and_type_errors(tmp_path, monkeypatch):
    import v3_agent.summarize_eval as module

    out = tmp_path / "eval"
    out.mkdir()
    manifest = {"dev_lock_path": str(tmp_path / "dev" / "exploratory_dev_lock.json")}
    (out / "experiment_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (out / "results.jsonl").write_text("synthetic-only\n", encoding="utf-8")
    rows = {}
    for case_id, condition, repeat in planned_keys():
        positive = case_id.endswith("_vuln")
        baseline = condition == "A"
        rows[(case_id, condition, repeat)] = {
            "case_id": case_id, "condition": condition,
            "status": "run_error" if baseline else "submitted",
            "run_error": {"category": "model_output_error"} if baseline else None,
            "finding": None if baseline else {
                "verdict": "vulnerable" if positive else "not_vulnerable"},
            "verdict_correct": (not positive) if not baseline else None,
            "evidence_valid": not baseline,
            "false_positive": False, "classification_error": positive and not baseline,
            "abstained": False, "state_changed_by_A": positive and not baseline,
            "mutation_preempted_by_control": False, "api_requests": 3,
            "duration_s": 1.0, "gate_rejections": 1 if baseline else 0,
        }
    monkeypatch.setattr(module, "expected_manifest", lambda _dev: manifest)
    monkeypatch.setattr(module, "result_rows", lambda *_args: rows)
    summary = module.summarize(out)
    assert summary["planned_runs"] == 48 and summary["independent_pairs"] == 6
    assert summary["per_condition"]["A"]["run_errors"] == [24, 24]
    b = summary["per_condition"]["B"]
    assert b["submitted"] == [24, 24]
    assert b["valid_evidence_among_vulnerability_reports"] == [12, 12]
    assert b["vulnerability_detected_with_correct_type"] == [0, 12]
    assert b["classification_errors"] == 12
    assert b["attributable_A_write_changes_on_vulnerable_write_cases"] == [8, 8]
