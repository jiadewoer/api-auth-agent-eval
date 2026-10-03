"""A/B dev runs are paired, isolated, resumable, and never silently retried."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from v3_agent.dev_manifest import DEV_CASE_IDS, snapshot
from v3_agent.freeze_dev import freeze_development
from v3_agent.model_client import MODEL_DIGEST_PREFIX
from v3_agent.run_ab_dev import planned_keys, run_development
from v3_agent.run_dev import deterministic_stub
from v3_agent.runner import PROMPTS, run_case
from v3_agent.summarize_dev import summarize


def _rows(directory: Path) -> list[dict]:
    return [json.loads(line) for line in (directory / "results.jsonl").read_text(encoding="utf-8").splitlines()]


def test_prompts_differ_by_one_sentence_and_manifest_locks_common_settings():
    a = PROMPTS["A"].read_text(encoding="utf-8").splitlines()
    b = PROMPTS["B"].read_text(encoding="utf-8").splitlines()
    assert b[:-1] == a and len(b) == len(a) + 1
    assert "B" in b[-1] and "A" in b[-1] and "POST" in b[-1]
    assert "vuln" not in "\n".join(b).lower() and "fixed" not in "\n".join(b).lower()
    manifest = snapshot("stub")
    assert manifest["split"] == "dev" and manifest["cases"] == list(DEV_CASE_IDS)
    assert manifest["conditions"] == ["A", "B"]
    assert manifest["prompt_sha256"]["A"] != manifest["prompt_sha256"]["B"]
    assert manifest["api_request_limit"] == 8 and manifest["model_decision_limit"] == 16
    assert manifest["shared_evidence_gate"] and manifest["shared_text_adapter"]


def test_eight_interleaved_runs_have_fresh_state_and_resume_without_overwrite(tmp_path):
    out = tmp_path / "dev"
    first = run_development(output=out, provider="stub")
    assert first["rows"] == first["new_rows"] == 8
    assert first["run_errors"] == 0
    rows = _rows(out)
    assert [(row["case_id"], row["condition"], row["repeat_index"]) for row in rows] == planned_keys()
    assert len({row["run_id"] for row in rows}) == len({row["result_path"] for row in rows}) == 8
    assert len({json.loads(Path(row["result_path"]).read_text(encoding="utf-8"))["db_path"]
                for row in rows}) == 8
    assert all(row["verdict_correct"] is True and row["evidence_valid"] for row in rows)
    assert all(row["api_requests"] == 3 and row["status"] == "submitted" for row in rows)
    summary = summarize(out)["per_condition"]
    for condition in ("A", "B"):
        assert summary[condition]["vulnerability_detected"] == [2, 2]
        assert summary[condition]["fixed_false_positives"] == [0, 2]
        assert summary[condition]["paired_correct"] == [2, 2]
        assert summary[condition]["run_errors"] == [0, 4]
        assert summary[condition]["mean_api_requests"] == 3
    saved_bytes = (out / "results.jsonl").read_bytes()
    second = run_development(output=out, provider="stub")
    assert second["rows"] == second["skipped"] == 8 and second["new_rows"] == 0
    assert (out / "results.jsonl").read_bytes() == saved_bytes


def test_manifest_mismatch_rejects_provider_and_changed_config(tmp_path):
    out = tmp_path / "dev"
    run_development(output=out, provider="stub")
    with pytest.raises(ValueError, match="Manifest mismatch"):
        run_development(output=out, provider="ollama", chat_fn=deterministic_stub)
    path = out / "experiment_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["api_request_limit"] = 12
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="Manifest mismatch"):
        run_development(output=out, provider="stub")


def test_model_errors_are_retained_in_results_and_not_selected_for_retry(tmp_path):
    out = tmp_path / "dev"

    def unavailable(**_kwargs):
        raise ConnectionError("local service unavailable")

    first = run_development(output=out, provider="stub", chat_fn=unavailable)
    assert first["run_errors"] == 8 and first["error_categories"] == {"model_service_unavailable": 8}
    rows = _rows(out)
    assert all(row["status"] == "run_error" and row["verdict_correct"] is None
               and row["api_requests"] == 0 for row in rows)
    second = run_development(output=out, provider="stub", chat_fn=deterministic_stub)
    assert second["new_rows"] == 0 and second["skipped"] == 8
    assert _rows(out) == rows
    for condition in ("A", "B"):
        assert summarize(out)["per_condition"][condition]["run_errors"] == [4, 4]
    with pytest.raises(ValueError):
        freeze_development(out)  # A deterministic or broken dev run cannot be a formal freeze.


def test_interrupted_dev_run_can_append_only_missing_keys(tmp_path, monkeypatch):
    import v3_agent.run_ab_dev as module

    out = tmp_path / "dev"
    real_run_case = module.run_case
    attempts = 0

    def interrupt_after_two(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 3:
            raise KeyboardInterrupt("interrupted")
        return real_run_case(*args, **kwargs)

    monkeypatch.setattr(module, "run_case", interrupt_after_two)
    with pytest.raises(KeyboardInterrupt):
        run_development(output=out, provider="stub")
    assert len(_rows(out)) == 2
    monkeypatch.setattr(module, "run_case", real_run_case)
    summary = run_development(output=out, provider="stub")
    assert summary["new_rows"] == 6 and summary["skipped"] == 2
    assert len(_rows(out)) == 8


def test_b_public_messages_have_no_internal_case_or_truth(tmp_path):
    captured = []

    def stop_after_first_model_step(**kwargs):
        captured.append(kwargs["messages"])
        raise ConnectionError("stop once prompt is captured")

    record = run_case("E01_vuln", stop_after_first_model_step, tmp_path, condition="B")
    assert record["status"] == "run_error"
    messages = json.dumps(captured[0], ensure_ascii=False).lower()
    for hidden in ("e01_vuln", "e01_fixed", "ground_truth", "truth.json", "expense-token-a"):
        assert hidden not in messages
    assert record["config"]["prompt_sha256"] == snapshot("stub")["prompt_sha256"]["B"]


def test_freeze_gate_accepts_complete_synthetic_fixture_but_never_labels_it_real(tmp_path):
    # A unit-test fixture simulates a populated runtime digest. It never calls Ollama
    # and its synthetic metrics must never be reported as a real-model experiment.
    out = tmp_path / "synthetic-ollama-fixture"
    run_development(output=out, provider="ollama", chat_fn=deterministic_stub,
                    runtime={"provider": "synthetic_test_only",
                             "model_digest": MODEL_DIGEST_PREFIX + "synthetic-test-only"})
    frozen = freeze_development(out)
    assert frozen["rows"] == 8
    assert frozen["submitted_by_condition"] == {"A": 4, "B": 4}
    assert freeze_development(out) == frozen
    result_path = out / "results.jsonl"
    current = result_path.read_text(encoding="utf-8")
    result_path.write_text(current.replace("\n", " \n", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="Frozen dev manifest differs"):
        freeze_development(out)
