"""Interleave A/B on two development pairs; never select reserved evaluation cases."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping

from v3_agent.dev_manifest import CONDITIONS, DEV_CASE_IDS, ensure_manifest
from v3_agent.grade import grade_run
from v3_agent.run_dev import deterministic_stub
from v3_agent.runner import run_case


def planned_keys() -> list[tuple[str, str, int]]:
    return [(case_id, condition, 0)
            for index, case_id in enumerate(DEV_CASE_IDS)
            for condition in (CONDITIONS if index % 2 == 0 else CONDITIONS[::-1])]


def _result_rows(path: Path, fingerprint: str) -> dict[tuple[str, str, int], dict]:
    existing = {}
    if not path.exists():
        return existing
    planned = set(planned_keys())
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("Result row is not an object")
            key = row["case_id"], row["condition"], row["repeat_index"]
            if not (isinstance(key[0], str) and isinstance(key[1], str)
                    and type(key[2]) is int):
                raise ValueError("Invalid result key types")
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"Malformed result row {number}; stop instead of silently skipping") from exc
        if key not in planned or key in existing or row.get("manifest_sha256") != fingerprint:
            raise ValueError(f"Unexpected/duplicate key or manifest hash at result row {number}")
        for field in ("result_path", "log_path", "grade_path"):
            try:
                exists = Path(row[field]).is_file()
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"Invalid {field} in result row {number}") from exc
            if not exists:
                raise ValueError(f"Missing {field} for result row {number}")
        existing[key] = row
    return existing


def run_development(
    *, output: str | Path, provider: str,
    chat_fn: Callable[..., Any] | None = None,
    runtime: Mapping[str, Any] | None = None,
) -> dict:
    target = Path(output)
    manifest = ensure_manifest(target, provider)
    fingerprint = sha256((target / "experiment_manifest.json").read_bytes()).hexdigest()
    results_path = target / "results.jsonl"
    existing = _result_rows(results_path, fingerprint)
    if chat_fn is None:
        if provider == "ollama":
            from v3_agent.model_client import local_chat
            chat_fn, runtime = local_chat()
            runtime["provider"] = "ollama"
        else:
            chat_fn, runtime = deterministic_stub, {"provider": "deterministic_stub"}
    if runtime is None:
        runtime = {"provider": provider}
    new_rows = 0
    for case_id, condition, repeat_index in planned_keys():
        key = (case_id, condition, repeat_index)
        if key in existing:
            continue  # Failures are also immutable observations, not selected for rerun.
        record = run_case(case_id, chat_fn, target, runtime=runtime, condition=condition)
        trace = [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]
        grade = grade_run(record, trace)
        grade_path = target / f"grade_{record['run_id']}.json"
        grade_path.write_text(json.dumps(grade, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        row = {
            "case_id": case_id, "condition": condition, "repeat_index": repeat_index,
            "run_id": record["run_id"], "public_task_id": record["public_task_id"],
            "status": record["status"], "run_error": record["run_error"],
            "finding": record["finding"],
            "verdict_correct": grade["verdict_correct"], "evidence_valid": grade["evidence_valid"],
            "false_positive": grade["false_positive"], "false_negative": grade["false_negative"],
            "classification_error": grade["classification_error"], "abstained": grade["abstained"],
            "state_changed_by_A": grade["state_changed_by_A"],
            "mutation_preempted_by_control": grade["mutation_preempted_by_control"],
            "api_requests": record["api_requests"], "model_decisions": record["model_decisions"],
            "gate_rejections": record["gate_rejections"], "duration_s": record["duration_s"],
            "model_digest": record["runtime"].get("model_digest"),
            "log_path": record["log_path"], "result_path": record["result_path"],
            "grade_path": str(grade_path), "manifest_sha256": fingerprint,
        }
        with results_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        existing[key] = row
        new_rows += 1
    failures = [r for r in existing.values() if r["status"] == "run_error"]
    return {"output": str(target), "provider": provider, "split": manifest["split"],
            "rows": len(existing), "new_rows": new_rows, "skipped": len(existing)-new_rows,
            "run_errors": len(failures),
            "error_categories": dict(Counter((r["run_error"] or {}).get("category") for r in failures)),
            "results_path": str(results_path), "manifest_path": str(target / "experiment_manifest.json")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("stub", "ollama"), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary = run_development(output=args.output, provider=args.provider)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if summary["run_errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
