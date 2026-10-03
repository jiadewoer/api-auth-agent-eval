"""Resumable sequential runner: case -> fresh lab -> trace -> independent grade.

One JSONL row per (case_id, agent_name, repeat_index). Failures are retained;
this command deliberately does not retry them in the same output directory.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from agent.runner import local_chat, run_case
from eval.grade import GRADER_VERSION, grade_run
from eval.manifest import runtime_manifest


def _now() -> str:
    return datetime.now().astimezone().isoformat()


def _write_json_atomic(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _manifest(root: Path, split: str, planned_repeats: int) -> dict:
    path = root / "experiment_manifest.json"
    expected = runtime_manifest(split, planned_repeats)
    if path.exists():
        old = json.loads(path.read_text(encoding="utf-8"))
        for key in (
            "agents", "model_tag", "model_digest_prefix", "temperature", "num_ctx",
            "tool_spec_sha256", "request_limit", "decision_limit", "timeout_seconds",
            "grader_version", "cases", "runs_per_case", "selected_split",
            "python_version", "dependency_versions", "source_sha256",
        ):
            if old[key] != expected[key]:
                raise ValueError(f"Manifest differs at {key}; choose a new --output")
        return old
    _write_json_atomic(path, expected)
    return expected


def _completed(path: Path) -> set[tuple[str, str, int]]:
    if not path.exists():
        return set()
    keys: set[tuple[str, str, int]] = set()
    lines = path.read_bytes().splitlines(keepends=True)
    valid_bytes = 0
    for lineno, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
            key = (row["case_id"], row["agent_name"], row["repeat_index"])
        except (ValueError, KeyError, TypeError) as error:
            if lineno == len(lines) and not line.endswith(b"\n"):
                # A hard stop during append can leave one unfinished final row.
                # Preserve its bytes and resume from the last complete JSONL row.
                backup = path.with_name(path.name + ".partial." + uuid4().hex[:12])
                backup.write_bytes(line)
                with path.open("r+b") as stream:
                    stream.truncate(valid_bytes)
                    stream.flush()
                    os.fsync(stream.fileno())
                break
            raise ValueError(f"Broken JSONL result at line {lineno}") from error
        if key in keys:
            raise ValueError(f"Duplicate case/agent/repeat key at line {lineno}")
        keys.add(key)
        valid_bytes += len(line)
        if lineno == len(lines) and not line.endswith(b"\n"):
            with path.open("ab") as stream:
                stream.write(b"\n")
                stream.flush()
                os.fsync(stream.fileno())
    return keys


def _runner_failure(case_id: str, agent_name: str, repeat_index: int,
                    error: Exception) -> dict:
    return {
        "case_id": case_id, "agent_name": agent_name, "repeat_index": repeat_index,
        "run_id": None, "agent_status": "run_error", "status": "run_error",
        "run_error": {"category": "runner_exception", "code": "RUNNER_EXCEPTION:" + type(error).__name__},
        "finding": None, "grade": None,
        "log_path": None, "db_path": None, "result_path": None,
    }


def _record_invocation(root: Path, summary: dict) -> None:
    with (root / "invocations.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(summary, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_batch(
    split: str, agent_name: str, repeats: int, output: str | Path,
    chat_fn: Callable[..., Any] | None = None,
    runtime_metadata: dict | None = None,
    planned_repeats: int | None = None,
) -> dict:
    if split not in {"dev", "holdout"} or agent_name not in {"baseline", "evidence", "both"}:
        raise ValueError("Choose dev/holdout and baseline/evidence/both")
    if repeats < 1:
        raise ValueError("--repeats must be positive")
    planned_repeats = repeats if planned_repeats is None else planned_repeats
    if planned_repeats < repeats:
        raise ValueError("--planned-repeats must be at least --repeats")
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    manifest = _manifest(root, split, planned_repeats)
    rows_path = root / "results.jsonl"
    done = _completed(rows_path)
    if chat_fn is None:
        chat_fn, runtime_metadata = local_chat()
    new_rows = skipped = errors = requests = 0
    invocation_id, started_at = uuid4().hex[:12], _now()
    agents = ("baseline", "evidence") if agent_name == "both" else (agent_name,)

    for case_id in manifest["cases"][split]:
        for repeat_index in range(repeats):
          for selected_agent in agents:
            key = (case_id, selected_agent, repeat_index)
            if key in done:
                skipped += 1
                continue
            try:
                # run_case seeds a fresh SQLite database and creates a fresh message list.
                run = run_case(case_id, chat_fn, root / "runs",
                               agent_name=selected_agent, runtime_metadata=runtime_metadata)
                rows = [json.loads(line) for line in Path(run["log_path"]).read_text(encoding="utf-8").splitlines()]
                try:
                    grade = grade_run(run, rows)  # The only step that reads private truth.
                    effective_error = grade["run_error"]
                except Exception as error:
                    effective_error = {"category": "grader_error", "code": "GRADER_EXCEPTION:" + type(error).__name__}
                    grade = {"grader_version": GRADER_VERSION, "run_error": effective_error,
                             "verdict_correct": None, "evidence_valid": False}
                result = {
                    "case_id": case_id, "agent_name": selected_agent,
                    "repeat_index": repeat_index, "run_id": run["run_id"],
                    "agent_status": run["status"],
                    "status": "run_error" if effective_error else "graded",
                    "run_error": effective_error, "finding": run["finding"],
                    "grade": grade, "log_path": run["log_path"],
                    "db_path": run["db_path"], "result_path": run["result_path"],
                }
                digest = (run.get("runtime") or {}).get("model_digest")
                if digest:
                    if manifest["actual_model_digest"] and digest != manifest["actual_model_digest"]:
                        raise ValueError("Model digest changed during experiment")
                    if not manifest["actual_model_digest"]:
                        manifest["actual_model_digest"] = digest
                        _write_json_atomic(root / "experiment_manifest.json", manifest)
            except Exception as error:
                result = _runner_failure(case_id, selected_agent, repeat_index, error)

            result["invocation_id"] = invocation_id
            result["recorded_at"] = _now()

            with rows_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(result, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            done.add(key)
            new_rows += 1
            errors += result["status"] == "run_error"
            requests += (result.get("grade") or {}).get("api_requests", 0)
            if result["status"] == "run_error" and (
                result["run_error"] or {}).get("category") in {
                    "runner_exception", "grader_error", "lab_exception",
                    "model_service_unavailable", "model_version_mismatch",
                }:
                message = (f"System failure saved for {key}: {result['run_error']}. "
                           "Stop; inspect it and restart the full formal A/B run in a new directory.")
                _record_invocation(root, {
                    "output": str(root), "run_invocation_id": invocation_id,
                    "started_at": started_at, "ended_at": _now(),
                    "new_rows": new_rows, "skipped": skipped,
                    "errors": errors, "api_requests": requests,
                    "aborted_reason": message,
                })
                raise RuntimeError(message)

    summary = {
        "output": str(root), "manifest_path": str(root / "experiment_manifest.json"),
        "results_path": str(rows_path), "new_rows": new_rows,
        "skipped": skipped, "errors": errors, "api_requests": requests,
        "run_invocation_id": invocation_id, "started_at": started_at,
        "ended_at": _now(),
    }
    _record_invocation(root, summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Sequential, resumable controlled evaluation")
    parser.add_argument("--split", choices=("dev", "holdout"), required=True)
    parser.add_argument("--agent", choices=("baseline", "evidence", "both"), required=True)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--planned-repeats", type=int,
                        help="Frozen final number of repeats; set to 2 on day 18 and day 19")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run_batch(args.split, args.agent, args.repeats, args.output,
                       planned_repeats=args.planned_repeats)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
