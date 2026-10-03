"""Resumable, balanced 2x2 follow-up runner; no old result is overwritten."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from agent.config import MODEL, MODEL_DIGEST_PREFIX, NUM_CTX, TEMPERATURE, PROMPTS
from agent.runner import local_chat
from cases.catalog import public_spec_for_case
from eval.grade import GRADER_VERSION, grade_run
from eval.manifest import FROZEN_FILES
from followup.conditions import CONDITIONS, model_tools
from followup.runner import run_condition


DEV = ("P01_vuln", "P01_fixed", "P04_vuln", "P04_fixed")
REUSED = tuple(f"{pair}_{variant}" for pair in ("P02", "P03", "P05", "P06")
               for variant in ("vuln", "fixed"))
SOURCE_FILES = (*FROZEN_FILES, "agent/prompts/baseline.txt",
                "followup/conditions.py", "followup/gate.py",
                "followup/runner.py", "followup/run.py", "followup/summarize.py")


def _hashes() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    return {name: sha256((root / name).read_bytes()).hexdigest()
            for name in SOURCE_FILES}


def _manifest(split: str, planned_repeats: int) -> dict:
    root = Path(__file__).resolve().parents[1]
    original = json.loads((root / "summary.json").read_text(encoding="utf-8"))["manifest"]
    current_hashes = _hashes()
    for name, old in original["source_sha256"].items():
        if current_hashes[name] != old:
            raise ValueError(f"Old frozen A/B source changed: {name}")
    schemas = {name: sha256(json.dumps(model_tools(condition),
                     ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
               for name, condition in CONDITIONS.items()}
    prompt = PROMPTS["baseline"].read_text(encoding="utf-8").strip()
    return {
        "experiment": "followup-v1", "split": split,
        "case_ids": list(DEV if split == "dev" else REUSED),
        "reused_cases_are_not_untouched_holdout": split == "reused",
        "conditions": {name: {"guided_schema": condition.guided_schema,
                               "evidence_gate": condition.evidence_gate,
                               "model_tool_schema_sha256": schemas[name]}
                       for name, condition in CONDITIONS.items()},
        "prompt_sha256": sha256(prompt.encode("utf-8")).hexdigest(),
        "model": MODEL, "model_digest_prefix": MODEL_DIGEST_PREFIX,
        "temperature": TEMPERATURE, "num_ctx": NUM_CTX,
        "request_limit": 8, "decision_limit": 16,
        "grader_version": GRADER_VERSION,
        "source_sha256": current_hashes,
        "planned_repeats": planned_repeats,
    }


def run_batch(
    split: str, repeats: int, output: str | Path,
    *, planned_repeats: int | None = None,
    chat_fn: Callable[..., Any] | None = None,
    runtime_metadata: dict | None = None,
) -> dict:
    if split not in ("dev", "reused") or repeats < 1:
        raise ValueError("Choose --split dev|reused and --repeats >= 1")
    planned = repeats if planned_repeats is None else planned_repeats
    if planned < repeats:
        raise ValueError("Planned repeats must be >= runs requested")
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    expected = _manifest(split, planned)
    mpath = root / "manifest.json"
    if mpath.exists():
        old = json.loads(mpath.read_text(encoding="utf-8"))
        if {k: v for k, v in old.items() if k not in {"created_at", "actual_model_digest"}} != expected:
            raise ValueError("Frozen condition, prompt or code changed: use a new output directory")
        manifest = old
    else:
        manifest = {**expected, "created_at": datetime.now().astimezone().isoformat(),
                    "actual_model_digest": None}
        mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    rows_path = root / "results.jsonl"
    old_rows = [json.loads(s) for s in rows_path.read_text(encoding="utf-8").splitlines()] if rows_path.exists() else []
    old_keys = [(r["case_id"], r["condition"], r["repeat_index"]) for r in old_rows]
    if len(set(old_keys)) != len(old_keys):
        raise ValueError("Duplicate condition/case/repeat in existing results")
    done = set(old_keys)
    if chat_fn is None:
        chat_fn, runtime_metadata = local_chat()
    new_rows = skipped = errors = 0
    for case_id in expected["case_ids"]:
        for repeat in range(repeats):
            # Rotate the first arm by case/repeat to reduce order bias.
            arms = list(CONDITIONS)
            shift = (expected["case_ids"].index(case_id) + repeat) % len(arms)
            arms = arms[shift:] + arms[:shift]
            for condition in arms:
                key = (case_id, condition, repeat)
                if key in done:
                    skipped += 1
                    continue
                raw = run_condition(case_id, condition, chat_fn, root / "runs",
                                    runtime_metadata=runtime_metadata)
                trace = [json.loads(s) for s in Path(raw["log_path"]).read_text(encoding="utf-8").splitlines()]
                grade = grade_run(raw, trace)
                digest = (raw.get("runtime") or {}).get("model_digest")
                if digest:
                    if manifest["actual_model_digest"] and manifest["actual_model_digest"] != digest:
                        raise ValueError("Model digest changed: stop and use a new output directory")
                    if not manifest["actual_model_digest"]:
                        manifest["actual_model_digest"] = digest
                        mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
                row = {
                    "case_id": case_id, "condition": condition, "repeat_index": repeat,
                    "run_id": raw["run_id"], "status": raw["status"],
                    "run_error": raw["run_error"], "finding": raw["finding"],
                    "grade": grade, "api_requests": raw["api_requests"],
                    "model_decisions": raw["model_decisions"],
                    "gate_rejections": raw["gate_rejections"],
                    "duration_s": raw["duration_s"], "log_path": raw["log_path"],
                    "result_path": raw["result_path"], "db_path": raw["db_path"],
                }
                with rows_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                done.add(key)
                new_rows += 1
                errors += raw["status"] == "run_error"
                if raw["run_error"] and raw["run_error"]["category"] in {
                    "model_service_unavailable", "model_version_mismatch",
                    "lab_exception", "model_resource_error", "model_timeout",
                }:
                    raise RuntimeError(f"System/model failure recorded for {key}: {raw['run_error']}")
    return {"output": str(root), "new_rows": new_rows, "skipped": skipped,
            "run_errors": errors, "results_path": str(rows_path)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Follow-up 2x2 experiment")
    parser.add_argument("--split", choices=("dev", "reused"), required=True)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--planned-repeats", type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(run_batch(args.split, args.repeats, args.output,
                               planned_repeats=args.planned_repeats),
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
