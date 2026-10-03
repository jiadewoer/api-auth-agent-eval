"""Run the V3-E1 reserved cases serially with immutable, resumable outcomes."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cases.v3_catalog import internal_case_for, public_spec_for_case
from v3_agent.dev_manifest import CONDITIONS, ROOT, ensure_manifest
from v3_agent.exploratory_lock import LOCK_NAME, SETUP_FAILURES, digest, require_lock
from v3_agent.grade import grade_run
from v3_agent.model_client import local_chat
from v3_agent.runner import run_case


EVAL_PAIRS = ("T02", "T03", "T04", "E02", "E03", "E04")
REPEATS = 2


def planned_keys() -> list[tuple[str, str, int]]:
    keys = []
    for repeat_index in range(REPEATS):
        for pair_index, pair in enumerate(EVAL_PAIRS):
            for variant_index, variant in enumerate(("fixed", "vuln")):
                case_id = f"{pair}_{variant}"
                order = CONDITIONS if (repeat_index + pair_index + variant_index) % 2 == 0 else CONDITIONS[::-1]
                keys.extend((case_id, condition, repeat_index) for condition in order)
    assert len(keys) == len(set(keys)) == 48
    return keys


def validate_reserved_catalog() -> None:
    for pair in EVAL_PAIRS:
        fixed, vuln = f"{pair}_fixed", f"{pair}_vuln"
        for case_id in (fixed, vuln):
            if internal_case_for(case_id)["split"] != "eval_reserved":
                raise ValueError(f"Non-reserved case in evaluation plan: {case_id}")
        if public_spec_for_case(fixed) != public_spec_for_case(vuln):
            raise ValueError(f"Public task differs across reserved pair: {pair}")


def expected_manifest(dev_dir: Path) -> dict:
    lock = require_lock(dev_dir)
    validate_reserved_catalog()
    manifest = ensure_manifest(dev_dir, "ollama")
    return {
        "schema_version": 1, "phase": "exploratory_evaluation", "protocol_id": "V3-E1",
        "provider": "ollama", "split": "reserved", "cases": [f"{p}_{v}" for p in EVAL_PAIRS
                                                 for v in ("fixed", "vuln")],
        "conditions": list(CONDITIONS), "repeats": REPEATS, "planned_runs": 48,
        "dev_lock_path": str((dev_dir / LOCK_NAME).resolve()),
        "dev_lock_sha256": digest(dev_dir / LOCK_NAME),
        "dev_manifest_sha256": lock["dev_manifest_sha256"],
        "dev_results_sha256": lock["dev_results_sha256"],
        "model": lock["model"], "model_digest": lock["model_digest"],
        "temperature": manifest["temperature"], "num_ctx": manifest["num_ctx"],
        "api_request_limit": manifest["api_request_limit"],
        "model_decision_limit": manifest["model_decision_limit"],
        "prompt_sha256": manifest["prompt_sha256"],
        "source_sha256": manifest["file_sha256"],
        "new_file_sha256": lock["new_file_sha256"],
    }


def ensure_eval_manifest(output: Path, dev_dir: Path) -> dict:
    current = expected_manifest(dev_dir)
    path = output / "experiment_manifest.json"
    if path.exists():
        stored = json.loads(path.read_text(encoding="utf-8"))
        if {k: v for k, v in stored.items() if k != "created_at"} != current:
            raise ValueError("Reserved manifest mismatch; stop instead of mixing configurations")
        return stored
    if (output / "results.jsonl").exists() or any(output.glob("pending_*.json")):
        raise ValueError("Reserved data exists without a manifest; stop")
    output.mkdir(parents=True, exist_ok=True)
    saved = {**current, "created_at": datetime.now(timezone.utc).isoformat()}
    with path.open("x", encoding="utf-8") as stream:
        json.dump(saved, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return saved


def result_rows(output: Path, fingerprint: str) -> dict[tuple[str, str, int], dict]:
    path = output / "results.jsonl"
    if not path.exists():
        return {}
    allowed = set(planned_keys())
    rows = {}
    run_ids, db_paths = set(), set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("Row must be an object")
            key = row["case_id"], row["condition"], row["repeat_index"]
            if type(key[2]) is not int or key not in allowed or key in rows:
                raise ValueError("Unexpected or duplicate reserved result key")
            if row["manifest_sha256"] != fingerprint or row["status"] not in {"submitted", "run_error"}:
                raise ValueError("Manifest hash or run status does not match")
            if row["run_id"] in run_ids or row["db_path"] in db_paths:
                raise ValueError("Run ID or database reused")
            for field in ("result_path", "log_path", "grade_path", "db_path"):
                if not Path(row[field]).is_file():
                    raise ValueError(f"Missing {field}")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"Malformed reserved result row {number}; do not retry selectively") from error
        rows[key] = row
        run_ids.add(row["run_id"])
        db_paths.add(row["db_path"])
    return rows


def pending_file(output: Path, key: tuple[str, str, int]) -> Path:
    return output / f"pending_{key[0]}_{key[1]}_{key[2]}.json"


def run_evaluation(*, dev_input: str | Path, output: str | Path) -> dict:
    dev_dir, target = Path(dev_input).resolve(), Path(output).resolve()
    if dev_dir == target:
        raise ValueError("Development and reserved directories must be separate")
    ensure_eval_manifest(target, dev_dir)
    fingerprint = digest(target / "experiment_manifest.json")
    existing = result_rows(target, fingerprint)
    for key in planned_keys():
        if key not in existing and pending_file(target, key).exists():
            raise ValueError(f"Uncommitted attempt for {key}; inspect its artifacts before continuing")
    if len(existing) == 48:
        return _progress(target, new_rows=0, existing=existing)
    chat_fn, runtime = local_chat()
    if runtime.get("model_digest") != require_lock(dev_dir)["model_digest"]:
        raise ValueError("Actual Ollama digest changed since development; no reserved run made")
    runtime["provider"] = "ollama"
    new_rows = 0
    for key in planned_keys():
        if key in existing:
            continue  # Failure records are immutable and never selectively retried.
        pending = pending_file(target, key)
        with pending.open("x", encoding="utf-8") as stream:
            json.dump({"case_id": key[0], "condition": key[1], "repeat_index": key[2],
                       "started_at": datetime.now(timezone.utc).isoformat()}, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        record = run_case(key[0], chat_fn, target, runtime=runtime, condition=key[1])
        trace = [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]
        grade = grade_run(record, trace)
        grade_path = target / f"grade_{record['run_id']}.json"
        with grade_path.open("x", encoding="utf-8") as stream:
            json.dump(grade, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        row = {
            "case_id": key[0], "condition": key[1], "repeat_index": key[2],
            "run_id": record["run_id"], "public_task_id": record["public_task_id"],
            "status": record["status"], "run_error": record["run_error"],
            "finding": record["finding"],
            "verdict_correct": grade["verdict_correct"], "evidence_valid": grade["evidence_valid"],
            "evidence_reasons": grade["evidence_reasons"],
            "false_positive": grade["false_positive"], "false_negative": grade["false_negative"],
            "classification_error": grade["classification_error"], "abstained": grade["abstained"],
            "state_changed_by_A": grade["state_changed_by_A"],
            "mutation_preempted_by_control": grade["mutation_preempted_by_control"],
            "api_requests": record["api_requests"], "model_decisions": record["model_decisions"],
            "gate_rejections": record["gate_rejections"], "duration_s": record["duration_s"],
            "model_digest": record["runtime"].get("model_digest"),
            "log_path": record["log_path"], "db_path": record["db_path"],
            "result_path": record["result_path"], "grade_path": str(grade_path),
            "manifest_sha256": fingerprint,
        }
        with (target / "results.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        pending.unlink()
        existing[key] = row
        new_rows += 1
        print(f"[{len(existing)}/48] {key[0]} {key[1]} repeat={key[2]} "
              f"status={row['status']} error={(row['run_error'] or {}).get('code')}",
              flush=True)
        if (row["run_error"] or {}).get("category") in SETUP_FAILURES:
            raise RuntimeError("A service/lab failure was recorded; paused reserved runs. "
                               "Keep this row and diagnose the setup before resuming.")
    return _progress(target, new_rows=new_rows, existing=existing)


def _progress(output: Path, *, new_rows: int, existing: dict) -> dict:
    errors = [r for r in existing.values() if r["status"] == "run_error"]
    return {
        "phase": "exploratory_evaluation", "output": str(output), "planned": 48,
        "rows": len(existing), "new_rows": new_rows, "skipped": len(existing)-new_rows,
        "run_errors": len(errors),
        "error_categories": dict(Counter((r["run_error"] or {}).get("category") for r in errors)),
        "results_path": str(output / "results.jsonl"),
        "manifest_path": str(output / "experiment_manifest.json"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dev-input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary = run_evaluation(dev_input=args.dev_input, output=args.output)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if summary["rows"] != 48 or summary["run_errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
