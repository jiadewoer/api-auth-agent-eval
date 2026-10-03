"""Interleaved V4 reserved evaluation; never selects development cases."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping

from v4_lab.catalog import RESERVED_CASE_IDS, RESERVED_PAIRS, public_spec_for_case, truth_for_case
from v4_lab.dev_manifest import ensure_manifest
from v4_lab.prompts import CONDITIONS
from v4_lab.run_ab_dev import deterministic_stub
from v4_lab.runner import run_case
from v4_lab.stages import score_write_stages


REPEATS = 2


def planned_keys() -> list[tuple[str, str, int]]:
    keys = []
    for repeat_index in range(REPEATS):
        for i, case_id in enumerate(RESERVED_CASE_IDS):
            offset = (i + repeat_index) % len(CONDITIONS)
            for condition in CONDITIONS[offset:] + CONDITIONS[:offset]:
                keys.append((case_id, condition, repeat_index))
    return keys


def _existing(path: Path, manifest_sha: str) -> dict[tuple[str, str, int], dict]:
    if not path.exists():
        return {}
    found = {}
    planned = set(planned_keys())
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
            key = row["case_id"], row["condition"], row["repeat_index"]
            if (key not in planned or key in found or row["manifest_sha256"] != manifest_sha
                    or any(not Path(row[name]).is_file() for name in
                           ("result_path", "log_path", "stage_path"))):
                raise ValueError("Unexpected key, hash or missing artifact")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid V4 reserved result row {line_no}; do not skip it") from exc
        found[key] = row
    return found


def _condition_summary(rows: list[dict]) -> dict:
    vulns = [row for row in rows if row["case_id"].endswith("_vuln")]
    fixed = [row for row in rows if row["case_id"].endswith("_fixed")]
    errors = [row for row in rows if row["status"] == "run_error"]
    return {
        "planned": len(rows),
        "vulnerable_rows": len(vulns),
        "fixed_rows": len(fixed),
        "stage_counts": {f"s{i}": [sum(row[f"s{i}"] for row in vulns), len(vulns)]
                         for i in range(1, 5)},
        "fixed_false_positives": [sum(row["fixed_false_positive"] for row in fixed), len(fixed)],
        "submitted": [sum(row["status"] == "submitted" for row in rows), len(rows)],
        "run_errors": [len(errors), len(rows)],
        "error_categories": dict(Counter((row["run_error"] or {}).get("category") for row in errors)),
        "mean_api_requests": round(sum(row["api_requests"] for row in rows) / len(rows), 3)
                             if rows else 0,
        "mean_duration_s": round(sum(row["duration_s"] for row in rows) / len(rows), 3)
                           if rows else 0,
        "gate_rejections": sum(row["gate_rejections"] for row in rows),
    }


def _pair_summary(rows: list[dict]) -> dict:
    result = {}
    for pair in RESERVED_PAIRS:
        pair_rows = [row for row in rows if row["case_id"].startswith(pair + "_")]
        result[pair] = {}
        for condition in CONDITIONS:
            group = [row for row in pair_rows if row["condition"] == condition]
            vulns = [row for row in group if row["case_id"].endswith("_vuln")]
            fixed = [row for row in group if row["case_id"].endswith("_fixed")]
            result[pair][condition] = {
                "vulnerable_s4": sum(row["s4"] for row in vulns),
                "fixed_false_positives": sum(row["fixed_false_positive"] for row in fixed),
                "run_errors": sum(row["status"] == "run_error" for row in group),
            }
    return result


def run_reserved(*, output: str | Path, provider: str,
                 chat_fn: Callable[..., Any] | None = None,
                 runtime: Mapping[str, Any] | None = None) -> dict:
    target = Path(output)
    manifest = ensure_manifest(target, provider, split="reserved")
    manifest_sha = sha256((target / "experiment_manifest.json").read_bytes()).hexdigest()
    results = target / "results.jsonl"
    existing = _existing(results, manifest_sha)
    if chat_fn is None:
        if provider == "ollama":
            from v3_agent.model_client import local_chat
            chat_fn, runtime = local_chat()
            runtime["provider"] = "ollama"
        else:
            chat_fn, runtime = deterministic_stub, {"provider": "deterministic_stub"}
    runtime = dict(runtime or {"provider": provider})
    new_rows = 0
    for index, (case_id, condition, repeat_index) in enumerate(planned_keys(), 1):
        key = case_id, condition, repeat_index
        if key in existing:
            continue  # Error rows are immutable observations too.
        record = run_case(case_id, chat_fn, target, runtime=runtime, condition=condition)
        trace = [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]
        score = score_write_stages(public=public_spec_for_case(case_id),
                                   truth=truth_for_case(case_id), record=record, trace=trace)
        score_path = target / f"stages_{record['run_id']}.json"
        score_path.write_text(json.dumps(score, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        row = {
            "case_id": case_id, "condition": condition, "repeat_index": repeat_index,
            "run_id": record["run_id"], "status": record["status"],
            "run_error": record["run_error"], "finding": record["finding"],
            **{f"s{i}": score[f"s{i}"] for i in range(1, 5)},
            "fixed_false_positive": score["fixed_false_positive"],
            "failure_stage": score["failure_stage"],
            "api_requests": record["api_requests"], "model_decisions": record["model_decisions"],
            "gate_rejections": record["gate_rejections"], "duration_s": record["duration_s"],
            "model_digest": record["runtime"].get("model_digest"),
            "result_path": record["result_path"], "log_path": record["log_path"],
            "stage_path": str(score_path), "manifest_sha256": manifest_sha,
        }
        with results.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        existing[key] = row
        new_rows += 1
        print(f"[{index}/{len(planned_keys())}] {case_id} {condition} repeat={repeat_index} "
              f"status={record['status']} error={(record['run_error'] or {}).get('code')}",
              flush=True)
    rows = list(existing.values())
    per_condition = {
        condition: _condition_summary([row for row in rows if row["condition"] == condition])
        for condition in CONDITIONS
    }
    errors = [row for row in rows if row["status"] == "run_error"]
    summary = {
        "phase": manifest["phase"],
        "protocol_id": "V4-R1",
        "provider": provider,
        "split": "reserved",
        "planned": len(planned_keys()),
        "rows": len(rows),
        "new_rows": new_rows,
        "skipped": len(rows) - new_rows,
        "independent_pairs": len(RESERVED_PAIRS),
        "repeats_per_case_version_condition": REPEATS,
        "run_errors": len(errors),
        "error_categories": dict(Counter((row["run_error"] or {}).get("category") for row in errors)),
        "manifest_sha256": manifest_sha,
        "results_sha256": sha256(results.read_bytes()).hexdigest() if results.exists() else None,
        "per_condition": per_condition,
        "per_pair": _pair_summary(rows),
        "output": str(target),
        "manifest_path": str(target / "experiment_manifest.json"),
        "results_path": str(results),
        "interpretation": (
            "Reserved evaluation: twelve independent pairs, not 192 independent systems. "
            "Run errors and fixed-case non-completions remain in denominators."
        ),
    }
    (target / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                                         encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("stub", "ollama"), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary = run_reserved(output=args.output, provider=args.provider)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if summary["run_errors"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
