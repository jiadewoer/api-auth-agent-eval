"""Interleaved 2×2 V4 development run; only T05/T06/E05/E06, never reserved."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from v4_lab.catalog import DEV_CASE_IDS, public_spec_for_case, truth_for_case
from v4_lab.dev_manifest import ensure_manifest
from v4_lab.prompts import CONDITIONS
from v4_lab.runner import run_case
from v4_lab.stages import score_write_stages


def planned_keys() -> list[tuple[str, str, int]]:
    return [(case_id, condition, 0)
            for i, case_id in enumerate(DEV_CASE_IDS)
            for condition in CONDITIONS[i % 4:] + CONDITIONS[:i % 4]]


def _native(name: str, arguments: dict) -> Any:
    return SimpleNamespace(message=SimpleNamespace(
        content="", tool_calls=[SimpleNamespace(function=SimpleNamespace(
            name=name, arguments=arguments))]))


def deterministic_stub(*, messages: list, **_kwargs: Any) -> Any:
    """Public-task-only plumbing driver; its accuracy says nothing about a model."""
    public = json.loads(messages[1]["content"])
    tools = [(m["tool_name"], json.loads(m["content"])) for m in messages
             if isinstance(m, dict) and m.get("role") == "tool"]
    if not tools:
        return _native("read_api_spec", {})
    requests = [row for name, row in tools if name == "send_request" and "error" not in row]
    if len(requests) == 0:
        return _native("send_request", {"identity": public["control_identity"],
                                        "method": "GET", "path": public["control_path"],
                                        "json_body": None})
    if len(requests) == 1:
        return _native("send_request", {"identity": "A", "method": public["target_method"],
                                        "path": public["target_path"],
                                        "json_body": public["request_body"]})
    if len(requests) == 2:
        return _native("send_request", {"identity": public["control_identity"],
                                        "method": "GET", "path": public["control_path"],
                                        "json_body": None})
    field = public["target_object"]["field"]
    before, after = requests[0]["body"][field], requests[2]["body"][field]
    succeeded = requests[1]["status_code"] == 200 and before != after
    denied = requests[1]["status_code"] == 403 and before == after
    verdict = "vulnerable" if succeeded else "not_vulnerable" if denied else "insufficient_evidence"
    policy = public["visible_policy"]
    role_only = any(marker in policy for marker in (
        "仅管理员", "只给管理员", "管理员 M",
        "仅财务", "只开放给财务", "财务 M", "专属功能",
    ))
    kind = ("BFLA" if role_only else "BOLA") if succeeded else None
    return _native("submit_finding", {
        "verdict": verdict, "vulnerability_type": kind,
        "identity": "A", "resource": f"{public['target_object']['kind']}_{public['target_object']['id']}",
        "evidence_request_ids": [item["request_id"] for item in requests],
        "explanation": "Deterministic driver compared the visible target field before and after the HTTP request.",
    })


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
            raise ValueError(f"Invalid V4 result row {line_no}; do not skip it") from exc
        found[key] = row
    return found


def run_development(*, output: str | Path, provider: str,
                    chat_fn: Callable[..., Any] | None = None,
                    runtime: Mapping[str, Any] | None = None) -> dict:
    target = Path(output)
    manifest = ensure_manifest(target, provider)
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
    for case_id, condition, repeat_index in planned_keys():
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
    per_condition = {}
    for condition in CONDITIONS:
        rows = [row for row in existing.values() if row["condition"] == condition]
        vulns = [row for row in rows if row["case_id"].endswith("_vuln")]
        per_condition[condition] = {
            "planned": len(DEV_CASE_IDS), "rows": len(rows), "vulnerable_rows": len(vulns),
            "stage_counts": {f"s{i}": [sum(row[f"s{i}"] for row in vulns), len(vulns)]
                             for i in range(1, 5)},
            "fixed_false_positives": sum(row["fixed_false_positive"] for row in rows),
            "run_errors": sum(row["status"] == "run_error" for row in rows),
        }
    errors = [row for row in existing.values() if row["status"] == "run_error"]
    return {"phase": manifest["phase"], "provider": provider, "split": "dev",
            "planned": len(planned_keys()), "rows": len(existing), "new_rows": new_rows,
            "skipped": len(existing)-new_rows, "run_errors": len(errors),
            "error_categories": dict(Counter((row["run_error"] or {}).get("category") for row in errors)),
            "per_condition": per_condition, "output": str(target),
            "manifest_path": str(target / "experiment_manifest.json"),
            "results_path": str(results)}


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
