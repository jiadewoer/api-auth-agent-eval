"""Completeness checks and separate outcome counts for the new four arms."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from followup.conditions import CONDITIONS
from followup_v2.run import DEV, REUSED, _manifest


def summarize(root: str | Path) -> dict:
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    split, repeats = manifest["split"], manifest["planned_repeats"]
    expected_manifest = _manifest(split, repeats)
    if any(manifest.get(k) != v for k, v in expected_manifest.items()):
        raise ValueError("Current code or frozen experiment parameters differ from run")
    rows = [json.loads(s) for s in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    case_ids = DEV if split == "dev" else REUSED
    keys = [(r["case_id"], r["condition"], r["repeat_index"]) for r in rows]
    expected = {(case, arm, rep) for case in case_ids for arm in CONDITIONS
                for rep in range(repeats)}
    if len(keys) != len(expected) or set(keys) != expected:
        raise ValueError(f"Incomplete/duplicate experiment: expected {len(expected)} rows, got {len(keys)}")
    if len({r["run_id"] for r in rows}) != len(rows):
        raise ValueError("A run ID was reused")
    if len({r["db_path"] for r in rows}) != len(rows):
        raise ValueError("A database was reused")
    for r in rows:
        for field in ("log_path", "db_path", "result_path"):
            if not Path(r[field]).is_file():
                raise ValueError(f"Missing {field} for {r['run_id']}")
        raw = json.loads(Path(r["result_path"]).read_text(encoding="utf-8"))
        if any(raw[k] != r[k] for k in ("run_id", "case_id", "condition", "finding")):
            raise ValueError(f"Mixed raw result: {r['run_id']}")
        trace = [json.loads(s) for s in Path(r["log_path"]).read_text(encoding="utf-8").splitlines()]
        if not trace or any(event["run_id"] != r["run_id"] for event in trace):
            raise ValueError(f"Missing/mixed trace: {r['run_id']}")
    result = {"experiment": manifest["experiment"], "split": split,
              "reused_cases_are_not_untouched_holdout": split == "reused",
              "rows": len(rows), "independent_pairs": len(case_ids) // 2,
              "per_condition": {}}
    for arm in CONDITIONS:
        group = [r for r in rows if r["condition"] == arm]
        vuln = [r for r in group if r["case_id"].endswith("_vuln")]
        fixed = [r for r in group if r["case_id"].endswith("_fixed")]
        report = [r for r in group if r["status"] == "submitted"
                  and (r["finding"] or {}).get("verdict") == "vulnerable"]
        by_key = {(r["case_id"], r["repeat_index"]): r for r in group}
        paired = sum(
            all(by_key[(f"{case.split('_')[0]}_{variant}", rep)]["grade"]["verdict_correct"] is True
                for variant in ("vuln", "fixed"))
            for case in case_ids if case.endswith("_vuln") for rep in range(repeats)
        )
        errors = Counter((r["run_error"] or {}).get("category") for r in group
                         if r["status"] == "run_error")
        result["per_condition"][arm] = {
            "vulnerability_detected": [sum(r["grade"]["verdict_correct"] is True for r in vuln), len(vuln)],
            "fixed_false_positives": [sum(r["grade"]["false_positive"] for r in fixed), len(fixed)],
            "correct_with_valid_evidence": [sum(r["grade"]["verdict_correct"] is True
                                                and r["grade"]["evidence_valid"] is True
                                                for r in vuln), len(vuln)],
            "valid_evidence_among_vulnerability_reports": [sum(r["grade"]["evidence_valid"] is True
                                                               for r in report), len(report)],
            "paired_correct": [paired, len(vuln)],
            "run_errors": [sum(r["status"] == "run_error" for r in group), len(group)],
            "error_categories": dict(errors),
            "gate_rejections": sum(r["gate_rejections"] for r in group),
            "mean_api_requests": round(sum(r["api_requests"] for r in group) / len(group), 3),
            "mean_model_decisions": round(sum(r["model_decisions"] for r in group) / len(group), 3),
            "mean_duration_s": round(sum(r["duration_s"] for r in group) / len(group), 3),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a complete follow-up set")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = summarize(args.input)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"checked_rows": result["rows"], "summary": str(target)},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
