"""Summarize all 48 V3-E1 reserved runs; count failures in planned denominators."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from statistics import mean

from v3_agent.dev_manifest import CONDITIONS
from v3_agent.exploratory_lock import digest
from v3_agent.run_ab_eval import EVAL_PAIRS, REPEATS, expected_manifest, planned_keys, result_rows


WRITE_PAIRS = frozenset({"T02", "T03", "E02", "E03"})


def summarize(output: str | Path) -> dict:
    directory = Path(output).resolve()
    manifest_path = directory / "experiment_manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Reserved experiment manifest is missing")
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    dev_dir = Path(saved["dev_lock_path"]).parent
    current = expected_manifest(dev_dir)
    if {k: v for k, v in saved.items() if k != "created_at"} != current:
        raise ValueError("Reserved experiment configuration changed")
    rows = result_rows(directory, digest(manifest_path))
    if set(rows) != set(planned_keys()):
        raise ValueError(f"Reserved results incomplete: {len(rows)}/48; do not report a partial sample")
    per_condition = {}
    per_pair = {}
    for condition in CONDITIONS:
        subset = [r for r in rows.values() if r["condition"] == condition]
        positives = [r for r in subset if r["case_id"].endswith("_vuln")]
        negatives = [r for r in subset if r["case_id"].endswith("_fixed")]
        vulnerability_reports = [r for r in subset
                                 if (r.get("finding") or {}).get("verdict") == "vulnerable"]
        write_positives = [r for r in positives if r["case_id"].split("_")[0] in WRITE_PAIRS]
        errors = [r for r in subset if r["status"] == "run_error"]
        paired = sum(
            rows[(f"{pair}_fixed", condition, repeat)]["verdict_correct"] is True
            and rows[(f"{pair}_vuln", condition, repeat)]["verdict_correct"] is True
            for pair in EVAL_PAIRS for repeat in range(REPEATS)
        )
        paired_with_evidence = sum(
            all(rows[(f"{pair}_{variant}", condition, repeat)]["verdict_correct"] is True
                and rows[(f"{pair}_{variant}", condition, repeat)]["evidence_valid"] is True
                for variant in ("fixed", "vuln"))
            for pair in EVAL_PAIRS for repeat in range(REPEATS)
        )
        per_condition[condition] = {
            "planned_runs": 24, "vulnerability_detected_with_correct_type": [
                sum(r["verdict_correct"] is True for r in positives), 12],
            "vulnerability_detected_with_correct_type_and_evidence": [
                sum(r["verdict_correct"] is True and r["evidence_valid"] is True
                    for r in positives), 12],
            "fixed_false_positives": [sum(r["false_positive"] is True for r in negatives), 12],
            "paired_correct": [paired, 12],
            "paired_correct_with_evidence": [paired_with_evidence, 12],
            "valid_evidence_among_vulnerability_reports": [
                sum(r["evidence_valid"] is True for r in vulnerability_reports),
                len(vulnerability_reports)],
            "vulnerable_reports_with_valid_evidence_before_type_check": [
                sum((r.get("finding") or {}).get("verdict") == "vulnerable"
                    and r["evidence_valid"] is True for r in positives), 12],
            "classification_errors": sum(r["classification_error"] is True for r in subset),
            "abstentions": sum(r["abstained"] is True for r in subset),
            "submitted": [sum(r["status"] == "submitted" for r in subset), 24],
            "run_errors": [len(errors), 24],
            "error_categories": dict(Counter(
                (r.get("run_error") or {}).get("category") for r in errors)),
            "attributable_A_write_changes_on_vulnerable_write_cases": [
                sum(r["state_changed_by_A"] is True for r in write_positives), 8],
            "control_preempted_target_write": sum(
                r["mutation_preempted_by_control"] is True for r in subset),
            "mean_api_requests": round(mean(r["api_requests"] for r in subset), 3),
            "mean_duration_s": round(mean(r["duration_s"] for r in subset), 3),
            "gate_rejections": sum(r["gate_rejections"] for r in subset),
        }
    for pair in EVAL_PAIRS:
        per_pair[pair] = {condition: {
            "vulnerable_correct": sum(rows[(f"{pair}_vuln", condition, repeat)]["verdict_correct"] is True
                                      for repeat in range(REPEATS)),
            "fixed_false_positives": sum(rows[(f"{pair}_fixed", condition, repeat)]["false_positive"] is True
                                         for repeat in range(REPEATS)),
            "paired_correct": sum(
                rows[(f"{pair}_fixed", condition, repeat)]["verdict_correct"] is True
                and rows[(f"{pair}_vuln", condition, repeat)]["verdict_correct"] is True
                for repeat in range(REPEATS)),
            "run_errors": sum(rows[(f"{pair}_{variant}", condition, repeat)]["status"] == "run_error"
                              for variant in ("fixed", "vuln") for repeat in range(REPEATS)),
        } for condition in CONDITIONS}
    result = {
        "phase": "exploratory_evaluation", "protocol_id": "V3-E1",
        "post_development_amendment": True, "planned_runs": 48,
        "independent_pairs": 6, "repeats_per_case_version_condition": 2,
        "manifest_sha256": digest(manifest_path),
        "results_sha256": digest(directory / "results.jsonl"),
        "per_condition": per_condition, "per_pair": per_pair,
        "interpretation": "Descriptive only: six independent pairs, not 48 independent cases; "
                          "baseline non-completion and type errors stay in the denominators.",
    }
    path = directory / "summary.json"
    if path.exists() and json.loads(path.read_text(encoding="utf-8")) != result:
        raise ValueError("Existing reserved summary differs; do not silently overwrite")
    if not path.exists():
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"summary": str(path), **result}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    print(json.dumps(summarize(args.input), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
