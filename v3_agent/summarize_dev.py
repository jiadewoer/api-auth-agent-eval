"""Describe the eight A/B development observations without hiding run errors."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from hashlib import sha256
from pathlib import Path
from statistics import mean

from v3_agent.dev_manifest import CONDITIONS, DEV_CASE_IDS, ensure_manifest
from v3_agent.run_ab_dev import _result_rows, planned_keys


def summarize(output: str | Path) -> dict:
    directory = Path(output)
    manifest_path = directory / "experiment_manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Missing development manifest")
    provider = json.loads(manifest_path.read_text(encoding="utf-8"))["provider"]
    ensure_manifest(directory, provider)
    fingerprint = sha256(manifest_path.read_bytes()).hexdigest()
    rows = _result_rows(directory / "results.jsonl", fingerprint)
    if set(rows) != set(planned_keys()):
        raise ValueError(f"Incomplete dev run: expected eight rows, found {len(rows)}")
    per_condition: dict[str, dict] = {}
    for condition in CONDITIONS:
        subset = [r for r in rows.values() if r["condition"] == condition]
        positives = [r for r in subset if r["case_id"].endswith("_vuln")]
        negatives = [r for r in subset if r["case_id"].endswith("_fixed")]
        reported_vulnerable = [r for r in subset
                               if (r.get("finding") or {}).get("verdict") == "vulnerable"]
        errors = [r for r in subset if r["status"] == "run_error"]
        per_condition[condition] = {
            "vulnerability_detected": [sum(r["verdict_correct"] is True for r in positives), 2],
            "fixed_false_positives": [sum(r["false_positive"] is True for r in negatives), 2],
            "valid_evidence_among_vulnerability_reports": [
                sum(r["evidence_valid"] is True for r in reported_vulnerable),
                len(reported_vulnerable),
            ],
            "paired_correct": [sum(
                rows[(pair + "_fixed", condition, 0)]["verdict_correct"] is True
                and rows[(pair + "_vuln", condition, 0)]["verdict_correct"] is True
                for pair in ("T01", "E01")
            ), 2],
            "submitted": [sum(r["status"] == "submitted" for r in subset), 4],
            "run_errors": [len(errors), 4],
            "error_categories": dict(Counter((r["run_error"] or {}).get("category") for r in errors)),
            "mean_api_requests": round(mean(r["api_requests"] for r in subset), 3),
            "mean_duration_s": round(mean(r["duration_s"] for r in subset), 3),
            "gate_rejections": sum(r["gate_rejections"] for r in subset),
        }
    return {"phase": "development", "provider": provider, "split": "dev",
            "rows": len(rows), "independent_pairs": len(DEV_CASE_IDS)//2,
            "per_condition": per_condition,
            "caution": "These two development pairs do not estimate unseen-system performance."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    result = summarize(args.input)
    path = Path(args.input) / "summary.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(path), **result}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
