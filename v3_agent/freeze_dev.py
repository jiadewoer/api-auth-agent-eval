"""Freeze completed real-model dev A/B runs; never treat stub outputs as evidence."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from v3_agent.dev_manifest import CONDITIONS, ensure_manifest
from v3_agent.run_ab_dev import _result_rows, planned_keys


def freeze_development(output: str | Path) -> dict:
    directory = Path(output)
    manifest = ensure_manifest(directory, "ollama")
    manifest_bytes = (directory / "experiment_manifest.json").read_bytes()
    fingerprint = sha256(manifest_bytes).hexdigest()
    results_path = directory / "results.jsonl"
    rows = _result_rows(results_path, fingerprint)
    if set(rows) != set(planned_keys()):
        raise ValueError(f"Incomplete dev run: expected 8 unique keys, got {len(rows)}")
    digests = {row["model_digest"] for row in rows.values()}
    if None in digests or len(digests) != 1:
        raise ValueError("Actual model digest missing or inconsistent")
    digest = next(iter(digests))
    if not digest.startswith(manifest["expected_model_digest_prefix"]):
        raise ValueError("Actual model digest differs from configured model")
    setup_failures = [row for row in rows.values()
                      if (row.get("run_error") or {}).get("category") in {
                          "model_service_unavailable", "model_timeout", "lab_exception",
                      }]
    if setup_failures:
        raise ValueError("Service/lab setup failures in dev; use a fresh directory after repair")
    for condition in CONDITIONS:
        if not any(row["status"] == "submitted" and row["condition"] == condition
                   for row in rows.values()):
            raise ValueError(f"Condition {condition} has no completed dev finding")
    if not any(row["api_requests"] > 0 for row in rows.values()):
        raise ValueError("No real API request was made in the development runs")
    errors = Counter((row.get("run_error") or {}).get("category")
                     for row in rows.values() if row["status"] == "run_error")
    result = {
        "phase": "development_frozen", "provider": "ollama", "split": "dev",
        "rows": 8, "independent_pairs": 2, "model_digest": digest,
        "manifest_sha256": fingerprint, "results_sha256": sha256(results_path.read_bytes()).hexdigest(),
        "submitted_by_condition": {condition: sum(row["status"] == "submitted" and row["condition"] == condition
                                              for row in rows.values()) for condition in CONDITIONS},
        "run_error_categories": dict(errors),
        "development_runner_scope": "four_dev_versions_only",
    }
    frozen_path = directory / "frozen_dev_manifest.json"
    if frozen_path.exists():
        existing = json.loads(frozen_path.read_text(encoding="utf-8"))
        if {k: v for k, v in existing.items() if k != "frozen_at"} != result:
            raise ValueError("Frozen dev manifest differs; do not overwrite")
        return existing
    result["frozen_at"] = datetime.now(timezone.utc).isoformat()
    frozen_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    print(json.dumps(freeze_development(args.input), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
