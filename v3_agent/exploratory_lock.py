"""Versioned post-development lock for the V3-E1 exploratory protocol."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from v3_agent.dev_manifest import CONDITIONS, ROOT, ensure_manifest
from v3_agent.run_ab_dev import _result_rows, planned_keys


AMENDMENT = "research/V3_EXPLORATORY_STAGE6_AMENDMENT.md"
LOCK_NAME = "exploratory_dev_lock.json"
NEW_CODE = (
    "v3_agent/exploratory_lock.py", "v3_agent/run_ab_eval.py",
    "v3_agent/summarize_eval.py",
)
SETUP_FAILURES = {
    "model_service_unavailable", "model_timeout", "model_exception", "lab_exception",
}


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def expected_lock(directory: Path) -> dict:
    manifest = ensure_manifest(directory, "ollama")  # Verify every old source hash.
    if manifest["model"] != "qwen3:8b":
        raise ValueError("V3-E1 is limited to the qwen3:8b development configuration")
    if (directory / "frozen_dev_manifest.json").exists():
        raise ValueError("This development run already has an original freeze; use that protocol")
    manifest_path = directory / "experiment_manifest.json"
    manifest_hash = digest(manifest_path)
    results_path = directory / "results.jsonl"
    rows = _result_rows(results_path, manifest_hash)
    if set(rows) != set(planned_keys()):
        raise ValueError(f"Expected eight unique development keys; found {len(rows)}")
    digests = {row.get("model_digest") for row in rows.values()}
    if None in digests or len(digests) != 1:
        raise ValueError("Development model digest is missing or inconsistent")
    model_digest = next(iter(digests))
    if not model_digest.startswith(manifest["expected_model_digest_prefix"]):
        raise ValueError("Development model digest differs from the manifest")
    for row in rows.values():
        if row.get("status") not in {"submitted", "run_error"}:
            raise ValueError("Unknown development outcome status")
        if row["status"] == "run_error" and not row.get("run_error"):
            raise ValueError("An unsuccessful development run has no error category")
        if (row.get("run_error") or {}).get("category") in SETUP_FAILURES:
            raise ValueError("Development contains a model-service or lab setup failure")
    counts = {}
    for condition in CONDITIONS:
        subset = [row for row in rows.values() if row["condition"] == condition]
        if not any(row["api_requests"] > 0 for row in subset):
            raise ValueError(f"Condition {condition} made no real API request")
        counts[condition] = {
            "submitted": sum(row["status"] == "submitted" for row in subset),
            "run_errors": sum(row["status"] == "run_error" for row in subset),
            "error_categories": dict(Counter(
                (row.get("run_error") or {}).get("category")
                for row in subset if row["status"] == "run_error"
            )),
        }
    if counts["A"]["submitted"] != 0 or counts["B"]["submitted"] != 4:
        raise ValueError("V3-E1 applies only to the observed A=0/4, B=4/4 development run")
    paths = (AMENDMENT, *NEW_CODE)
    for relative in paths:
        if not (ROOT / relative).is_file():
            raise ValueError(f"Missing V3-E1 amendment or runner: {relative}")
    return {
        "protocol_id": "V3-E1", "phase": "exploratory_development_locked",
        "post_dev_amendment": True, "original_freeze_passed": False,
        "reason": "Zero baseline submissions are retained as observed Agent failures",
        "provider": "ollama", "split": "dev", "rows": 8,
        "model": manifest["model"], "model_digest": model_digest,
        "dev_manifest_sha256": manifest_hash,
        "dev_results_sha256": digest(results_path),
        "new_file_sha256": {relative: digest(ROOT / relative) for relative in paths},
        "submitted_and_failures": counts,
        "evaluation_plan": {"independent_pairs": 6, "versions_per_pair": 2,
                            "conditions": list(CONDITIONS), "repeats": 2,
                            "planned_runs": 48},
    }


def require_lock(directory: str | Path) -> dict:
    directory = Path(directory).resolve()
    path = directory / LOCK_NAME
    if not path.is_file():
        raise ValueError("Exploratory lock missing; run exploratory_lock first")
    stored = json.loads(path.read_text(encoding="utf-8"))
    expected = expected_lock(directory)
    if {k: v for k, v in stored.items() if k != "locked_at"} != expected:
        raise ValueError("Development result, protocol, code or lock changed; stop")
    return stored


def lock_development(directory: str | Path) -> dict:
    directory = Path(directory).resolve()
    path = directory / LOCK_NAME
    if path.exists():
        return require_lock(directory)
    result = {**expected_lock(directory),
              "locked_at": datetime.now(timezone.utc).isoformat()}
    with path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    print(json.dumps(lock_development(args.input), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
