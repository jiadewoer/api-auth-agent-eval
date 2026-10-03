"""Read-only check before spending the untouched holdout cases."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from hashlib import sha256
from pathlib import Path

from cases.catalog import public_spec_for_case
from eval.manifest import manifest_template


# These are observed Agent outcomes. They remain in the denominator and are
# reported by summarize.py; requiring a lucky, all-successful dev run would
# select on model randomness before the holdout experiment.
RECORDED_AGENT_FAILURES = {
    "no_conclusion", "budget_exceeded", "finding_validation_error",
    "invalid_json", "tool_parameter_error",
}


def check(dev_output: str | Path, formal_output: str | Path) -> dict:
    dev = Path(dev_output)
    formal = Path(formal_output)
    template = manifest_template()
    manifest = json.loads((dev / "experiment_manifest.json").read_text(encoding="utf-8"))
    for field in ("agents", "model_tag", "model_digest_prefix", "temperature",
                  "num_ctx", "tool_spec_sha256", "request_limit", "decision_limit",
                  "timeout_seconds", "grader_version", "cases", "source_sha256"):
        if manifest.get(field) != template[field]:
            raise ValueError(f"Development run differs from frozen files: {field}")
    if manifest["selected_split"] != "dev":
        raise ValueError("The supplied development output is not dev")
    rows = [json.loads(line) for line in (dev / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    expected = {(c, a, 0) for c in template["cases"]["dev"]
                for a in ("baseline", "evidence")}
    observed = [(r["case_id"], r["agent_name"], r["repeat_index"]) for r in rows]
    if len(observed) != len(expected) or set(observed) != expected:
        raise ValueError("Dev needs exactly one A and one B for each P01/P04 variant")
    failures = Counter()
    graded_agents: set[str] = set()
    seen_run_ids: set[str] = set()
    for row in rows:
        run_id = row.get("run_id")
        if not run_id or run_id in seen_run_ids:
            raise ValueError("Dev has a missing or repeated run_id")
        seen_run_ids.add(run_id)
        for field in ("log_path", "db_path", "result_path"):
            if not row.get(field) or not Path(row[field]).is_file():
                raise ValueError(f"Dev missing {field} for {run_id}")
        raw = json.loads(Path(row["result_path"]).read_text(encoding="utf-8"))
        if any(raw.get(key) != row.get(key) for key in
               ("run_id", "case_id", "agent_name", "finding")):
            raise ValueError(f"Dev original result differs from row for {run_id}")
        trace = [json.loads(line) for line in Path(row["log_path"]).read_text(encoding="utf-8").splitlines()]
        if not trace or any(event.get("run_id") != run_id for event in trace):
            raise ValueError(f"Dev trace missing or mixed for {run_id}")
        if row["status"] == "graded":
            if (not isinstance(row.get("finding"), dict)
                    or not isinstance(row.get("grade"), dict)
                    or row["grade"].get("run_error")):
                raise ValueError(f"Dev graded result incomplete for {run_id}")
            graded_agents.add(row["agent_name"])
        elif row["status"] == "run_error":
            failure = row.get("run_error") or {}
            category = failure.get("category")
            if (category not in RECORDED_AGENT_FAILURES
                    or not failure.get("code")
                    or row.get("finding") is not None
                    or (row.get("grade") or {}).get("run_error") != failure):
                raise ValueError(f"Dev has a system or unrecorded failure for {run_id}: {failure}")
            if trace[-1].get("tool_name") != "run_error":
                raise ValueError(f"Dev failure has no terminal log event for {run_id}")
            failures[category] += 1
        else:
            raise ValueError(f"Dev has an unknown result status for {run_id}")
    if graded_agents != {"baseline", "evidence"}:
        raise ValueError("Each Agent needs at least one graded development run")
    if formal.exists() and any(formal.iterdir()):
        raise ValueError("Formal output is not empty; use a fresh directory")
    for case_id in template["cases"]["holdout"]:
        public = json.dumps(public_spec_for_case(case_id), ensure_ascii=False)
        if any(forbidden in public for forbidden in
               (case_id, "vuln", "fixed", "ground_truth", "variant", "truth.json")):
            raise ValueError(f"Public task leaked private metadata for {case_id}")
    return {"ok": True, "dev_rows": len(rows),
            "dev_graded": len(rows) - sum(failures.values()),
            "dev_agent_failures": dict(failures),
            "preflight_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "formal_output": str(formal),
            "holdout_cases": len(template["cases"]["holdout"])}


def main() -> None:
    parser = argparse.ArgumentParser(description="Check frozen development run before formal cases")
    parser.add_argument("--dev-output", required=True)
    parser.add_argument("--formal-output", required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.dev_output, args.formal_output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
