"""Run only P01/P04 development variants with frozen version A.

This is an observation sheet, not the week-three truth-based scorer.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import uuid4

from agent.runner import DEV_CASE_IDS, local_chat, run_case
from cases.catalog import public_spec_for_case


def observe(record: dict) -> dict:
    """Report the actual requests made; leave semantic quality to human review."""
    spec = public_spec_for_case(record["case_id"])
    legitimate_identity = "B" if record["case_id"].startswith("P01") else "M"
    rows = [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]
    actual = [row for row in rows if row["tool_name"] == "send_request" and row["request_id"]]
    path = spec["target_path"]
    legal = [row["request_id"] for row in actual
             if row["identity"] == legitimate_identity and row["arguments"]["path"] == path]
    candidate = [row["request_id"] for row in actual
                 if row["identity"] == "A" and row["arguments"]["path"] == path]
    first_legal = bool(legal and candidate and
                       next(row["step"] for row in actual if row["request_id"] == legal[0]) <
                       next(row["step"] for row in actual if row["request_id"] == candidate[0]))
    return {
        "case_id": record["case_id"], "run_id": record["run_id"],
        "status": record["status"], "run_error": record["run_error"],
        "legitimate_request_ids": legal, "candidate_request_ids": candidate,
        "legitimate_before_candidate": first_legal,
        "cited_request_ids": (record["finding"] or {}).get("evidence_request_ids", []),
        "verdict": (record["finding"] or {}).get("verdict"),
        "explanation": (record["finding"] or {}).get("explanation"),
        "check_only_status_code_by_hand": None,
        "log_path": record["log_path"], "db_path": record["db_path"],
        "result_path": record["result_path"],
    }


def run_dev_suite(chat_fn, log_dir: str | Path = "results/tmp", runtime_metadata=None,
                  agent_name: str = "baseline") -> dict:
    root = Path(log_dir)
    root.mkdir(parents=True, exist_ok=True)
    observations = [observe(run_case(case_id, chat_fn, root,
                                     runtime_metadata=runtime_metadata,
                                     agent_name=agent_name))
                    for case_id in DEV_CASE_IDS]
    path = root / f"dev_suite_{uuid4().hex[:12]}.json"
    sheet = {"cases": observations, "all_submitted": all(
        row["status"] == "submitted" for row in observations)}
    path.write_text(json.dumps(sheet, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"summary_path": str(path), **sheet}


def main() -> None:
    parser = argparse.ArgumentParser(description="Four frozen development cases; no holdout cases")
    parser.add_argument("--log-dir", default="results/tmp")
    parser.add_argument("--agent", choices=("baseline", "evidence"), default="baseline")
    args = parser.parse_args()
    chat_fn, runtime = local_chat()
    result = run_dev_suite(chat_fn, args.log_dir, runtime_metadata=runtime,
                           agent_name=args.agent)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
