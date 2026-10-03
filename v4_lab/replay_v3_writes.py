"""Recompute V4 mechanism stages on the 16 already-seen V3-E1 write runs.

This is a historical diagnostic, never an unseen V4 evaluation. The archive is
read-only; output must be a new directory so earlier records stay untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from cases.v3_catalog import public_spec_for_case
from v4_lab.stages import score_write_stages


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SHA256 = "ccf6c99958cd0d0c16a39497a252a5eb6421dfce3c45a9faff6bb33649d13704"
RESULTS_SHA256 = "3b9d171fbd1de91d79a503c1e3e6b3246e43d8abd4f69de847a950ddc96af84f"
PAIRS = {"T02", "T03", "E02", "E03"}


def replay(archive_path: Path) -> tuple[list[dict], dict]:
    with ZipFile(archive_path) as archive:
        names = {name.replace("\\", "/").split("/")[-1]: name for name in archive.namelist()}
        if len(names) != len(archive.namelist()):
            raise ValueError("Duplicate basenames in archive")
        read = lambda name: archive.read(names[name])
        digest = lambda name: hashlib.sha256(read(name)).hexdigest()
        if digest("experiment_manifest.json") != MANIFEST_SHA256 or digest("results.jsonl") != RESULTS_SHA256:
            raise ValueError("Not the audited V3-E1 archive")
        manifest = json.loads(read("experiment_manifest.json"))
        for rel in ("v3_agent/protocol.py", "cases/v3_catalog.py", "cases/v3_ticket_specs.json",
                    "cases/v3_expense_specs.json", "cases/v3_ticket_truth.json", "cases/v3_expense_truth.json"):
            local = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
            if local != manifest["source_sha256"][rel]:
                raise ValueError(f"V3 source is not frozen: {rel}")
        input_rows = [json.loads(line) for line in read("results.jsonl").splitlines()]
        scores = []
        for row in input_rows:
            case_id = row["case_id"]
            if case_id.split("_")[0] not in PAIRS or not case_id.endswith("_vuln"):
                continue
            run_id = row["run_id"]
            record = json.loads(read(f"agent_{run_id}.json"))
            trace = [json.loads(line) for line in read(f"agent_{run_id}.jsonl").splitlines()]
            if (record["run_id"], record["case_id"]) != (run_id, case_id):
                raise ValueError("Record does not match results row")
            app = "ticket" if case_id.startswith("T") else "expense"
            truth = json.loads((ROOT / f"cases/v3_{app}_truth.json").read_text(encoding="utf-8"))["cases"][case_id]
            result = score_write_stages(public=public_spec_for_case(case_id), truth=truth,
                                        record=record, trace=trace)
            scores.append({"condition": row["condition"], "repeat_index": row["repeat_index"],
                           **result})
    scores.sort(key=lambda score: (score["case_id"], score["condition"], score["repeat_index"]))
    keys = {(row["case_id"], row["condition"], row["repeat_index"]) for row in scores}
    if len(scores) != 16 or len(keys) != 16:
        raise ValueError("Expected 16 unique vulnerable write runs")
    summary = {"status": "historical_exploratory_replay", "n_runs": 16,
               "n_independent_pairs": 4, "manifest_sha256": MANIFEST_SHA256,
               "results_sha256": RESULTS_SHA256, "conditions": {}}
    for condition in ("A", "B"):
        subset = [row for row in scores if row["condition"] == condition]
        if len(subset) != 8:
            raise ValueError("Condition count differs from audited plan")
        summary["conditions"][condition] = {
            **{f"s{stage}": [sum(row[f"s{stage}"] for row in subset), 8]
               for stage in range(1, 5)},
            "failure_stage": dict(Counter(row["failure_stage"] for row in subset)),
        }
    return scores, summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows, summary = replay(args.archive)
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.output / "stages_16.jsonl").open("x", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    (args.output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
