"""Static V3 inventory audit; it does not run the model or grade its output."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from cases.v3_catalog import internal_case_for, public_spec_for_case


ROOT = Path(__file__).resolve().parents[1]


def check() -> dict:
    registry = json.loads((ROOT / "research/v3_registry.json").read_text(encoding="utf-8"))
    if registry["purpose"] != "researcher_authored_cases_reserved_from_agent_tuning":
        raise ValueError("V3 case provenance missing")
    apps = registry["applications"]
    if len(apps) != 2 or {app["app_id"] for app in apps} != {
        "ticket_lab_v3", "expense_lab_v1",
    }:
        raise ValueError("Expected two distinct V3 application families")

    public_docs = {
        "ticket_lab_v3": json.loads((ROOT / "cases/v3_ticket_specs.json").read_text(encoding="utf-8")),
        "expense_lab_v1": json.loads((ROOT / "cases/v3_expense_specs.json").read_text(encoding="utf-8")),
    }
    truth_docs = {
        "ticket_lab_v3": json.loads((ROOT / "cases/v3_ticket_truth.json").read_text(encoding="utf-8"))["cases"],
        "expense_lab_v1": json.loads((ROOT / "cases/v3_expense_truth.json").read_text(encoding="utf-8"))["cases"],
    }
    all_ids: set[str] = set()
    task_ids: set[str] = set()
    split_counts: Counter[str] = Counter()
    oracle_counts: Counter[str] = Counter()
    for app in apps:
        app_id = app["app_id"]
        if len(app["pairs"]) != 4:
            raise ValueError("Expected four V3 pairs in each application")
        specs = {row["pair_id"]: row for row in public_docs[app_id]["cases"]}
        if len(specs) != 4:
            raise ValueError("Duplicate or missing public tasks")
        truths = truth_docs[app_id]
        listed: set[str] = set()
        per_split: Counter[str] = Counter()
        per_oracle: Counter[tuple[str, str]] = Counter()
        for pair in app["pairs"]:
            pair_id, split = pair["pair_id"], pair["split"]
            if pair_id not in specs or specs[pair_id]["split"] != split:
                raise ValueError("Registry and visible spec disagree")
            if set(pair["variants"]) != {f"{pair_id}_fixed", f"{pair_id}_vuln"}:
                raise ValueError("Pair has incorrect server variants")
            per_split[split] += 1
            split_counts[split] += 1
            public = public_spec_for_case(pair["variants"][0])
            if public != public_spec_for_case(pair["variants"][1]):
                raise ValueError("Paired model input differs")
            if public["public_task_id"] in task_ids:
                raise ValueError("Public IDs are not unique")
            task_ids.add(public["public_task_id"])
            visible = json.dumps(public, ensure_ascii=False).lower()
            if any(term in visible for term in ("vuln", "fixed", "ground_truth", "truth.json", "case_id")):
                raise ValueError("Server label leaked into model input")
            left, right = (truths[f"{pair_id}_{variant}"] for variant in ("fixed", "vuln"))
            if left["ground_truth"] is not False or right["ground_truth"] is not True:
                raise ValueError("Paired labels not opposite")
            for key in ("vulnerability_type", "oracle_kind"):
                if left[key] != right[key]:
                    raise ValueError("Paired oracles disagree")
            if left["oracle_kind"] == "write_state":
                for key in ("oracle_table", "oracle_row_id", "oracle_field", "before", "attempted_after"):
                    if left[key] != right[key]:
                        raise ValueError("Write oracle differs between variants")
                if left["before"] == left["attempted_after"]:
                    raise ValueError("Write oracle is a no-op")
            elif left["oracle_kind"] == "read_body":
                if left["protected_markers"] != right["protected_markers"]:
                    raise ValueError("Read oracle differs between variants")
                if left.get("protected_record") != right.get("protected_record"):
                    raise ValueError("Structured read oracle differs between variants")
            else:
                raise ValueError("Unknown oracle kind")
            per_oracle[(split, left["oracle_kind"])] += 1
            oracle_counts[left["oracle_kind"]] += 1
            for case_id in pair["variants"]:
                if case_id in all_ids or internal_case_for(case_id)["app_id"] != app_id:
                    raise ValueError("Duplicate case or wrong app")
                all_ids.add(case_id)
                listed.add(case_id)
        if set(specs) != {pair["pair_id"] for pair in app["pairs"]} or listed != set(truths):
            raise ValueError("Specs/truth/registry coverage mismatch")
        if per_split != {"dev": 1, "eval_reserved": 3}:
            raise ValueError("Per-application split wrong")
        if per_oracle != {("dev", "write_state"): 1,
                          ("eval_reserved", "write_state"): 2,
                          ("eval_reserved", "read_body"): 1}:
            raise ValueError("Per-application oracle mix wrong")
    return {
        "ok": True, "applications": 2, "case_pairs": 8, "server_variants": len(all_ids),
        "splits": dict(split_counts), "oracles": dict(oracle_counts),
        "status": "case_design_verified_agent_and_grader_not_yet_connected",
    }


if __name__ == "__main__":
    print(json.dumps(check(), ensure_ascii=False, indent=2))
