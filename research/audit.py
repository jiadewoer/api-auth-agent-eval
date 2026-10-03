"""Check case provenance and pair separation before accepting an experiment."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def audit(registry_path: str | Path, specs_path: str | Path, truth_path: str | Path) -> dict:
    registry = json.loads(Path(registry_path).read_text(encoding="utf-8"))
    specs = json.loads(Path(specs_path).read_text(encoding="utf-8"))
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))["cases"]
    if registry.get("schema_version") != 1:
        raise ValueError("Unsupported registry schema")
    public = {row["pair_id"]: row for row in specs["cases"]}
    if len(public) != len(specs["cases"]):
        raise ValueError("Duplicate pair in public specs")
    case_ids: set[str] = set()
    pair_ids: set[str] = set()
    app_ids: set[str] = set()
    splits: dict[str, int] = {}
    for app in registry["applications"]:
        app_id = app["app_id"]
        if not app_id or app_id in app_ids:
            raise ValueError("Missing or duplicate application ID")
        app_ids.add(app_id)
        for pair in app["pairs"]:
            pair_id = pair["pair_id"]
            if pair_id in pair_ids or pair_id not in public:
                raise ValueError(f"Duplicate or unknown pair: {pair_id}")
            pair_ids.add(pair_id)
            if pair["split"] not in {"dev", "pilot_formal", "prospective_holdout"}:
                raise ValueError(f"Unknown split: {pair_id}")
            if pair["split"] == "prospective_holdout" and registry["purpose"] == "retrospective_pilot_inventory_only":
                raise ValueError("Historical cases cannot be relabelled prospective holdout")
            splits[pair["split"]] = splits.get(pair["split"], 0) + 1
            variants = pair["variants"]
            if len(variants) != 2 or set(variants) != {f"{pair_id}_vuln", f"{pair_id}_fixed"}:
                raise ValueError(f"Missing/mismatched counterfactual pair: {pair_id}")
            if any(case in case_ids or case not in truth for case in variants):
                raise ValueError(f"Duplicate or unknown case in {pair_id}")
            case_ids.update(variants)
            positive, negative = truth[f"{pair_id}_vuln"], truth[f"{pair_id}_fixed"]
            if (positive["ground_truth"], negative["ground_truth"]) != (True, False):
                raise ValueError(f"Wrong labels: {pair_id}")
            if positive["vulnerability_type"] != negative["vulnerability_type"] or \
               positive["oracle_kind"] != negative["oracle_kind"] or \
               positive["protected_markers"] != negative["protected_markers"]:
                raise ValueError(f"Pair changes task or oracle: {pair_id}")
            visible = json.dumps(public[pair_id], ensure_ascii=False).lower()
            if any(word in visible for word in ("_vuln", "_fixed", "ground_truth", "truth.json")) or \
                    re.search(r"\b(vuln|fixed)\b", visible):
                raise ValueError(f"Label leakage in visible spec: {pair_id}")
    if case_ids != set(truth) or pair_ids != set(public):
        raise ValueError("Registry, public specs and truth do not cover the same cases")
    return {"ok": True, "applications": len(app_ids), "independent_pairs": len(pair_ids),
            "splits": splits,
            "inference_status": "pilot_only_single_application" if len(app_ids) == 1 else
                                "requires_independent_app_review"}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--registry", default=str(ROOT / "research/registry.json"))
    p.add_argument("--specs", default=str(ROOT / "cases/specs.json"))
    p.add_argument("--truth", default=str(ROOT / "cases/truth.json"))
    args = p.parse_args()
    print(json.dumps(audit(args.registry, args.specs, args.truth), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
