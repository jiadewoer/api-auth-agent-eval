"""Paired, application-aware analysis of frozen run records.

The unit of generalization is an application. A repeat of the same case is
recorded but never counted as a new application or a new case pair.
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from statistics import mean


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    location = fraction * (len(ordered) - 1)
    lo = int(location)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (location - lo) * (ordered[hi] - ordered[lo])


def analyze(
    rows: list[dict], registry: dict, *, split: str,
    reference: str, treatment: str, bootstrap_samples: int = 2000,
    random_seed: int = 20260927,
) -> dict:
    """Reject incomplete/duplicate grids, then compare conditions pairwise.

    Primary endpoint: both variants of the same pair in the same repeat are
    classified correctly, with trace-valid evidence for the vulnerable one.
    Technical failures count as unsuccessful attempts in this denominator.
    """
    if reference == treatment or bootstrap_samples < 1:
        raise ValueError("Choose distinct conditions and positive bootstrap_samples")
    pairs = {}
    for app in registry["applications"]:
        for pair in app["pairs"]:
            if pair["split"] == split:
                if pair["pair_id"] in pairs:
                    raise ValueError("Duplicate pair in registry")
                pairs[pair["pair_id"]] = (app["app_id"], pair["variants"])
    if not pairs:
        raise ValueError(f"No pairs in split {split}")
    expected_cases = {case for _, variants in pairs.values() for case in variants}
    conditions = (reference, treatment)
    keys: dict[tuple[str, str, int], dict] = {}
    run_ids: set[str] = set()
    for row in rows:
        condition = row.get("condition", row.get("agent_name"))
        case, repeat = row["case_id"], row["repeat_index"]
        key = (case, condition, repeat)
        if case not in expected_cases or condition not in conditions or \
                not isinstance(repeat, int) or repeat < 0 or key in keys:
            raise ValueError(f"Unexpected or duplicate run key: {key}")
        if (row.get("grade") or {}).get("case_id", case) != case:
            raise ValueError(f"Foreign grade for {key}")
        if row.get("status") not in {"submitted", "graded", "run_error"}:
            raise ValueError(f"Unknown run status for {key}")
        if row["status"] == "run_error" and not row.get("run_error"):
            raise ValueError(f"Missing failure reason for {key}")
        if row["status"] != "run_error" and row.get("run_error"):
            raise ValueError(f"Successful row contains a run error for {key}")
        if not isinstance(row.get("grade"), dict):
            raise ValueError(f"Missing grade for {key}")
        run_id = row.get("run_id")
        if run_id is not None:
            if run_id in run_ids:
                raise ValueError(f"Duplicate run ID: {run_id}")
            run_ids.add(run_id)
        keys[key] = row
    repeat_count = max((key[2] for key in keys), default=-1) + 1
    expected = {(case, condition, repeat) for case in expected_cases
                for condition in conditions for repeat in range(repeat_count)}
    if not repeat_count or keys.keys() != expected:
        missing = expected - keys.keys()
        raise ValueError(f"Incomplete condition x case x repeat grid: missing {len(missing)}")
    scores: dict[tuple[str, str, int], int] = {}
    per_condition = {}
    per_app = defaultdict(lambda: defaultdict(lambda: {"successes": 0, "observations": 0}))
    for condition in conditions:
        vuln = [keys[(f"{pair}_vuln", condition, rep)]
                for pair in pairs for rep in range(repeat_count)]
        fixed = [keys[(f"{pair}_fixed", condition, rep)]
                 for pair in pairs for rep in range(repeat_count)]
        for pair, (app_id, variants) in pairs.items():
            if set(variants) != {f"{pair}_vuln", f"{pair}_fixed"}:
                raise ValueError(f"Invalid pair variants: {pair}")
            for rep in range(repeat_count):
                pos, neg = (keys[(f"{pair}_{variant}", condition, rep)]
                            for variant in ("vuln", "fixed"))
                pg, ng = pos["grade"], neg["grade"]
                success = (pos["status"] != "run_error" and neg["status"] != "run_error"
                           and pg.get("verdict_correct") is True
                           and pg.get("evidence_valid") is True
                           and ng.get("verdict_correct") is True)
                scores[(pair, condition, rep)] = int(success)
                cell = per_app[app_id][condition]
                cell["successes"] += success
                cell["observations"] += 1
        all_runs = vuln + fixed
        per_condition[condition] = {
            "attributable_pair_success": [sum(scores[(pair, condition, rep)]
                                             for pair in pairs for rep in range(repeat_count)),
                                         len(pairs) * repeat_count],
            "vulnerability_detected": [sum(r["grade"].get("verdict_correct") is True for r in vuln), len(vuln)],
            "fixed_false_positives": [sum(r["grade"].get("false_positive") is True for r in fixed), len(fixed)],
            "technical_failures": [sum(r["status"] == "run_error" for r in all_runs), len(all_runs)],
            "abstentions": [sum(r["grade"].get("abstained") is True for r in all_runs), len(all_runs)],
            "mean_api_requests": mean(r.get("api_requests", r["grade"].get("api_requests", 0))
                                      for r in all_runs),
        }
    # Equal-weight applications, then equal-weight case pairs inside each app.
    # Repeats stay in the case-pair mean. This estimates transfer to a new app.
    by_app_pairs = defaultdict(list)
    for pair, (app_id, _) in pairs.items():
        by_app_pairs[app_id].append(pair)
    def app_effect(app_id: str, selected: list[str] | None = None) -> float:
        chosen = selected or by_app_pairs[app_id]
        return mean(mean(scores[(pair, treatment, rep)] - scores[(pair, reference, rep)]
                         for rep in range(repeat_count)) for pair in chosen)
    effects = {app_id: app_effect(app_id) for app_id in by_app_pairs}
    estimate = mean(effects.values())
    ci = None
    if len(by_app_pairs) >= 5:
        rng = random.Random(random_seed)
        app_ids = list(by_app_pairs)
        replicates = []
        for _ in range(bootstrap_samples):
            sampled_apps = [rng.choice(app_ids) for _ in app_ids]
            replicates.append(mean(app_effect(app, [rng.choice(by_app_pairs[app])
                                                for _ in by_app_pairs[app]])
                                   for app in sampled_apps))
        ci = [round(_percentile(replicates, 0.025), 4),
              round(_percentile(replicates, 0.975), 4)]
    return {
        "status": "pilot_descriptive_only" if len(by_app_pairs) < 5 else
                  "multi_application_exploratory_interval",
        "warning": "Old cases and tuning invalidate prospective claims" if
                   registry.get("purpose") == "retrospective_pilot_inventory_only" else None,
        "split": split, "independent_applications": len(by_app_pairs),
        "independent_case_pairs": len(pairs), "repeats_per_case": repeat_count,
        "attempted_runs": len(keys), "per_condition": per_condition,
        "per_application": dict(per_app),
        "paired_effect_treatment_minus_reference": {
            "comparison": f"{treatment} - {reference}",
            "primary_endpoint": "attributable_pair_success",
            "equal_weight_application_difference": round(estimate, 4),
            "per_application_difference": effects,
            "application_cluster_bootstrap_95pct": ci,
            "interval_note": "No cross-application interval with fewer than 5 apps" if ci is None
                             else "Exploratory percentile interval; resamples apps and pairs, not runs",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze complete paired runs by application")
    parser.add_argument("--input", required=True, help="JSONL produced by eval or followup")
    parser.add_argument("--registry", default=str(Path(__file__).with_name("registry.json")))
    parser.add_argument("--split", default="pilot_formal")
    parser.add_argument("--reference", default="baseline")
    parser.add_argument("--treatment", default="evidence")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in Path(args.input).read_text(encoding="utf-8").splitlines()]
    registry = json.loads(Path(args.registry).read_text(encoding="utf-8"))
    result = analyze(rows, registry, split=args.split, reference=args.reference,
                     treatment=args.treatment)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(target), "status": result["status"],
                      "independent_applications": result["independent_applications"],
                      "independent_case_pairs": result["independent_case_pairs"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
