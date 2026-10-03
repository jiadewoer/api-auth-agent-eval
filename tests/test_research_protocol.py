"""Guard against the two misleading claims in the pilot: leakage and n=32."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from research.analyze import analyze
from research.audit import audit


ROOT = Path(__file__).resolve().parents[1]


def _study(app_count: int = 1):
    apps = []
    rows = []
    for index in range(app_count):
        pair = f"Q{index}"
        apps.append({"app_id": f"app{index}", "pairs": [{"pair_id": pair,
                     "split": "prospective_holdout", "variants": [f"{pair}_vuln", f"{pair}_fixed"]}]})
        for arm in ("T0E0", "T1E1"):
            for repeat in (0, 1):
                for variant in ("vuln", "fixed"):
                    correct = arm == "T1E1" or variant == "fixed"
                    case = f"{pair}_{variant}"
                    rows.append({"case_id": case, "condition": arm, "repeat_index": repeat,
                                 "status": "submitted", "run_error": None,
                                 "grade": {"case_id": case, "verdict_correct": correct,
                                           "evidence_valid": correct,
                                           "false_positive": False, "api_requests": 2}})
    return rows, {"purpose": "prospective_study", "applications": apps}


def test_original_registry_marks_all_formal_pairs_as_one_app():
    result = audit(ROOT / "research/registry.json", ROOT / "cases/specs.json", ROOT / "cases/truth.json")
    assert result["applications"] == 1
    assert result["splits"]["pilot_formal"] == 4
    assert result["inference_status"] == "pilot_only_single_application"


def test_leaking_case_label_fails_audit(tmp_path):
    specs = json.loads((ROOT / "cases/specs.json").read_text(encoding="utf-8"))
    specs["cases"][0]["visible_policy"] += " P01_fixed"
    changed = tmp_path / "specs.json"
    changed.write_text(json.dumps(specs), encoding="utf-8")
    with pytest.raises(ValueError, match="Label leakage"):
        audit(ROOT / "research/registry.json", changed, ROOT / "cases/truth.json")


def test_repeats_are_not_new_independent_pairs_or_apps():
    rows, registry = _study()
    result = analyze(rows, registry, split="prospective_holdout", reference="T0E0", treatment="T1E1")
    assert result["attempted_runs"] == 8
    assert result["independent_case_pairs"] == 1
    assert result["independent_applications"] == 1
    assert result["per_condition"]["T1E1"]["attributable_pair_success"] == [2, 2]
    assert result["per_condition"]["T0E0"]["attributable_pair_success"] == [0, 2]
    assert result["paired_effect_treatment_minus_reference"]["application_cluster_bootstrap_95pct"] is None


def test_missing_or_duplicate_counterfactual_run_fails_closed():
    rows, registry = _study()
    for bad in (rows[:-1], rows + [rows[0]]):
        with pytest.raises(ValueError):
            analyze(bad, registry, split="prospective_holdout", reference="T0E0", treatment="T1E1")


def test_reused_run_id_fails_even_if_rows_have_distinct_keys():
    rows, registry = _study()
    rows[0]["run_id"] = rows[1]["run_id"] = "same-run"
    with pytest.raises(ValueError, match="Duplicate run ID"):
        analyze(rows, registry, split="prospective_holdout", reference="T0E0", treatment="T1E1")


def test_interval_resamples_applications_only_when_enough_apps():
    rows, registry = _study(app_count=5)
    result = analyze(rows, registry, split="prospective_holdout",
                     reference="T0E0", treatment="T1E1", bootstrap_samples=50)
    assert result["independent_applications"] == 5
    assert result["paired_effect_treatment_minus_reference"]["application_cluster_bootstrap_95pct"] == [1.0, 1.0]
