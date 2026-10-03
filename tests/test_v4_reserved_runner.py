"""Reserved runner planning, manifest and deterministic plumbing."""

from __future__ import annotations

import pytest

from v4_lab.catalog import DEV_CASE_IDS, RESERVED_CASE_IDS
from v4_lab.dev_manifest import snapshot
from v4_lab.prompts import CONDITIONS
from v4_lab.run_ab_dev import deterministic_stub
from v4_lab.run_reserved import planned_keys, run_reserved


def test_reserved_manifest_and_plan_are_reserved_only() -> None:
    keys = planned_keys()
    assert len(keys) == len(set(keys)) == 192
    assert set(key[0] for key in keys) == set(RESERVED_CASE_IDS)
    assert not (set(key[0] for key in keys) & set(DEV_CASE_IDS))
    manifest = snapshot("stub", split="reserved")
    assert manifest["phase"] == "V4_reserved_evaluation"
    assert manifest["split"] == "reserved"
    assert manifest["repeats"] == 2
    assert manifest["planned_runs"] == 192


def test_stub_reserved_all_arms_and_immutable_resume(tmp_path) -> None:
    summary = run_reserved(output=tmp_path / "reserved", provider="stub",
                           chat_fn=deterministic_stub)
    assert (summary["rows"], summary["new_rows"], summary["run_errors"]) == (192, 192, 0)
    assert summary["independent_pairs"] == 12
    for condition in CONDITIONS:
        assert summary["per_condition"][condition]["stage_counts"]["s4"] == [24, 24]
        assert summary["per_condition"][condition]["fixed_false_positives"] == [0, 24]
    resumed = run_reserved(output=tmp_path / "reserved", provider="stub",
                           chat_fn=deterministic_stub)
    assert resumed["rows"] == 192 and resumed["new_rows"] == 0 and resumed["skipped"] == 192
    with pytest.raises(ValueError, match="manifest mismatch"):
        run_reserved(output=tmp_path / "reserved", provider="ollama",
                     chat_fn=deterministic_stub)
