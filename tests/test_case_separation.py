"""Check the real Agent input projection, not just the on-disk truth file."""

import json
import re
from pathlib import Path

import pytest

from cases.catalog import internal_case_for, public_spec_for_case


PAIR_IDS = ("P01", "P02", "P03", "P04", "P05", "P06")
CASE_IDS = tuple(f"{pair}_{variant}" for pair in PAIR_IDS for variant in ("fixed", "vuln"))
CASES_DIR = Path(__file__).resolve().parents[1] / "cases"
TRUTH_PATH = CASES_DIR / "truth.json"
INTERNAL_FIELDS = {
    "pair_id", "case_id", "split", "target_method", "target_path",
    "test_identities", "target_object", "visible_policy",
}
PUBLIC_FIELDS = {
    "public_task_id", "target_method", "target_path", "test_identities",
    "target_object", "visible_policy",
}


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_each_case_has_eight_internal_fields_and_label_free_agent_input(case_id):
    internal = internal_case_for(case_id)
    assert set(internal) == INTERNAL_FIELDS
    assert internal["case_id"] == case_id
    assert internal["split"] in {"dev", "holdout"}
    assert internal["target_method"] in {"GET", "POST"}
    assert internal["target_path"].startswith("/")

    # Serialize the exact projection that the runner will give the Agent.
    public = public_spec_for_case(case_id)
    assert set(public) == PUBLIC_FIELDS
    assert re.fullmatch(r"TASK-[A-Z0-9]+", public["public_task_id"])
    assert public["target_method"] == internal["target_method"]
    assert public["target_path"] == internal["target_path"]
    assert public["test_identities"] == internal["test_identities"]

    agent_input = json.dumps(public, ensure_ascii=False).lower()
    for forbidden in (
        "case_id", "ground_truth", "variant", "protected_markers",
        "truth.json", str(TRUTH_PATH).lower(), case_id.lower(),
        "vuln", "fixed",
    ):
        assert forbidden not in agent_input


def test_pairs_have_one_public_task_and_truth_stays_internal():
    specs = json.loads((CASES_DIR / "specs.json").read_text(encoding="utf-8"))
    truth = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))["cases"]
    assert len(specs["cases"]) == len(PAIR_IDS)  # One shared policy per pair.
    assert {task["pair_id"] for task in specs["cases"]} == set(PAIR_IDS)
    assert len({task["public_task_id"] for task in specs["cases"]}) == len(PAIR_IDS)
    assert set(truth) == set(CASE_IDS)

    for pair_id in PAIR_IDS:
        assert public_spec_for_case(f"{pair_id}_fixed") == public_spec_for_case(
            f"{pair_id}_vuln"
        )
        assert {truth[f"{pair_id}_{variant}"]["ground_truth"] for variant in ("fixed", "vuln")} == {False, True}
        for variant in ("fixed", "vuln"):
            info = truth[f"{pair_id}_{variant}"]
            assert info["variant"] == variant
            assert info["oracle_kind"] in {"read_body", "write_state"}
            assert info["protected_markers"]
    assert {task["pair_id"] for task in specs["cases"] if task["split"] == "dev"} == {"P01", "P04"}
    assert {task["pair_id"] for task in specs["cases"] if task["split"] == "holdout"} == {"P02", "P03", "P05", "P06"}
