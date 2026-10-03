"""The rule baseline must distinguish observable leaks and changed state."""

import pytest

from scripts.rule_baseline import CASE_IDS, classify_read, classify_write, run_case


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_baseline_observes_all_twelve_cases_without_truth_lookup(case_id):
    result = run_case(case_id)
    assert set(result) == {"case_id", "observed", "verdict", "evidence"}
    assert result["case_id"] == case_id
    assert len(result["evidence"]) == 2
    assert result["observed"]["legal_status"] == 200
    assert result["verdict"] == (
        "confirmed" if case_id.endswith("_vuln") else "not_observed"
    )
    if case_id.startswith(("P03", "P05")):
        assert (result["observed"]["test_before"] != result["observed"]["test_after"]) == case_id.endswith("_vuln")


def test_200_without_state_change_is_not_proof():
    assert classify_write(200, "open", "closed", 200, "open", "open") == "needs_review"
    assert classify_write(200, "B", "A", 403, "B", "B") == "not_observed"
    assert classify_write(200, "B", "A", 403, "B", "A") == "needs_review"


def test_200_without_protected_content_is_not_proof():
    assert classify_read(200, {"body": ""}, 200, {"body": ""}) == "needs_review"
    assert classify_read(200, {"body": "secret"}, 200, {"body": "unrelated"}) == "needs_review"
