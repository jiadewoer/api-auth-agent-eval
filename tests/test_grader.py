"""The scorer must use actual same-run observations, never the model's prose."""

import json

import pytest

from eval.grade import TRUTH_PATH, grade_case, grade_run


TRUTH = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))["cases"]


def request(request_id="r001", *, run_id="run-one", identity="A", method="GET",
            path="/tickets/201", status=200, body=None):
    return {
        "run_id": run_id, "tool_name": "send_request", "request_id": request_id,
        "arguments": {"identity": identity, "method": method, "path": path},
        "identity": identity, "response_status": status,
        "response_body": body if body is not None else {"detail": "Access denied"},
        "error": None,
    }


def finding(verdict="vulnerable", vulnerability_type="BOLA", ids=None,
            identity="A", resource="ticket_201"):
    return {"verdict": verdict, "vulnerability_type": vulnerability_type,
            "identity": identity, "resource": resource,
            "evidence_request_ids": ids if ids is not None else ["r001"],
            "explanation": "This text alone is not evidence"}


def grade(case_id="P01_vuln", evidence=None, answer=None, **kwargs):
    return grade_case(
        case_id=case_id, run_id="run-one", truth_case=TRUTH[case_id],
        trace_rows=evidence if evidence is not None else [],
        finding=answer if answer is not None else finding(), **kwargs,
    )


def test_real_read_evidence_and_lucky_correct_verdict_without_evidence():
    actual = [request(body={"id": 201, "owner_id": "B", "body": "b-private-201"})]
    correct = grade(evidence=actual)
    assert correct["verdict_correct"] is True
    assert correct["evidence_valid"] is True
    assert correct["api_requests"] == 1

    fabricated = grade(evidence=actual, answer=finding(ids=["r999"]))
    assert fabricated["verdict_correct"] is True  # Lucky verdict; not good evidence.
    assert fabricated["evidence_valid"] is False
    assert "unknown_or_foreign_request_id" in fabricated["evidence_reasons"]


def test_another_runs_same_request_id_never_counts_as_evidence():
    foreign = [request(run_id="someone-else",
                       body={"id": 201, "owner_id": "B", "body": "b-private-201"})]
    got = grade(evidence=foreign)
    assert got["verdict_correct"] is True
    assert got["evidence_valid"] is False
    assert "mixed_run_trace" in got["evidence_reasons"]
    assert got["api_requests"] == 0


def test_legitimate_shared_200_cannot_prove_private_ticket_vulnerability():
    shared = [request(path="/tickets/301", body={"id": 301, "owner_id": "B", "body": "b-shared-301"})]
    got = grade(evidence=shared)
    assert got["verdict_correct"] is True
    assert got["evidence_valid"] is False
    assert "target_request_missing" in got["evidence_reasons"]


def test_write_200_without_state_change_is_not_valid_evidence():
    actual = [request(method="POST", path="/tickets/201/close", status=200,
                      body={"id": 201, "status": "closed"})]
    unchanged = [{"run_id": "run-one", "request_id": "r001", "identity": "A",
                  "method": "POST", "path": "/tickets/201/close", "ticket_id": 201,
                  "field": "status", "before": "open", "after": "open"}]
    got = grade("P03_vuln", actual, finding(), write_observations=unchanged)
    assert got["verdict_correct"] is True
    assert got["evidence_valid"] is False
    assert "protected_content_or_state_not_observed" in got["evidence_reasons"]
    changed = [{**unchanged[0], "after": "closed"}]
    assert grade("P03_vuln", actual, finding(), write_observations=changed)["evidence_valid"] is True


def test_false_positive_false_negative_and_wrong_type_are_separate():
    fixed_trace = [request(status=403)]
    fp = grade("P01_fixed", fixed_trace, finding())
    assert fp["false_positive"] is True and fp["verdict_correct"] is False
    assert fp["evidence_valid"] is False
    assert fp["evidence_provided"] is True  # Plausible-looking but invalid.
    assert "observations_do_not_support_verdict" in fp["evidence_reasons"]

    leaked = [request(body={"id": 201, "body": "b-private-201"})]
    fn = grade(evidence=leaked, answer=finding("not_vulnerable", None))
    assert fn["false_negative"] is True and fn["evidence_valid"] is False
    wrong_type = grade(evidence=leaked, answer=finding("vulnerable", "BFLA"))
    assert wrong_type["classification_error"] is True
    assert wrong_type["verdict_correct"] is False
    assert wrong_type["evidence_valid"] is True  # The leak exists; the type is wrong.


def test_abstain_and_run_error_are_neither_fixed_success_nor_false_negative():
    denied = [request(status=403)]
    abstain = grade("P01_fixed", denied, finding("insufficient_evidence", None))
    assert abstain["abstained"] is True
    assert abstain["verdict_correct"] is None
    assert abstain["run_error"] is None

    technical_failure = grade_case(
        case_id="P01_fixed", run_id="run-one", finding=None,
        trace_rows=denied, truth_case=TRUTH["P01_fixed"], status="run_error",
        run_error={"category": "model_timeout", "code": "MODEL_TIMEOUT"},
    )
    assert technical_failure["run_error"]["category"] == "model_timeout"
    assert technical_failure["verdict_correct"] is None
    assert technical_failure["false_positive"] is False


def test_negative_write_evidence_requires_denial_and_unchanged_state():
    denied = [request(method="POST", path="/tickets/201/close", status=403)]
    state = [{"run_id": "run-one", "request_id": "r001", "identity": "A",
              "method": "POST", "path": "/tickets/201/close", "ticket_id": 201,
              "field": "status", "before": "open", "after": "open"}]
    got = grade("P03_fixed", denied, finding("not_vulnerable", None), write_observations=state)
    assert got["verdict_correct"] is True and got["evidence_valid"] is True


@pytest.mark.parametrize("case_id,path,resource,kind,marker", [
    ("P02_vuln", "/tickets/201/comments", "ticket_comments_201", "BOLA", "comment-private-201"),
    ("P04_vuln", "/admin/export", "admin_export", "BFLA", "comment-private-301"),
    ("P06_vuln", "/admin/audit", "admin_audit", "BFLA", "fixture-created"),
])
def test_other_read_oracles_use_real_target_and_marker(case_id, path, resource, kind, marker):
    actual = [request(path=path, body={"data": marker})]
    got = grade(case_id, actual, finding("vulnerable", kind, resource=resource))
    assert got["verdict_correct"] is True and got["evidence_valid"] is True


def test_reassign_requires_actual_owner_change():
    trace = [request(method="POST", path="/tickets/201/reassign", status=200,
                     body={"id": 201, "owner_id": "A"})]
    snapshot = [{"run_id": "run-one", "request_id": "r001", "identity": "A",
                 "method": "POST", "path": "/tickets/201/reassign", "ticket_id": 201,
                 "field": "owner_id", "before": "B", "after": "A"}]
    got = grade("P05_vuln", trace, finding("vulnerable", "BFLA"),
                write_observations=snapshot)
    assert got["verdict_correct"] is True and got["evidence_valid"] is True


def test_grade_run_loads_private_truth_but_does_not_trust_reported_request_count():
    record = {"case_id": "P01_vuln", "run_id": "run-one", "status": "submitted",
              "finding": finding(), "api_requests": 999, "duration_s": 2.5}
    got = grade_run(record, [request(body={"body": "b-private-201"})])
    assert got["verdict_correct"] is True
    assert got["api_requests"] == 1
    assert got["duration_s"] == 2.5
