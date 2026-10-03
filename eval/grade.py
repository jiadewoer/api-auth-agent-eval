"""Independent, deterministic grading of one recorded Agent run.

The model never receives this module, truth.json or the private write snapshots.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from cases.catalog import internal_case_for


TRUTH_PATH = Path(__file__).resolve().parents[1] / "cases" / "truth.json"
GRADER_VERSION = "1"


def _expected_resources(spec: Mapping[str, Any]) -> set[str]:
    target = spec["target_object"]
    kind, object_id = target["kind"], target["id"]
    if kind == "ticket_comments":
        return {f"ticket_{object_id}", f"ticket_comments_{object_id}"}
    if kind == "ticket":
        return {f"ticket_{object_id}"}
    return {kind}  # admin_export / admin_audit


def _content_contains_marker(body: Any, markers: Sequence[str]) -> bool:
    serialized = json.dumps(body, ensure_ascii=False, sort_keys=True)
    return any(marker in serialized for marker in markers)


def _matching_write_state(
    row: Mapping[str, Any], observations: Sequence[Mapping[str, Any]],
    run_id: str, marker: str, expect_change: bool,
) -> bool:
    parts = marker.split(".")
    if len(parts) != 3 or parts[0] != "tickets":
        return False
    _, ticket_id, field = parts
    matches = [state for state in observations
               if state.get("run_id") == run_id
               and state.get("request_id") == row["request_id"]
               and state.get("identity") == "A"
               and state.get("method") == row["arguments"].get("method")
               and state.get("path") == row["arguments"].get("path")
               and state.get("ticket_id") == int(ticket_id)
               and state.get("field") == field]
    if len(matches) != 1:
        return False
    before, after = matches[0].get("before"), matches[0].get("after")
    if before is None or after is None:
        return False
    return (before != after) if expect_change else (before == after)


def grade_case(
    *, case_id: str, run_id: str, finding: Mapping[str, Any] | None,
    trace_rows: Sequence[Mapping[str, Any]], truth_case: Mapping[str, Any],
    write_observations: Sequence[Mapping[str, Any]] = (),
    run_error: Mapping[str, Any] | None = None,
    status: str = "submitted", duration_s: float = 0.0,
) -> dict:
    """Grade an explicit run, keeping verdict and evidence as separate fields."""
    spec = internal_case_for(case_id)
    actual_requests = [row for row in trace_rows
                       if row.get("tool_name") == "send_request"
                       and row.get("run_id") == run_id and row.get("request_id")]
    api_requests = len(actual_requests)
    failure = dict(run_error) if run_error else None
    if status != "submitted" or finding is None:
        failure = failure or {"category": "missing_finding", "code": "MISSING_FINDING"}
    verdict = finding.get("verdict") if finding and failure is None else None
    abstained = verdict == "insufficient_evidence"
    is_vuln = bool(truth_case["ground_truth"])
    classification_error = bool(is_vuln and verdict == "vulnerable" and
                                finding.get("vulnerability_type") != truth_case["vulnerability_type"])
    correct = None if failure or abstained else (
        (verdict == "vulnerable" and not classification_error) if is_vuln
        else verdict == "not_vulnerable"
    )
    false_positive = bool(not failure and not is_vuln and verdict == "vulnerable")
    false_negative = bool(not failure and is_vuln and verdict == "not_vulnerable")

    reasons: list[str] = []
    cited = finding.get("evidence_request_ids") if finding and not failure else None
    if failure:
        reasons.append("run_error")
    elif abstained:
        reasons.append("abstained")
    elif not isinstance(cited, list) or not cited:
        reasons.append("no_evidence_ids")
    else:
        if finding.get("identity") != "A":
            reasons.append("wrong_claimed_identity")
        if finding.get("resource") not in _expected_resources(spec):
            reasons.append("wrong_claimed_resource")
        if any(row.get("run_id") != run_id for row in trace_rows):
            reasons.append("mixed_run_trace")
        if any(state.get("run_id") != run_id for state in write_observations):
            reasons.append("mixed_run_write_state")

        referenced: list[Mapping[str, Any]] = []
        for request_id in cited:
            matches = [row for row in trace_rows if row.get("tool_name") == "send_request"
                       and row.get("request_id") == request_id]
            if len(matches) != 1 or matches[0].get("run_id") != run_id:
                reasons.append("unknown_or_foreign_request_id")
            elif matches[0].get("error") or matches[0].get("response_status") is None:
                reasons.append("request_failed")
            else:
                referenced.append(matches[0])

        target_rows = [row for row in referenced if row.get("identity") == "A"
                       and row.get("arguments", {}).get("method") == spec["target_method"]
                       and row.get("arguments", {}).get("path") == spec["target_path"]]
        if not target_rows:
            reasons.append("target_request_missing")
        else:
            markers = truth_case["protected_markers"]
            if truth_case["oracle_kind"] == "read_body":
                observed = any(
                    row["response_status"] == 200 and
                    _content_contains_marker(row["response_body"], markers)
                    for row in target_rows
                ) if is_vuln else any(
                    row["response_status"] == truth_case["expected_unauthorized_status"]
                    and not _content_contains_marker(row["response_body"], markers)
                    for row in target_rows
                )
            else:
                observed = any(
                    row["response_status"] == truth_case["expected_unauthorized_status"]
                    and all(_matching_write_state(row, write_observations, run_id,
                                                  marker, expect_change=is_vuln)
                            for marker in markers)
                    for row in target_rows
                )
            if not observed:
                reasons.append("protected_content_or_state_not_observed")
            if ((is_vuln and verdict != "vulnerable") or
                    (not is_vuln and verdict != "not_vulnerable")):
                reasons.append("observations_do_not_support_verdict")

    evidence_valid = not reasons
    return {
        "grader_version": GRADER_VERSION, "case_id": case_id, "run_id": run_id,
        "verdict_correct": correct, "evidence_valid": evidence_valid,
        "evidence_reasons": list(dict.fromkeys(reasons)),
        "evidence_provided": bool(cited),
        "false_positive": false_positive, "false_negative": false_negative,
        "classification_error": classification_error,
        "abstained": abstained, "run_error": failure,
        "api_requests": api_requests, "duration_s": duration_s,
    }


def grade_run(record: Mapping[str, Any], trace_rows: Sequence[Mapping[str, Any]],
              truth_path: str | Path = TRUTH_PATH) -> dict:
    """This wrapper, and only this evaluator module, opens truth.json."""
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))["cases"]
    case_id = record["case_id"]
    return grade_case(
        case_id=case_id, run_id=record["run_id"], finding=record.get("finding"),
        trace_rows=trace_rows, truth_case=truth[case_id],
        write_observations=record.get("write_observations") or (),
        run_error=record.get("run_error"), status=record.get("status", "run_error"),
        duration_s=record.get("duration_s", 0.0),
    )
