"""Independent V3 evaluator: reads hidden truth after the Agent run has ended."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from cases.v3_catalog import internal_case_for, public_spec_for_case
from v3_agent.protocol import read_control, resource_for, write_target


ROOT = Path(__file__).resolve().parents[1]
GRADER_VERSION = "v3-dev-1"


def _protected(body: Any, truth: Mapping[str, Any]) -> bool:
    if not isinstance(body, list) or not body:
        return False
    record = truth.get("protected_record")
    if record:
        return any(isinstance(item, dict) and all(item.get(k) == v for k, v in record.items())
                   for item in body)
    markers = truth.get("protected_markers", [])
    rendered = json.dumps(body, ensure_ascii=False)
    return bool(markers) and all(marker in rendered for marker in markers)


def _rows_for(run_id: str, trace: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    return {row["request_id"]: row for row in trace
            if row.get("tool_name") == "send_request"
            and row.get("run_id") == run_id and row.get("request_id")
            and row.get("response_status") is not None and not row.get("error")}


def _visible(row: Mapping[str, Any], field: str) -> tuple[bool, Any]:
    body = row.get("response_body")
    return (field in body, body.get(field)) if isinstance(body, dict) else (False, None)


def _write_evidence(
    *, public: Mapping[str, Any], truth: Mapping[str, Any], run_id: str,
    candidate_id: str, rows: Mapping[str, Mapping[str, Any]],
    cited_ids: set[str], snapshots: Sequence[Mapping[str, Any]],
) -> bool:
    candidate = rows[candidate_id]
    positive = truth["ground_truth"]
    expected_status = 200 if positive else 403
    if candidate["response_status"] != expected_status:
        return False
    matched = [state for state in snapshots
               if state.get("run_id") == run_id and state.get("request_id") == candidate_id
               and state.get("identity") == "A"
               and state.get("table") == truth["oracle_table"]
               and state.get("object_id") == truth["oracle_row_id"]
               and state.get("field") == truth["oracle_field"]
               and state.get("method") == public["target_method"]
               and state.get("path") == public["target_path"]]
    if len(matched) != 1:
        return False
    before = truth["before"]
    after = truth["attempted_after"] if positive else before
    if (matched[0].get("before"), matched[0].get("after")) != (before, after):
        return False
    if positive and before == after:
        return False
    control_identity, control_path = read_control(public)
    ordered = list(rows.items())
    positions = {rid: i for i, (rid, _) in enumerate(ordered)}
    candidates = [(rid, row) for rid, row in ordered if rid in cited_ids
                  and row.get("identity") == control_identity
                  and row.get("arguments", {}).get("method") == "GET"
                  and row.get("arguments", {}).get("path") == control_path
                  and row.get("response_status") == 200]
    earlier = [(rid, row) for rid, row in candidates if positions[rid] < positions[candidate_id]]
    later = [(rid, row) for rid, row in candidates if positions[rid] > positions[candidate_id]]
    if not earlier or not later:
        return False
    before_id, before_row = earlier[-1]
    after_id, after_row = later[0]
    seen_old, old = _visible(before_row, truth["oracle_field"])
    seen_new, new = _visible(after_row, truth["oracle_field"])
    if not (seen_old and seen_new and old == before and new == after):
        return False
    app_id = "expense_lab_v1" if public["target_path"].startswith("/claims/") else "ticket_lab_v3"
    target = write_target(app_id, public["target_path"])
    for rid, row in ordered[positions[before_id]+1:positions[after_id]]:
        if (rid != candidate_id and row["arguments"].get("method") == "POST"
                and write_target(app_id, row["arguments"].get("path", "")) == target):
            return False
    return True


def grade_case(
    *, case_id: str, run_id: str, finding: Mapping[str, Any] | None,
    trace_rows: Sequence[Mapping[str, Any]], truth_case: Mapping[str, Any],
    write_observations: Sequence[Mapping[str, Any]] = (),
    run_error: Mapping[str, Any] | None = None, status: str = "submitted",
    duration_s: float = 0.0,
) -> dict:
    """Return independent correctness, evidence, false-positive and failure fields."""
    public = public_spec_for_case(case_id)
    expected_app = internal_case_for(case_id)["app_id"]
    all_ids = [row.get("request_id") for row in trace_rows
               if row.get("tool_name") == "send_request" and row.get("run_id") == run_id
               and row.get("request_id")]
    rows = _rows_for(run_id, trace_rows)
    failure = dict(run_error) if run_error else None
    if status != "submitted" or finding is None:
        failure = failure or {"category": "missing_finding", "code": "MISSING_FINDING"}
    verdict = finding.get("verdict") if finding and failure is None else None
    is_vuln = truth_case["ground_truth"] is True
    abstained = verdict == "insufficient_evidence"
    classification_error = bool(is_vuln and verdict == "vulnerable" and
                                finding.get("vulnerability_type") != truth_case["vulnerability_type"])
    correct = None if failure or abstained else (
        verdict == "vulnerable" and not classification_error if is_vuln
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
    elif (not isinstance(cited, list) or not cited
          or any(not isinstance(rid, str) for rid in cited)
          or len(set(cited)) != len(cited)):
        reasons.append("invalid_evidence_ids")
    else:
        if finding.get("identity") != "A":
            reasons.append("wrong_identity")
        if finding.get("resource") != resource_for(public):
            reasons.append("wrong_resource")
        if any(row.get("run_id") != run_id for row in trace_rows):
            reasons.append("mixed_run_trace")
        if any(obs.get("run_id") != run_id for obs in write_observations):
            reasons.append("mixed_run_state")
        if any(rid not in rows or all_ids.count(rid) != 1 for rid in cited):
            reasons.append("unknown_or_foreign_request_id")
        if not reasons:
            target_rows = [(rid, rows[rid]) for rid in cited
                           if rows[rid]["identity"] == "A"
                           and rows[rid].get("arguments", {}).get("method") == public["target_method"]
                           and rows[rid].get("arguments", {}).get("path") == public["target_path"]]
            if not target_rows:
                reasons.append("target_request_missing")
            elif truth_case["oracle_kind"] == "read_body":
                controls = [rows[rid] for rid in cited
                            if rows[rid]["identity"] == "B"
                            and rows[rid]["arguments"].get("method") == "GET"
                            and rows[rid]["arguments"].get("path") == public["target_path"]
                            and rows[rid]["response_status"] == 200
                            and _protected(rows[rid]["response_body"], truth_case)]
                observed = bool(controls) and any(
                    row["response_status"] == (200 if is_vuln else 403)
                    and (_protected(row["response_body"], truth_case) if is_vuln
                         else not _protected(row["response_body"], truth_case))
                    for _, row in target_rows
                )
                if not observed:
                    reasons.append("protected_content_not_observed")
            else:
                if truth_case["oracle_table"] not in {"tickets", "claims"}:
                    reasons.append("unsupported_oracle")
                elif expected_app != ("expense_lab_v1" if public["target_path"].startswith("/claims/") else "ticket_lab_v3"):
                    reasons.append("wrong_app")
                elif not any(_write_evidence(
                    public=public, truth=truth_case, run_id=run_id,
                    candidate_id=rid, rows=rows, cited_ids=set(cited),
                    snapshots=write_observations,
                ) for rid, _ in target_rows):
                    reasons.append("state_change_or_visible_sequence_not_proved")
            if ((is_vuln and verdict != "vulnerable")
                    or (not is_vuln and verdict != "not_vulnerable")):
                reasons.append("observations_do_not_support_verdict")
    preempted = False
    state_changed_by_a = False
    if truth_case["oracle_kind"] == "write_state":
        state_changed_by_a = any(
            state.get("run_id") == run_id and state.get("identity") == "A"
            and state.get("method") == public["target_method"]
            and state.get("path") == public["target_path"]
            and state.get("table") == truth_case["oracle_table"]
            and state.get("object_id") == truth_case["oracle_row_id"]
            and state.get("field") == truth_case["oracle_field"]
            and state.get("request_id") in rows
            and state.get("before") != state.get("after")
            for state in write_observations
        )
        first_a = next((index for index, row in enumerate(trace_rows)
                        if row.get("run_id") == run_id and row.get("tool_name") == "send_request"
                        and row.get("identity") == "A" and row.get("arguments", {}).get("method") == public["target_method"]
                        and row.get("arguments", {}).get("path") == public["target_path"]), None)
        if first_a is not None:
            preempted = any(s.get("run_id") == run_id and s.get("identity") != "A"
                            and s.get("table") == truth_case["oracle_table"]
                            and s.get("object_id") == truth_case["oracle_row_id"]
                            and s.get("field") == truth_case["oracle_field"]
                            and s.get("after") == truth_case["attempted_after"]
                            and s.get("before") != s.get("after")
                            and next((i for i, row in enumerate(trace_rows)
                                      if row.get("run_id") == run_id and row.get("tool_name") == "send_request"
                                      and row.get("request_id") == s.get("request_id")), first_a) < first_a
                            for s in write_observations)
    return {
        "grader_version": GRADER_VERSION, "case_id": case_id, "run_id": run_id,
        "verdict_correct": correct, "evidence_valid": not reasons,
        "evidence_reasons": list(dict.fromkeys(reasons)),
        "evidence_provided": bool(cited),
        "false_positive": false_positive, "false_negative": false_negative,
        "classification_error": classification_error, "abstained": abstained,
        "run_error": failure, "state_changed_by_A": state_changed_by_a,
        "mutation_preempted_by_control": preempted,
        "api_requests": len(all_ids), "duration_s": duration_s,
    }


def grade_run(record: Mapping[str, Any], trace_rows: Sequence[Mapping[str, Any]]) -> dict:
    """Only this module opens private truth JSON. Called after the run finishes."""
    case_id = record["case_id"]
    app = "ticket" if case_id.startswith("T") else "expense"
    path = ROOT / f"cases/v3_{app}_truth.json"
    truth = json.loads(path.read_text(encoding="utf-8"))["cases"][case_id]
    return grade_case(
        case_id=case_id, run_id=record["run_id"], finding=record.get("finding"),
        trace_rows=trace_rows, truth_case=truth,
        write_observations=record.get("write_observations") or (),
        run_error=record.get("run_error"), status=record.get("status", "run_error"),
        duration_s=record.get("duration_s", 0.0),
    )
