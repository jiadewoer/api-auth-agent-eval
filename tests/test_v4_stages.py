"""Mechanism scoring separates real writes, visible proof and classification."""

from __future__ import annotations

from copy import deepcopy

import pytest

from v4_lab.catalog import public_spec_for_case, truth_for_case
from v4_lab.stages import score_write_stages


def _run(pair="T05"):
    case_id, run_id = f"{pair}_vuln", "unit-run"
    public, truth = public_spec_for_case(case_id), truth_for_case(case_id)
    field = truth["oracle_field"]
    old, new = truth["before"], truth["attempted_after"]
    control, target = public["control_path"], public["target_path"]
    def row(step, rid, identity, method, path, status, body):
        return {"run_id": run_id, "step": step, "tool_name": "send_request",
                "request_id": rid, "identity": identity,
                "arguments": {"identity": identity, "method": method, "path": path,
                              "json_body": public["request_body"] if method == "POST" else None},
                "response_status": status, "response_body": body, "error": None}
    trace = [row(1, "r001", "B", "GET", control, 200, {field: old}),
             row(2, "r002", "A", "POST", target, 200, {field: new}),
             row(3, "r003", "B", "GET", control, 200, {field: new})]
    cited = ["r001", "r002", "r003"]
    finding = {"verdict": "vulnerable", "vulnerability_type": truth["vulnerability_type"],
               "identity": "A", "resource": f"{public['target_object']['kind']}_{truth['oracle_row_id']}",
               "evidence_request_ids": cited, "explanation": "Visible unauthorized change"}
    trace.extend([
        {"run_id": run_id, "step": 4, "tool_name": "evidence_gate",
         "arguments": {"request_ids": cited}, "response_body": {"accepted": True}},
        {"run_id": run_id, "step": 5, "tool_name": "submit_finding",
         "arguments": finding, "response_body": {"accepted": True}},
    ])
    record = {"run_id": run_id, "case_id": case_id, "status": "submitted",
              "finding": finding, "run_error": None,
              "write_observations": [{"run_id": run_id, "request_id": "r002",
                "identity": "A", "method": "POST", "path": target,
                "table": truth["oracle_table"], "object_id": truth["oracle_row_id"],
                "field": field, "before": old, "after": new}]}
    return public, truth, record, trace


@pytest.mark.parametrize("pair", ("T05", "T06", "E05", "E06"))
def test_full_stages_for_all_dev_mechanisms(pair):
    public, truth, record, trace = _run(pair)
    result = score_write_stages(public=public, truth=truth, record=record, trace=trace)
    assert [result[f"s{i}"] for i in range(1, 5)] == [True] * 4
    assert result["cited_clean_sequence"] == ["r001", "r002", "r003"]


def test_missing_prior_or_later_get_remains_at_s1():
    for lost in ("r001", "r003"):
        public, truth, record, trace = _run()
        trace[:] = [row for row in trace if row.get("request_id") != lost]
        result = score_write_stages(public=public, truth=truth, record=record, trace=trace)
        assert (result["s1"], result["s2"], result["s3"], result["s4"]) == (True, False, False, False)


def test_wrong_value_or_foreign_identity_breaks_visible_sequence():
    for change in ("value", "identity"):
        public, truth, record, trace = _run()
        if change == "value":
            trace[2]["response_body"][truth["oracle_field"]] = truth["before"]
        else:
            trace[2]["identity"] = "A"
        result = score_write_stages(public=public, truth=truth, record=record, trace=trace)
        assert result["s1"] and not result["s2"]


def test_preemptive_and_post_target_control_mutations_are_distinct():
    for placement in ("before", "after", "between"):
        public, truth, record, trace = _run("T06")
        other = deepcopy(record["write_observations"][0])
        other.update(identity="M", request_id="r004", path=public["target_path"],
                     before=("draft" if placement == "before" else "escalated"),
                     after=("normal" if placement != "after" else "elevated"))
        record["write_observations"].append(other)
        request = deepcopy(trace[1])
        request.update(request_id="r004", identity="M")
        request["arguments"] = {**request["arguments"], "identity": "M"}
        insert = 0 if placement == "before" else 2 if placement == "between" else 3
        trace.insert(insert, request)
        if placement == "between":
            restored = deepcopy(other)
            restored.update(request_id="r005", before="normal", after="escalated")
            record["write_observations"].append(restored)
            second_request = deepcopy(request)
            second_request["request_id"] = "r005"
            trace.insert(insert + 1, second_request)
        result = score_write_stages(public=public, truth=truth, record=record, trace=trace)
        if placement == "between":
            assert result["s1"] and not result["s2"]
        else:
            assert result["s2"]
        group = "before" if placement == "before" else "after"
        assert result["control_mutation_request_ids"][group] == (
            ["r004", "r005"] if placement == "between" else ["r004"])


def test_uncited_sequence_and_wrong_type_are_separate_failures():
    public, truth, record, trace = _run("E06")
    record["finding"]["evidence_request_ids"] = ["r002"]
    trace[-2]["arguments"]["request_ids"] = ["r002"]
    assert score_write_stages(public=public, truth=truth, record=record, trace=trace)["failure_stage"] == "S3"
    public, truth, record, trace = _run("E06")
    record["finding"]["vulnerability_type"] = "BOLA"
    assert score_write_stages(public=public, truth=truth, record=record, trace=trace)["failure_stage"] == "S4"


def test_gate_rejection_or_foreign_evidence_cannot_be_s3():
    for variant in ("gate", "foreign"):
        public, truth, record, trace = _run()
        if variant == "gate":
            trace[-2]["response_body"] = {"issues": ["bad"]}
        else:
            record["finding"]["evidence_request_ids"].append("r999")
        result = score_write_stages(public=public, truth=truth, record=record, trace=trace)
        assert result["s2"] and not result["s3"]


def test_timeout_still_records_prior_write_and_sequence():
    public, truth, record, trace = _run()
    record.update(status="run_error", finding=None,
                  run_error={"category": "model_timeout", "code": "MODEL_TIMEOUT"})
    result = score_write_stages(public=public, truth=truth, record=record, trace=trace)
    assert result["s1"] and result["s2"] and not result["s3"]
    assert result["run_error"]["code"] == "MODEL_TIMEOUT"


def test_fixed_state_and_false_positive():
    public, truth, record, trace = _run()
    record["case_id"] = "T05_fixed"
    truth = truth_for_case("T05_fixed")
    trace[1]["response_status"] = 403
    record["write_observations"][0]["after"] = truth["before"]
    result = score_write_stages(public=public, truth=truth, record=record, trace=trace)
    assert not any(result[f"s{i}"] for i in range(1, 5))
    assert result["fixed_false_positive"]


def test_mixed_run_and_duplicate_request_rejected():
    public, truth, record, trace = _run()
    trace[0]["run_id"] = "foreign"
    with pytest.raises(ValueError, match="Mixed-run"):
        score_write_stages(public=public, truth=truth, record=record, trace=trace)
    trace[0]["run_id"] = record["run_id"]
    trace.insert(1, deepcopy(trace[0]))
    with pytest.raises(ValueError, match="Duplicate"):
        score_write_stages(public=public, truth=truth, record=record, trace=trace)
