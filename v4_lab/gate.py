"""Agent-facing V4 feedback from public task and this run's HTTP only.

No case ID, variant, private snapshot or truth file is consulted here.
"""

from __future__ import annotations

from typing import Any, Mapping

from agent.finding import Finding
from v4_lab.protocol import write_target


def _expected_after(public: Mapping[str, Any]) -> str:
    path = public["target_path"]
    if path.endswith("/escalate"):
        return "escalated"
    if path.endswith("/mark_reviewed"):
        return "reviewed"
    if path.endswith("/priority"):
        return public["request_body"]["priority"]
    return public["request_body"]["cost_center"]


def evidence_issues(public: Mapping[str, Any], finding: Finding,
                    requests: Mapping[str, Mapping[str, Any]]) -> list[str]:
    if finding.verdict == "insufficient_evidence":
        return []
    issues = []
    if finding.identity != "A":
        issues.append("claimed_identity_must_be_A")
    resource = f"{public['target_object']['kind']}_{public['target_object']['id']}"
    if finding.resource != resource:
        issues.append("resource_does_not_match_target")
    cited = {rid: requests[rid] for rid in finding.evidence_request_ids if rid in requests}
    ordered = list(requests.items())
    positions = {rid: i for i, (rid, _) in enumerate(ordered)}
    candidates = [(rid, row) for rid, row in cited.items()
                  if row["identity"] == "A" and row["method"] == public["target_method"]
                  and row["path"] == public["target_path"]]
    if not candidates:
        return [*issues, "cite_A_target_request"]
    control_id, control_path = public["control_identity"], public["control_path"]
    field = public["target_object"]["field"]
    app_id = "ticket_lab_v4" if public["target_path"].startswith("/tickets/") else "expense_lab_v4"
    target = write_target(app_id, public["target_path"])
    expected = _expected_after(public)
    for rid, candidate in candidates:
        earlier = [(control_rid, row) for control_rid, row in cited.items()
                   if row["identity"] == control_id and row["method"] == "GET"
                   and row["path"] == control_path and row["status_code"] == 200
                   and positions[control_rid] < positions[rid]]
        later = [(control_rid, row) for control_rid, row in cited.items()
                 if row["identity"] == control_id and row["method"] == "GET"
                 and row["path"] == control_path and row["status_code"] == 200
                 and positions[control_rid] > positions[rid]]
        if not earlier or not later:
            continue
        first_id, first = earlier[-1]
        last_id, last = later[0]
        if any(other_id != rid and row["method"] == "POST"
               and write_target(app_id, row["path"]) == target
               for other_id, row in ordered[positions[first_id]+1:positions[last_id]]):
            continue
        old_body, new_body = first["body"], last["body"]
        if (not isinstance(old_body, dict) or not isinstance(new_body, dict)
                or field not in old_body or field not in new_body):
            continue
        old, new = old_body[field], new_body[field]
        if finding.verdict == "vulnerable":
            if candidate["status_code"] == 200 and old != new and new == expected:
                return issues
        elif candidate["status_code"] == 403 and old == new:
            return issues
    return [*issues, "cite_clean_B_GET_A_POST_B_GET_sequence"]
