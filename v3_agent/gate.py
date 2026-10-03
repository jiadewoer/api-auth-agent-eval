"""Submission feedback from public policy and HTTP observations only.

No truth files, case IDs, SQLite paths, private write snapshots or oracle values.
"""

from __future__ import annotations

from typing import Any, Mapping

from agent.finding import Finding
from v3_agent.protocol import intended_after, read_control, resource_for, write_target


def _field(public: Mapping[str, Any]) -> str:
    return str(public["target_object"]["field"])


def _visible(row: Mapping[str, Any], field: str) -> tuple[bool, Any]:
    body = row.get("body")
    return (field in body, body.get(field)) if isinstance(body, dict) else (False, None)


def evidence_issues(public: Mapping[str, Any], finding: Finding,
                    requests: Mapping[str, Mapping[str, Any]]) -> list[str]:
    if finding.verdict == "insufficient_evidence":
        return []
    issues: list[str] = []
    if finding.identity != "A":
        issues.append("claimed_identity_must_be_A")
    if finding.resource != resource_for(public):
        issues.append("resource_does_not_match_target")
    cited = {rid: requests[rid] for rid in finding.evidence_request_ids if rid in requests}
    ordered = list(requests.items())
    indices = {rid: index for index, (rid, _) in enumerate(ordered)}
    method, path = public["target_method"], public["target_path"]
    candidate = [(rid, row) for rid, row in cited.items()
                 if row["identity"] == "A" and row["method"] == method and row["path"] == path]
    if not candidate:
        return [*issues, "cite_A_target_request"]

    if method == "GET":
        legal = [row for row in cited.values()
                 if row["identity"] == "B" and row["method"] == "GET"
                 and row["path"] == path and row["status_code"] == 200
                 and isinstance(row["body"], list) and row["body"]]
        if not legal:
            issues.append("cite_B_nonempty_legal_GET")
        if finding.verdict == "vulnerable":
            if not any(row["status_code"] == 200 and isinstance(row["body"], list)
                       and row["body"] and any(row["body"] == ctrl["body"] for ctrl in legal)
                       for _, row in candidate):
                issues.append("A_did_not_show_matching_protected_content")
        elif not any(row["status_code"] == 403 for _, row in candidate):
            issues.append("A_denial_not_observed")
        return issues

    control_identity, read_path = read_control(public)
    field = _field(public)
    target_app = "expense_lab_v1" if path.startswith("/claims/") else "ticket_lab_v3"
    target = write_target(target_app, path)
    if target is None:
        return [*issues, "unknown_write_target"]
    expected = intended_after(public)
    for candidate_id, write in candidate:
        earlier = [(rid, row) for rid, row in cited.items()
                   if row["identity"] == control_identity and row["method"] == "GET"
                   and row["path"] == read_path and row["status_code"] == 200
                   and indices[rid] < indices[candidate_id]]
        later = [(rid, row) for rid, row in cited.items()
                 if row["identity"] == control_identity and row["method"] == "GET"
                 and row["path"] == read_path and row["status_code"] == 200
                 and indices[rid] > indices[candidate_id]]
        if not earlier or not later:
            continue
        before_id, before = earlier[-1]
        after_id, after = later[0]
        # Attribution fails if *any* other write to this field occurs between
        # the visible before/after GETs, even when that write was not cited.
        if any(rid != candidate_id and row["method"] == "POST"
               and write_target(target_app, row["path"]) == target
               for rid, row in ordered[indices[before_id]+1:indices[after_id]]):
            continue
        present_before, old = _visible(before, field)
        present_after, new = _visible(after, field)
        if not present_before or not present_after:
            continue  # T02's null is valid; missing field is not.
        if finding.verdict == "vulnerable" and write["status_code"] == 200:
            if old != new and new == expected:
                return issues
        if finding.verdict == "not_vulnerable" and write["status_code"] == 403:
            if old == new:
                return issues
    issues.append("cite_clean_B_GET_A_POST_B_GET_sequence")
    return issues
