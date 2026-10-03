"""Pre-submission check using only the public task and model-visible requests.

No case ID, truth marker, SQLite snapshot, grader output or hidden server
variant enters this module. E1 returns *issues*, never a correct label.
"""

from __future__ import annotations

from typing import Any, Mapping

from agent.finding import Finding
from agent.tools import AgentTools
from pydantic import ValidationError


def _protected_values(path: str, body: Any) -> tuple[str, ...]:
    """Fields named in the public API contract, not private truth markers."""
    if path == "/tickets/201" and isinstance(body, dict):
        values = (body.get("body"),)
    elif path == "/tickets/201/comments" and isinstance(body, list):
        values = tuple(row.get("body") for row in body if isinstance(row, dict))
    elif path == "/admin/export" and isinstance(body, dict):
        values = tuple(row.get("body") for section in ("tickets", "comments")
                       for row in (body.get(section) or []) if isinstance(row, dict))
    elif path == "/admin/audit" and isinstance(body, list):
        values = tuple(row.get(field) for row in body if isinstance(row, dict)
                       for field in ("actor_id", "action", "created_at"))
    else:
        values = ()
    return tuple(value for value in values if isinstance(value, str) and value)


def _resource_allowed(public: Mapping[str, Any], resource: str) -> bool:
    target = public["target_object"]
    if target["kind"] == "ticket_comments":
        return resource in {f"ticket_{target['id']}", f"ticket_comments_{target['id']}"}
    if target["kind"] == "ticket":
        return resource == f"ticket_{target['id']}"
    return resource == target["kind"]


def evidence_issues(
    public: Mapping[str, Any], finding: Finding,
    requests: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Require cited request evidence, never infer a ground-truth label."""
    if finding.verdict == "insufficient_evidence":
        return []  # Abstention is an actual submission, evaluated separately.
    method, path = public["target_method"], public["target_path"]
    cited = [(rid, requests[rid]) for rid in finding.evidence_request_ids if rid in requests]
    issues: list[str] = []
    if finding.identity != "A":
        issues.append("claimed_identity_must_be_A")
    if not _resource_allowed(public, finding.resource):
        issues.append("resource_does_not_match_public_target")
    candidate = [(rid, row) for rid, row in cited
                 if row["identity"] == "A" and row["method"] == method and row["path"] == path]
    if not candidate:
        return [*issues, "cite_A_request_to_target"]

    legal = "M" if path.startswith("/admin/") or path.endswith("/reassign") else "B"
    if method == "GET":
        controls = [row for _, row in cited if row["identity"] == legal
                    and row["method"] == "GET" and row["path"] == path
                    and row["status_code"] == 200]
        if not controls:
            issues.append(f"cite_{legal}_legal_GET_control")
        if finding.verdict == "vulnerable":
            observed = any(row["status_code"] == 200 and
                           _protected_values(path, row["body"]) and
                           any(set(_protected_values(path, row["body"])) &
                               set(_protected_values(path, control["body"]))
                               for control in controls)
                           for _, row in candidate)
            if not observed:
                issues.append("A_did_not_show_matching_protected_content")
        elif not any(row["status_code"] == 403 for _, row in candidate):
            issues.append("A_denial_not_observed")
        return issues

    # A write requires cited, visible before/after GET snapshots bracketing
    # its POST. Unlike the grader, this checker NEVER reads private SQLite.
    read_path = f"/tickets/{public['target_object']['id']}"
    field = "owner_id" if path.endswith("/reassign") else "status"
    ordered = list(requests.items())
    positions = {rid: index for index, (rid, _) in enumerate(ordered)}
    for rid, write in candidate:
        before = [(bid, row) for bid, row in cited
                  if row["identity"] == legal and row["method"] == "GET"
                  and row["path"] == read_path and row["status_code"] == 200
                  and positions[bid] < positions[rid]]
        after = [(aid, row) for aid, row in cited
                 if row["identity"] == legal and row["method"] == "GET"
                 and row["path"] == read_path and row["status_code"] == 200
                 and positions[aid] > positions[rid]]
        if not before or not after:
            continue
        bid, b = before[-1]
        aid, a = after[0]
        # A different write in the observed interval would break attribution.
        if any(row["method"] == "POST" and row["path"].startswith(read_path + "/")
               and key != rid for key, row in ordered[positions[bid] + 1:positions[aid]]):
            continue
        old = b["body"].get(field) if isinstance(b["body"], dict) else None
        new = a["body"].get(field) if isinstance(a["body"], dict) else None
        if old is None or new is None:
            continue
        if finding.verdict == "vulnerable" and write["status_code"] == 200 and old != new:
            if ((field == "status" and new == "closed") or
                (field == "owner_id" and new == (write.get("body") or {}).get("owner_id"))):
                return issues
        if finding.verdict == "not_vulnerable" and write["status_code"] == 403 and old == new:
            return issues
    issues.append("cite_clean_before_A_POST_after_GET_sequence_with_expected_state")
    return issues


class FollowupTools(AgentTools):
    def __init__(self, *args: Any, public: Mapping[str, Any], evidence_gate: bool,
                 **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.public = dict(public)
        self.evidence_gate = evidence_gate
        self.gate_rejections = 0

    def submit_finding(self, verdict: str, vulnerability_type: str | None,
                       identity: str, resource: str, evidence_request_ids: list[str],
                       explanation: str) -> dict:
        args = {"verdict": verdict, "vulnerability_type": vulnerability_type,
                "identity": identity, "resource": resource,
                "evidence_request_ids": evidence_request_ids, "explanation": explanation}
        if self.evidence_gate:
            try:
                finding = Finding.model_validate(args)
            except ValidationError:
                return super().submit_finding(**args)
            if any(rid not in self._requests for rid in finding.evidence_request_ids):
                return super().submit_finding(**args)
            issues = evidence_issues(self.public, finding, self._requests)
            if issues:
                self.gate_rejections += 1
                # Do not return secret truth or database state in feedback.
                self._log("evidence_gate", arguments={"request_ids": evidence_request_ids},
                          response_body={"issues": issues}, error="EVIDENCE_CHECK_FAILED")
                return {"error": {"code": "EVIDENCE_CHECK_FAILED", "issues": issues}}
            self._log("evidence_gate", arguments={"request_ids": evidence_request_ids},
                      response_body={"accepted": True})
        return super().submit_finding(**args)
