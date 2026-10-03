"""V4 development-only public routes and bounded tool contract."""

from __future__ import annotations

import re
from typing import Any

from v3_agent.protocol import MAX_BODY_BYTES, MAX_DECISIONS, MAX_REQUESTS, bearer_for as v3_bearer


_ID = r"(0|[1-9][0-9]{0,18})"
_ROUTES = {
    "ticket_lab_v4": (
        ("GET", re.compile(rf"/tickets/{_ID}/priority")),
        ("POST", re.compile(rf"/tickets/{_ID}/priority")),
        ("POST", re.compile(rf"/tickets/{_ID}/escalate")),
    ),
    "expense_lab_v4": (
        ("GET", re.compile(rf"/claims/{_ID}/cost_center")),
        ("POST", re.compile(rf"/claims/{_ID}/change_cost_center")),
        ("GET", re.compile(rf"/claims/{_ID}/review_state")),
        ("POST", re.compile(rf"/claims/{_ID}/mark_reviewed")),
    ),
}
_DOCS = {
    "ticket_lab_v4": (
        "GET /tickets/{id}/priority: owner, administrator and shared reader may read; "
        "POST /tickets/{id}/priority with {priority:high}: owner or administrator only; "
        "POST /tickets/{id}/escalate with null body: administrator only, including when the owner is not an administrator."
    ),
    "expense_lab_v4": (
        "GET /claims/{id}/cost_center: owner or finance may read; "
        "POST /claims/{id}/change_cost_center with {cost_center:dept-A}: owner only while submitted; "
        "GET /claims/{id}/review_state: owner, finance and shared summary reader may read; "
        "POST /claims/{id}/mark_reviewed with null body: finance only, including when the owner is a claimant."
    ),
}


def public_api_for(app_id: str) -> str:
    return _DOCS[app_id]


def bearer_for(app_id: str, identity: str) -> str:
    mapped = {"ticket_lab_v4": "ticket_lab_v3", "expense_lab_v4": "expense_lab_v1"}
    return v3_bearer(mapped[app_id], identity)


def route_match(app_id: str, method: Any, path: Any) -> bool:
    if (app_id not in _ROUTES or method not in ("GET", "POST")
            or not isinstance(path, str) or len(path) > 64):
        return False
    for expected, pattern in _ROUTES[app_id]:
        match = pattern.fullmatch(path) if method == expected else None
        if match and int(match[1]) <= 9223372036854775807:
            return True
    return False


def valid_body(app_id: str, method: str, path: str, body: Any) -> bool:
    if not route_match(app_id, method, path):
        return False
    if method == "GET" or path.endswith(("/escalate", "/mark_reviewed")):
        return body is None
    if app_id == "ticket_lab_v4" and path.endswith("/priority"):
        return isinstance(body, dict) and body == {"priority": "high"}
    if app_id == "expense_lab_v4" and path.endswith("/change_cost_center"):
        return isinstance(body, dict) and body == {"cost_center": "dept-A"}
    return False


def write_target(app_id: str, path: str) -> tuple[str, int, str] | None:
    if app_id == "ticket_lab_v4":
        match = re.fullmatch(rf"/tickets/{_ID}/(priority|escalate)", path)
        return ("tickets", int(match[1]), "priority") if match else None
    if app_id == "expense_lab_v4":
        match = re.fullmatch(rf"/claims/{_ID}/(change_cost_center|mark_reviewed)", path)
        if match:
            return "claims", int(match[1]), "cost_center" if match[2] == "change_cost_center" else "review_state"
    return None
