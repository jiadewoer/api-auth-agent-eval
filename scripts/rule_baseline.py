"""Fixed-flow authorization baseline: does not import or open truth.json.

Run from the project root with: python -m scripts.rule_baseline
The evaluator's case_id selects the lab instance; the decision function only
receives a public task, HTTP responses, and a read-only state observation.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app
from cases.catalog import public_spec_for_case


PAIR_IDS = ("P01", "P02", "P03", "P04", "P05", "P06")
CASE_IDS = tuple(f"{pair}_{variant}" for pair in PAIR_IDS for variant in ("fixed", "vuln"))

# These are written by a human tester from the visible business rules.
# They are NOT answers about which server variant contains a vulnerability.
LEGAL_IDENTITY = {
    "GET /tickets/201": "B",
    "GET /tickets/201/comments": "B",
    "POST /tickets/201/close": "B",
    "GET /admin/export": "M",
    "POST /tickets/201/reassign": "M",
    "GET /admin/audit": "M",
}
WRITE_FIELDS = {
    "POST /tickets/201/close": "status",
    "POST /tickets/201/reassign": "owner_id",
}


def _auth(identity: str) -> dict[str, str]:
    # This injection is inside the runner. No raw Bearer token goes to an Agent.
    return {"Authorization": f"Bearer lab-token-{identity.lower()}"}


def _field(db_path: Path, field: str) -> str:
    if field not in {"status", "owner_id"}:
        raise ValueError("Unsupported state field")
    with closing(sqlite3.connect(db_path)) as conn:
        row = conn.execute(f"SELECT {field} FROM tickets WHERE id = ?", (201,)).fetchone()
    return row[0]


def _by_id(rows: list[dict], row_id: int) -> dict:
    return next(row for row in rows if row["id"] == row_id)


def _protected_values(target: str, body) -> dict:
    """Extract specific private fields, rather than mistaking any 200 for proof."""
    if target == "GET /tickets/201":
        return {"owner_id": body["owner_id"], "body": body["body"]}
    if target == "GET /tickets/201/comments":
        return {"comment_body": _by_id(body, 1)["body"]}
    if target == "GET /admin/export":
        return {
            "ticket_body": _by_id(body["tickets"], 201)["body"],
            "comment_body": _by_id(body["comments"], 2)["body"],
        }
    if target == "GET /admin/audit":
        record = _by_id(body, 1)
        return {key: record[key] for key in ("actor_id", "action", "created_at")}
    raise ValueError("Unsupported read target")


def classify_write(
    control_status: int, control_before: str, control_after: str,
    candidate_status: int, candidate_before: str, candidate_after: str,
) -> str:
    """A 200 without a state change is inconclusive, not a confirmed leak."""
    if control_status != 200 or control_before == control_after:
        return "needs_review"
    if (candidate_status == 200 and candidate_before != candidate_after
            and candidate_after == control_after):
        return "confirmed"
    if candidate_status in {401, 403} and candidate_after == candidate_before:
        return "not_observed"
    return "needs_review"


def classify_read(
    control_status: int, control_values: dict | None,
    candidate_status: int, candidate_values: dict | None,
) -> str:
    """Require nonempty protected content from the legal reference request."""
    if control_status != 200 or not control_values:
        return "needs_review"
    if not all(isinstance(value, str) and value for value in control_values.values()):
        return "needs_review"
    if candidate_status == 200 and candidate_values == control_values:
        return "confirmed"
    if candidate_status in {401, 403} and candidate_values is None:
        return "not_observed"
    return "needs_review"


def inspect_case(
    public: dict, control: TestClient, candidate: TestClient,
    control_db: Path, candidate_db: Path,
) -> dict:
    """Decide using only visible task/rules and observations, never case_id."""
    method, path = public["target_method"], public["target_path"]
    target = f"{method} {path}"
    legal_identity = LEGAL_IDENTITY[target]
    payload = {"new_owner_id": "A"} if target.endswith("/reassign") else None
    options = {"json": payload} if payload is not None else {}

    # Separate seeded databases prevent the legitimate write from changing
    # the candidate's starting state before A gets to try the same operation.
    field = WRITE_FIELDS.get(target)
    before_control = _field(control_db, field) if field else None
    before_candidate = _field(candidate_db, field) if field else None
    legal = control.request(method, path, headers=_auth(legal_identity), **options)
    after_control = _field(control_db, field) if field else None
    attempted = candidate.request(method, path, headers=_auth("A"), **options)
    after_candidate = _field(candidate_db, field) if field else None

    observed = {
        "legal_identity": legal_identity,
        "legal_status": legal.status_code,
        "test_identity": "A",
        "test_status": attempted.status_code,
    }
    if field:
        observed.update({
            "field": field,
            "legal_before": before_control, "legal_after": after_control,
            "test_before": before_candidate, "test_after": after_candidate,
        })
        verdict = classify_write(
            legal.status_code, before_control, after_control,
            attempted.status_code, before_candidate, after_candidate,
        )
        evidence = [
            f"{legal_identity} {target}: {before_control} -> {after_control}",
            f"A {target}: {before_candidate} -> {after_candidate}",
        ]
        return {"observed": observed, "verdict": verdict, "evidence": evidence}

    try:
        legal_values = _protected_values(target, legal.json()) if legal.status_code == 200 else None
        test_values = _protected_values(target, attempted.json()) if attempted.status_code == 200 else None
    except (KeyError, IndexError, StopIteration, TypeError, ValueError):
        legal_values = test_values = None
    observed.update({"legal_values": legal_values, "test_values": test_values})
    verdict = classify_read(
        legal.status_code, legal_values, attempted.status_code, test_values
    )
    evidence = [
        f"{legal_identity} {target}: {legal.status_code}, fields={legal_values}",
        f"A {target}: {attempted.status_code}, fields={test_values}",
    ]
    return {"observed": observed, "verdict": verdict, "evidence": evidence}


def run_case(case_id: str) -> dict:
    """Private runner selects server config; inspect_case never sees its name."""
    public = public_spec_for_case(case_id)
    with tempfile.TemporaryDirectory(prefix="auth-baseline-") as directory:
        base = Path(directory)
        control_db, candidate_db = base / "control.sqlite", base / "candidate.sqlite"
        control_app = create_app(case_id, control_db)
        candidate_app = create_app(case_id, candidate_db)
        with TestClient(control_app) as control, TestClient(candidate_app) as candidate:
            result = inspect_case(public, control, candidate, control_db, candidate_db)
    return {"case_id": case_id, **result}


def main() -> None:
    for case_id in CASE_IDS:
        print(json.dumps(run_case(case_id), ensure_ascii=False))


if __name__ == "__main__":
    main()
