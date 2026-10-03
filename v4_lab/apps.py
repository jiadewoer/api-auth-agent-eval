"""V4 pairs on fresh SQLite databases and real HTTP routes.

The V3 applications are composed with their fixed authorization variants;
their frozen source and result files are never edited by the V4 lab.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from expense_app.auth import ExpenseUser, get_current_user as expense_user
from expense_app.db import get_connection as expense_connection
from expense_app.main import create_app as expense_v3_app
from ticket_v3.auth import LabUser, can_read_ticket, get_current_user as ticket_user
from ticket_v3.db import get_connection as ticket_connection
from ticket_v3.main import create_app as ticket_v3_app
from ticket_v3.permissions import is_admin
from v4_lab.catalog import ALL_CASE_IDS, internal_case_for


class PriorityIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    priority: str


class CostCenterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cost_center: str


class PriorityOut(BaseModel):
    id: int
    priority: str


class CostCenterOut(BaseModel):
    id: int
    cost_center: str


class ReviewStateOut(BaseModel):
    id: int
    review_state: str


def _seed_ticket(path: str | Path, spec: dict) -> None:
    target_id = int(spec["target_object"]["id"])
    is_function_case = spec["target_path"].endswith("/escalate")
    owner_id, shared_with_id = ("A", "B") if is_function_case else ("B", "A")
    conn = ticket_connection(path)
    try:
        with conn:
            fields = {row[1] for row in conn.execute("PRAGMA table_info(tickets)")}
            if "priority" not in fields:
                conn.execute("ALTER TABLE tickets ADD COLUMN priority TEXT NOT NULL DEFAULT 'normal'")
            conn.executemany(
                """INSERT INTO tickets
                   (id, owner_id, shared_with_id, title, body, status, priority)
                   VALUES (?, ?, ?, ?, ?, 'open', 'normal')""",
                [(target_id, owner_id, shared_with_id,
                  f"V4 ticket {target_id}", f"ticket-{target_id}")],
            )
    finally:
        conn.close()


def _seed_expense(path: str | Path, spec: dict) -> None:
    target_id = int(spec["target_object"]["id"])
    is_function_case = spec["target_path"].endswith("/mark_reviewed")
    owner_id, shared_with_id = ("A", "B") if is_function_case else ("B", "A")
    conn = expense_connection(path)
    try:
        with conn:
            fields = {row[1] for row in conn.execute("PRAGMA table_info(claims)")}
            if "cost_center" not in fields:
                conn.execute("ALTER TABLE claims ADD COLUMN cost_center TEXT NOT NULL DEFAULT 'dept-B'")
            if "review_state" not in fields:
                conn.execute("ALTER TABLE claims ADD COLUMN review_state TEXT NOT NULL DEFAULT 'pending'")
            conn.executemany(
                """INSERT INTO claims
                   (id, owner_id, shared_with_id, payee_id, amount_cents,
                    summary, status, cost_center, review_state)
                   VALUES (?, ?, ?, 'payee-B', ?, ?, 'submitted', 'dept-B', 'pending')""",
                [(target_id, owner_id, shared_with_id,
                  2500 + target_id, f"V4 claim {target_id}")],
            )
    finally:
        conn.close()


def _vulnerable_target(case_id: str, object_id: int, suffix: str) -> bool:
    spec = internal_case_for(case_id)
    return (case_id.endswith("_vuln") and spec["target_path"].endswith(suffix)
            and int(spec["target_object"]["id"]) == object_id)


def create_ticket_app(case_id: str, db_path: str | Path) -> FastAPI:
    if case_id not in ALL_CASE_IDS or not case_id.startswith("T"):
        raise ValueError("Not a V4 ticket case")
    spec = internal_case_for(case_id)
    # No V3 vulnerability is enabled in this composed app.
    application = ticket_v3_app("T04_fixed", db_path)
    _seed_ticket(db_path, spec)

    @application.get("/tickets/{ticket_id}/priority", response_model=PriorityOut)
    def read_priority(ticket_id: int, user: Annotated[LabUser, Depends(ticket_user)]) -> PriorityOut:
        conn = ticket_connection(db_path)
        try:
            ticket = conn.execute(
                "SELECT id, owner_id, shared_with_id, priority FROM tickets WHERE id = ?",
                (ticket_id,),
            ).fetchone()
            if ticket is None:
                raise HTTPException(status_code=404, detail="Ticket not found")
            if not can_read_ticket(user, ticket):
                raise HTTPException(status_code=403, detail="Access denied")
            return PriorityOut(id=ticket_id, priority=ticket["priority"])
        finally:
            conn.close()

    @application.post("/tickets/{ticket_id}/priority", response_model=PriorityOut)
    def change_priority(ticket_id: int, payload: PriorityIn,
                        user: Annotated[LabUser, Depends(ticket_user)]) -> PriorityOut:
        conn = ticket_connection(db_path)
        try:
            ticket = conn.execute(
                "SELECT id, owner_id, priority FROM tickets WHERE id = ?", (ticket_id,),
            ).fetchone()
            if ticket is None:
                raise HTTPException(status_code=404, detail="Ticket not found")
            allowed = ticket["owner_id"] == user.id or is_admin(conn, user)
            if _vulnerable_target(case_id, ticket_id, "/priority") and user.id == "A":
                allowed = True  # Confuses sharing with object write permission.
            if not allowed:
                raise HTTPException(status_code=403, detail="Access denied")
            if payload.priority != "high":
                raise HTTPException(status_code=400, detail="Invalid priority")
            if ticket["priority"] != "normal":
                raise HTTPException(status_code=409, detail="Priority already changed")
            with conn:
                conn.execute("UPDATE tickets SET priority = 'high' WHERE id = ?", (ticket_id,))
            return PriorityOut(id=ticket_id, priority="high")
        finally:
            conn.close()

    @application.post("/tickets/{ticket_id}/escalate", response_model=PriorityOut)
    def escalate(ticket_id: int, user: Annotated[LabUser, Depends(ticket_user)]) -> PriorityOut:
        conn = ticket_connection(db_path)
        try:
            allowed = is_admin(conn, user)
            if _vulnerable_target(case_id, ticket_id, "/escalate") and user.id == "A":
                allowed = True  # Function role check omitted for the target actor.
            if not allowed:
                raise HTTPException(status_code=403, detail="Access denied")
            ticket = conn.execute("SELECT priority FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            if ticket is None:
                raise HTTPException(status_code=404, detail="Ticket not found")
            if ticket["priority"] != "normal":
                raise HTTPException(status_code=409, detail="Already escalated")
            with conn:
                conn.execute("UPDATE tickets SET priority = 'escalated' WHERE id = ?", (ticket_id,))
            return PriorityOut(id=ticket_id, priority="escalated")
        finally:
            conn.close()
    return application


def create_expense_app(case_id: str, db_path: str | Path) -> FastAPI:
    if case_id not in ALL_CASE_IDS or not case_id.startswith("E"):
        raise ValueError("Not a V4 expense case")
    spec = internal_case_for(case_id)
    application = expense_v3_app(db_path, case_id="E04_fixed")
    _seed_expense(db_path, spec)

    @application.get("/claims/{claim_id}/cost_center", response_model=CostCenterOut)
    def read_cost_center(claim_id: int, user: Annotated[ExpenseUser, Depends(expense_user)]) -> CostCenterOut:
        conn = expense_connection(db_path)
        try:
            claim = conn.execute(
                "SELECT id, owner_id, cost_center FROM claims WHERE id = ?", (claim_id,),
            ).fetchone()
            if claim is None:
                raise HTTPException(status_code=404, detail="Claim not found")
            if claim["owner_id"] != user.id and user.role != "finance":
                raise HTTPException(status_code=403, detail="Access denied")
            return CostCenterOut(id=claim_id, cost_center=claim["cost_center"])
        finally:
            conn.close()

    @application.post("/claims/{claim_id}/change_cost_center", response_model=CostCenterOut)
    def change_cost_center(claim_id: int, payload: CostCenterIn,
                           user: Annotated[ExpenseUser, Depends(expense_user)]) -> CostCenterOut:
        conn = expense_connection(db_path)
        try:
            claim = conn.execute(
                "SELECT id, owner_id, cost_center, status FROM claims WHERE id = ?",
                (claim_id,),
            ).fetchone()
            if claim is None:
                raise HTTPException(status_code=404, detail="Claim not found")
            allowed = user.role == "claimant" and claim["owner_id"] == user.id
            if _vulnerable_target(case_id, claim_id, "/change_cost_center") and user.id == "A":
                allowed = True  # Shared summary incorrectly grants object write access.
            if not allowed:
                raise HTTPException(status_code=403, detail="Access denied")
            if payload.cost_center != "dept-A":
                raise HTTPException(status_code=400, detail="Invalid cost center")
            if claim["status"] != "submitted" or claim["cost_center"] != "dept-B":
                raise HTTPException(status_code=409, detail="Claim cannot be updated")
            with conn:
                conn.execute("UPDATE claims SET cost_center = 'dept-A' WHERE id = ?", (claim_id,))
            return CostCenterOut(id=claim_id, cost_center="dept-A")
        finally:
            conn.close()

    @application.get("/claims/{claim_id}/review_state", response_model=ReviewStateOut)
    def read_review_state(claim_id: int, user: Annotated[ExpenseUser, Depends(expense_user)]) -> ReviewStateOut:
        conn = expense_connection(db_path)
        try:
            claim = conn.execute(
                "SELECT id, owner_id, shared_with_id, review_state FROM claims WHERE id = ?",
                (claim_id,),
            ).fetchone()
            if claim is None:
                raise HTTPException(status_code=404, detail="Claim not found")
            if not (claim["owner_id"] == user.id or claim["shared_with_id"] == user.id
                    or user.role == "finance"):
                raise HTTPException(status_code=403, detail="Access denied")
            return ReviewStateOut(id=claim_id, review_state=claim["review_state"])
        finally:
            conn.close()

    @application.post("/claims/{claim_id}/mark_reviewed", response_model=ReviewStateOut)
    def mark_reviewed(claim_id: int, user: Annotated[ExpenseUser, Depends(expense_user)]) -> ReviewStateOut:
        conn = expense_connection(db_path)
        try:
            allowed = user.role == "finance"
            if _vulnerable_target(case_id, claim_id, "/mark_reviewed") and user.id == "A":
                allowed = True  # Function role check omitted for the target actor.
            if not allowed:
                raise HTTPException(status_code=403, detail="Access denied")
            claim = conn.execute("SELECT review_state FROM claims WHERE id = ?", (claim_id,)).fetchone()
            if claim is None:
                raise HTTPException(status_code=404, detail="Claim not found")
            if claim["review_state"] != "pending":
                raise HTTPException(status_code=409, detail="Already reviewed")
            with conn:
                conn.execute("UPDATE claims SET review_state = 'reviewed' WHERE id = ?", (claim_id,))
            return ReviewStateOut(id=claim_id, review_state="reviewed")
        finally:
            conn.close()
    return application


def create_app(case_id: str, db_path: str | Path) -> FastAPI:
    if case_id.startswith("T"):
        return create_ticket_app(case_id, db_path)
    if case_id.startswith("E"):
        return create_expense_app(case_id, db_path)
    raise ValueError("Not a V4 case")
