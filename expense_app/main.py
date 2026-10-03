"""A separate, correctly authorized expense-claim API."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from expense_app.auth import ExpenseUser, get_current_user
from expense_app.case_catalog import EXPENSE_CASE_IDS
from expense_app.db import get_connection, seed
from expense_app.permissions import (
    can_approve,
    can_change_payee,
    can_read_claim,
    can_read_private_details,
)


class ClaimOut(BaseModel):
    id: int
    owner_id: str
    amount_cents: int
    summary: str
    status: str
    payee_id: str | None  # Explicitly redacted for a shared reader.


class HistoryOut(BaseModel):
    id: int
    claim_id: int
    actor_id: str
    action: str
    created_at: str


class ApproveOut(BaseModel):
    id: int
    status: str


class PayeeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_payee_id: str


class PayeeOut(BaseModel):
    id: int
    payee_id: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_app(
    db_path: str | Path = "data/expense_manual.sqlite", *, case_id: str = "E01_fixed",
) -> FastAPI:
    """Seed once per application instance, never on an ordinary request."""
    if case_id not in EXPENSE_CASE_IDS:
        raise ValueError("Unsupported expense case")
    seed(db_path)
    application = FastAPI(title="Synthetic Expense Authorization Lab")

    @application.get("/claims/{claim_id}", response_model=ClaimOut)
    def read_claim(
        claim_id: int,
        user: Annotated[ExpenseUser, Depends(get_current_user)],
    ) -> ClaimOut:
        conn = get_connection(db_path)
        try:
            claim = conn.execute(
                """SELECT id, owner_id, shared_with_id, payee_id,
                          amount_cents, summary, status
                   FROM claims WHERE id = ?""",
                (claim_id,),
            ).fetchone()
            if claim is None:
                raise HTTPException(status_code=404, detail="Claim not found")
            if not can_read_claim(user, claim):
                raise HTTPException(status_code=403, detail="Access denied")
            return ClaimOut(
                id=claim["id"],
                owner_id=claim["owner_id"],
                amount_cents=claim["amount_cents"],
                summary=claim["summary"],
                status=claim["status"],
                payee_id=(claim["payee_id"] if can_read_private_details(user, claim)
                          else None),
            )
        finally:
            conn.close()

    @application.get("/claims/{claim_id}/history", response_model=list[HistoryOut])
    def read_history(
        claim_id: int,
        user: Annotated[ExpenseUser, Depends(get_current_user)],
    ) -> list[HistoryOut]:
        conn = get_connection(db_path)
        try:
            claim = conn.execute(
                "SELECT id, owner_id FROM claims WHERE id = ?", (claim_id,)
            ).fetchone()
            if claim is None:
                raise HTTPException(status_code=404, detail="Claim not found")
            # E04: a shared summary is mistakenly treated as history permission.
            e04_shared_history = (
                case_id == "E04_vuln" and claim_id == 601 and user.id == "A"
            )
            if not (can_read_private_details(user, claim) or e04_shared_history):
                raise HTTPException(status_code=403, detail="Access denied")
            rows = conn.execute(
                """SELECT id, claim_id, actor_id, action, created_at
                   FROM history WHERE claim_id = ? ORDER BY id""",
                (claim_id,),
            ).fetchall()
            return [HistoryOut(**dict(row)) for row in rows]
        finally:
            conn.close()

    @application.post("/claims/{claim_id}/approve", response_model=ApproveOut)
    def approve_claim(
        claim_id: int,
        user: Annotated[ExpenseUser, Depends(get_current_user)],
    ) -> ApproveOut:
        conn = get_connection(db_path)
        try:
            # Check the finance role before revealing whether an ID exists.
            # E02: the role check alone differs; the real state update is shared.
            e02_missing_role_check = (
                case_id == "E02_vuln" and claim_id == 501 and user.id == "A"
            )
            if not (can_approve(user) or e02_missing_role_check):
                raise HTTPException(status_code=403, detail="Access denied")
            claim = conn.execute(
                "SELECT id, status FROM claims WHERE id = ?", (claim_id,)
            ).fetchone()
            if claim is None:
                raise HTTPException(status_code=404, detail="Claim not found")
            if claim["status"] != "submitted":
                raise HTTPException(status_code=409, detail="Already approved")

            with conn:
                update = conn.execute(
                    """UPDATE claims SET status = 'approved'
                       WHERE id = ? AND status = 'submitted'""",
                    (claim_id,),
                )
                if update.rowcount != 1:
                    raise HTTPException(status_code=409, detail="Claim changed")
                conn.execute(
                    """INSERT INTO history (claim_id, actor_id, action, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (claim_id, user.id, "claim-approved", _utc_now()),
                )
            return ApproveOut(id=claim_id, status="approved")
        finally:
            conn.close()

    @application.post("/claims/{claim_id}/change_payee", response_model=PayeeOut)
    def change_payee(
        claim_id: int,
        payload: PayeeIn,
        user: Annotated[ExpenseUser, Depends(get_current_user)],
    ) -> PayeeOut:
        conn = get_connection(db_path)
        try:
            claim = conn.execute(
                "SELECT id, owner_id, payee_id, status FROM claims WHERE id = ?",
                (claim_id,),
            ).fetchone()
            if claim is None:
                raise HTTPException(status_code=404, detail="Claim not found")
            # E01's only changed authorization decision. All other routes and
            # identities use the same business rule in both server variants.
            e01_missing_owner_check = (
                case_id == "E01_vuln" and claim_id == 501 and user.id == "A"
            )
            # E03: sharing a summary is incorrectly accepted as payee editing.
            e03_shared_write = (
                case_id == "E03_vuln" and claim_id == 601 and user.id == "A"
            )
            if not (can_change_payee(user, claim) or e01_missing_owner_check
                    or e03_shared_write):
                raise HTTPException(status_code=403, detail="Access denied")
            if claim["status"] != "submitted":
                raise HTTPException(status_code=409, detail="Approved claim cannot change payee")
            target = conn.execute(
                "SELECT id FROM payees WHERE id = ?", (payload.new_payee_id,)
            ).fetchone()
            if target is None:
                raise HTTPException(status_code=400, detail="Unknown synthetic payee")
            if claim["payee_id"] == target["id"]:
                raise HTTPException(status_code=409, detail="Payee unchanged")

            with conn:
                update = conn.execute(
                    """UPDATE claims SET payee_id = ?
                       WHERE id = ? AND payee_id = ? AND status = 'submitted'""",
                    (target["id"], claim_id, claim["payee_id"]),
                )
                if update.rowcount != 1:
                    raise HTTPException(status_code=409, detail="Claim changed")
                conn.execute(
                    """INSERT INTO history (claim_id, actor_id, action, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (claim_id, user.id,
                     f"payee-changed:{claim['payee_id']}->{target['id']}", _utc_now()),
                )
            return PayeeOut(id=claim_id, payee_id=target["id"])
        finally:
            conn.close()

    return application


# Uvicorn imports this once. Tests call create_app with their own tmp_path.
app = create_app(
    os.environ.get("EXPENSE_DB_PATH", "data/expense_manual.sqlite"),
    case_id=os.environ.get("EXPENSE_CASE_ID", "E01_fixed"),
)
