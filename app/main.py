"""Six lab routes; the hidden case selector changes one authorization guard per pair."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from app.auth import LabUser, can_read_ticket, get_current_user
from app.db import get_connection, seed
from app.permissions import (
    can_close_ticket,
    can_read_private_comments,
    can_reassign_ticket,
    is_admin,
)


class TicketOut(BaseModel):
    id: int
    owner_id: str
    title: str
    body: str
    status: str


class CommentOut(BaseModel):
    id: int
    ticket_id: int
    author_id: str
    body: str


class CloseOut(BaseModel):
    id: int
    status: str


class ReassignIn(BaseModel):
    new_owner_id: str


class ReassignOut(BaseModel):
    id: int
    owner_id: str


class UserOut(BaseModel):
    id: str
    name: str
    role: str


class TicketExportOut(BaseModel):
    id: int
    owner_id: str
    shared_with_id: str | None
    title: str
    body: str
    status: str


class ExportOut(BaseModel):
    users: list[UserOut]
    tickets: list[TicketExportOut]
    comments: list[CommentOut]


class AuditOut(BaseModel):
    id: int
    actor_id: str
    ticket_id: int | None
    action: str
    created_at: str


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_app(
    case_id: str = "P01_fixed", db_path: str | Path = "data/manual.sqlite"
) -> FastAPI:
    """Seed once at creation; every ordinary request uses the same database."""
    if case_id not in {
        "P01_fixed", "P01_vuln", "P02_fixed", "P02_vuln",
        "P03_fixed", "P03_vuln", "P04_fixed", "P04_vuln",
        "P05_fixed", "P05_vuln", "P06_fixed", "P06_vuln",
    }:
        raise ValueError(f"Unsupported case_id: {case_id}")

    seed(db_path)
    application = FastAPI(title="Local API Authorization Lab")

    @application.get("/tickets/{ticket_id}", response_model=TicketOut)
    def read_ticket(
        ticket_id: int,
        user: Annotated[LabUser, Depends(get_current_user)],
    ) -> TicketOut:
        conn = get_connection(db_path)
        try:
            row = conn.execute(
                """SELECT id, owner_id, shared_with_id, title, body, status
                   FROM tickets WHERE id = ?""",
                (ticket_id,),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            raise HTTPException(status_code=404, detail="Ticket not found")
        # P01's only changed guard: A can read B's private ticket 201 in this case.
        allowed = can_read_ticket(user, row)
        if case_id == "P01_vuln" and user.id == "A" and row["id"] == 201:
            allowed = True
        if not allowed:
            raise HTTPException(status_code=403, detail="Access denied")

        return TicketOut(
            id=row["id"],
            owner_id=row["owner_id"],
            title=row["title"],
            body=row["body"],
            status=row["status"],
        )

    @application.get("/tickets/{ticket_id}/comments", response_model=list[CommentOut])
    def read_comments(
        ticket_id: int,
        user: Annotated[LabUser, Depends(get_current_user)],
    ) -> list[CommentOut]:
        conn = get_connection(db_path)
        try:
            ticket = conn.execute(
                "SELECT id, owner_id FROM tickets WHERE id = ?", (ticket_id,)
            ).fetchone()
            if ticket is None:
                raise HTTPException(status_code=404, detail="Ticket not found")
            # P02's only changed guard: A may read B's private 201 comments.
            allowed = can_read_private_comments(conn, user, ticket)
            if case_id == "P02_vuln" and user.id == "A" and ticket["id"] == 201:
                allowed = True
            if not allowed:
                raise HTTPException(status_code=403, detail="Access denied")

            rows = conn.execute(
                """SELECT id, ticket_id, author_id, body FROM comments
                   WHERE ticket_id = ? ORDER BY id""",
                (ticket_id,),
            ).fetchall()
            return [CommentOut(**dict(row)) for row in rows]
        finally:
            conn.close()

    @application.post("/tickets/{ticket_id}/close", response_model=CloseOut)
    def close_ticket(
        ticket_id: int,
        user: Annotated[LabUser, Depends(get_current_user)],
    ) -> CloseOut:
        conn = get_connection(db_path)
        try:
            ticket = conn.execute(
                "SELECT id, owner_id, status FROM tickets WHERE id = ?", (ticket_id,)
            ).fetchone()
            if ticket is None:
                raise HTTPException(status_code=404, detail="Ticket not found")
            # P03's only changed guard: A may close B's 201 ticket.
            allowed = can_close_ticket(conn, user, ticket)
            if case_id == "P03_vuln" and user.id == "A" and ticket["id"] == 201:
                allowed = True
            if not allowed:
                raise HTTPException(status_code=403, detail="Access denied")

            # A repeated close returns 200, stays closed, and adds no audit event.
            if ticket["status"] == "open":
                with conn:
                    update = conn.execute(
                        """UPDATE tickets SET status = 'closed'
                           WHERE id = ? AND status = 'open'""",
                        (ticket_id,),
                    )
                    if update.rowcount:
                        conn.execute(
                            """INSERT INTO audit (actor_id, ticket_id, action, created_at)
                               VALUES (?, ?, ?, ?)""",
                            (user.id, ticket_id, "ticket-closed", _now_utc()),
                        )
            return CloseOut(id=ticket_id, status="closed")
        finally:
            conn.close()

    @application.post("/tickets/{ticket_id}/reassign", response_model=ReassignOut)
    def reassign_ticket(
        ticket_id: int,
        payload: ReassignIn,
        user: Annotated[LabUser, Depends(get_current_user)],
    ) -> ReassignOut:
        conn = get_connection(db_path)
        try:
            # Check the admin role before even looking up the protected ticket.
            # P05's only changed guard: the administrator role gate is absent.
            if case_id != "P05_vuln" and not can_reassign_ticket(conn, user):
                raise HTTPException(status_code=403, detail="Access denied")

            ticket = conn.execute(
                "SELECT id, owner_id FROM tickets WHERE id = ?", (ticket_id,)
            ).fetchone()
            if ticket is None:
                raise HTTPException(status_code=404, detail="Ticket not found")

            target = conn.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'user'",
                (payload.new_owner_id,),
            ).fetchone()
            if target is None:
                raise HTTPException(
                    status_code=400, detail="New owner must be an existing user"
                )

            if ticket["owner_id"] != target["id"]:
                with conn:
                    conn.execute(
                        "UPDATE tickets SET owner_id = ? WHERE id = ?",
                        (target["id"], ticket_id),
                    )
                    conn.execute(
                        """INSERT INTO audit (actor_id, ticket_id, action, created_at)
                           VALUES (?, ?, ?, ?)""",
                        (
                            user.id,
                            ticket_id,
                            f"ticket-reassigned:{ticket['owner_id']}->{target['id']}",
                            _now_utc(),
                        ),
                    )
            return ReassignOut(id=ticket_id, owner_id=target["id"])
        finally:
            conn.close()

    @application.get("/admin/export", response_model=ExportOut)
    def export_data(
        user: Annotated[LabUser, Depends(get_current_user)],
    ) -> ExportOut:
        conn = get_connection(db_path)
        try:
            # P04's only changed guard: the role gate is absent in this case.
            if case_id != "P04_vuln" and not is_admin(conn, user):
                raise HTTPException(status_code=403, detail="Access denied")

            users = conn.execute(
                "SELECT id, name, role FROM users ORDER BY id"
            ).fetchall()
            tickets = conn.execute(
                """SELECT id, owner_id, shared_with_id, title, body, status
                   FROM tickets ORDER BY id"""
            ).fetchall()
            comments = conn.execute(
                "SELECT id, ticket_id, author_id, body FROM comments ORDER BY id"
            ).fetchall()
            return ExportOut(
                users=[UserOut(**dict(row)) for row in users],
                tickets=[TicketExportOut(**dict(row)) for row in tickets],
                comments=[CommentOut(**dict(row)) for row in comments],
            )
        finally:
            conn.close()

    @application.get("/admin/audit", response_model=list[AuditOut])
    def read_audit(
        user: Annotated[LabUser, Depends(get_current_user)],
    ) -> list[AuditOut]:
        conn = get_connection(db_path)
        try:
            # P06's only changed guard: the administrator role gate is absent.
            if case_id != "P06_vuln" and not is_admin(conn, user):
                raise HTTPException(status_code=403, detail="Access denied")

            rows = conn.execute(
                """SELECT id, actor_id, ticket_id, action, created_at
                   FROM audit ORDER BY id"""
            ).fetchall()
            return [AuditOut(**dict(row)) for row in rows]
        finally:
            conn.close()

    return application


app = create_app(
    case_id=os.environ.get("LAB_CASE_ID", "P01_fixed"),
    db_path=os.environ.get("LAB_DB_PATH", "data/manual.sqlite"),
)
