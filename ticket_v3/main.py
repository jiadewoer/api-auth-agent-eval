"""V3 ticket cases; old P01–P06 application stays in app/."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from ticket_v3.auth import LabUser, can_read_ticket, get_current_user
from ticket_v3.db import get_connection, seed, seed_v3
from ticket_v3.case_catalog import TICKET_CASE_IDS
from ticket_v3.permissions import (
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


class ShareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    shared_with_id: str


class ShareOut(BaseModel):
    id: int
    shared_with_id: str


class SharingOut(BaseModel):
    id: int
    shared_with_id: str | None


class NoteOut(BaseModel):
    id: int
    ticket_id: int
    body: str


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_app(
    case_id: str = "T01_fixed", db_path: str | Path = "data/ticket_v3_manual.sqlite"
) -> FastAPI:
    """Seed once at creation; every ordinary request uses the same database."""
    if case_id not in TICKET_CASE_IDS:
        raise ValueError(f"Unsupported case_id: {case_id}")

    seed(db_path)
    seed_v3(db_path)
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
        allowed = can_read_ticket(user, row)
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
            allowed = can_read_private_comments(conn, user, ticket)
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
            allowed = can_close_ticket(conn, user, ticket)
            if case_id == "T01_vuln" and user.id == "A" and ticket["id"] == 301:
                allowed = True  # Shared-body read was mistaken for close permission.
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
            if not can_reassign_ticket(conn, user):
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
            if not is_admin(conn, user):
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
            if not is_admin(conn, user):
                raise HTTPException(status_code=403, detail="Access denied")

            rows = conn.execute(
                """SELECT id, actor_id, ticket_id, action, created_at
                   FROM audit ORDER BY id"""
            ).fetchall()
            return [AuditOut(**dict(row)) for row in rows]
        finally:
            conn.close()

    if case_id in TICKET_CASE_IDS:
        @application.get("/tickets/{ticket_id}/sharing", response_model=SharingOut)
        def read_sharing(
            ticket_id: int,
            user: Annotated[LabUser, Depends(get_current_user)],
        ) -> SharingOut:
            conn = get_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT id, owner_id, shared_with_id FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Ticket not found")
                if row["owner_id"] != user.id and not is_admin(conn, user):
                    raise HTTPException(status_code=403, detail="Access denied")
                return SharingOut(id=ticket_id, shared_with_id=row["shared_with_id"])
            finally:
                conn.close()

        @application.post("/tickets/{ticket_id}/share", response_model=ShareOut)
        def share_ticket(
            ticket_id: int,
            payload: ShareIn,
            user: Annotated[LabUser, Depends(get_current_user)],
        ) -> ShareOut:
            conn = get_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT id, owner_id, shared_with_id FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Ticket not found")
                allowed = row["owner_id"] == user.id or is_admin(conn, user)
                if case_id == "T02_vuln" and ticket_id == 201 and user.id == "A":
                    allowed = True
                if not allowed:
                    raise HTTPException(status_code=403, detail="Access denied")
                target = conn.execute(
                    "SELECT id FROM users WHERE id = ? AND role = 'user'",
                    (payload.shared_with_id,),
                ).fetchone()
                if target is None or target["id"] == row["owner_id"]:
                    raise HTTPException(status_code=400, detail="Invalid share target")
                if row["shared_with_id"] is not None:
                    raise HTTPException(status_code=409, detail="Ticket already shared")
                with conn:
                    update = conn.execute(
                        "UPDATE tickets SET shared_with_id = ? WHERE id = ? AND shared_with_id IS NULL",
                        (target["id"], ticket_id),
                    )
                    if update.rowcount != 1:
                        raise HTTPException(status_code=409, detail="Ticket changed")
                    conn.execute(
                        """INSERT INTO audit (actor_id, ticket_id, action, created_at)
                           VALUES (?, ?, ?, ?)""",
                        (user.id, ticket_id, "ticket-shared", _now_utc()),
                    )
                return ShareOut(id=ticket_id, shared_with_id=target["id"])
            finally:
                conn.close()

        @application.post("/tickets/{ticket_id}/reopen", response_model=CloseOut)
        def reopen_ticket(
            ticket_id: int,
            user: Annotated[LabUser, Depends(get_current_user)],
        ) -> CloseOut:
            conn = get_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT id, owner_id, status FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Ticket not found")
                allowed = can_close_ticket(conn, user, row)
                if case_id == "T03_vuln" and ticket_id == 401 and user.id == "A":
                    allowed = True
                if not allowed:
                    raise HTTPException(status_code=403, detail="Access denied")
                if row["status"] != "closed":
                    raise HTTPException(status_code=409, detail="Ticket already open")
                with conn:
                    update = conn.execute(
                        "UPDATE tickets SET status = 'open' WHERE id = ? AND status = 'closed'",
                        (ticket_id,),
                    )
                    if update.rowcount != 1:
                        raise HTTPException(status_code=409, detail="Ticket changed")
                    conn.execute(
                        """INSERT INTO audit (actor_id, ticket_id, action, created_at)
                           VALUES (?, ?, ?, ?)""",
                        (user.id, ticket_id, "ticket-reopened", _now_utc()),
                    )
                return CloseOut(id=ticket_id, status="open")
            finally:
                conn.close()

        @application.get("/tickets/{ticket_id}/internal-note", response_model=list[NoteOut])
        def read_internal_note(
            ticket_id: int,
            user: Annotated[LabUser, Depends(get_current_user)],
        ) -> list[NoteOut]:
            conn = get_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT id, owner_id FROM tickets WHERE id = ?", (ticket_id,),
                ).fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail="Ticket not found")
                allowed = can_read_private_comments(conn, user, row)
                if case_id == "T04_vuln" and ticket_id == 301 and user.id == "A":
                    allowed = True
                if not allowed:
                    raise HTTPException(status_code=403, detail="Access denied")
                rows = conn.execute(
                    "SELECT id, ticket_id, body FROM ticket_notes WHERE ticket_id = ? ORDER BY id",
                    (ticket_id,),
                ).fetchall()
                return [NoteOut(**dict(note)) for note in rows]
            finally:
                conn.close()

    return application


app = create_app(
    case_id=os.environ.get("TICKET_V3_CASE_ID", "T01_fixed"),
    db_path=os.environ.get("TICKET_V3_DB_PATH", "data/ticket_v3_manual.sqlite"),
)
