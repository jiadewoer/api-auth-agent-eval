"""Authorization rules that consult the seeded users table.

Keep read-body access separate from private-comment, mutation, and admin access.
"""

from __future__ import annotations

import sqlite3

from ticket_v3.auth import LabUser


def is_admin(conn: sqlite3.Connection, user: LabUser) -> bool:
    row = conn.execute("SELECT role FROM users WHERE id = ?", (user.id,)).fetchone()
    return row is not None and row["role"] == "admin"


def can_read_private_comments(
    conn: sqlite3.Connection, user: LabUser, ticket: sqlite3.Row
) -> bool:
    return ticket["owner_id"] == user.id or is_admin(conn, user)


def can_close_ticket(
    conn: sqlite3.Connection, user: LabUser, ticket: sqlite3.Row
) -> bool:
    return ticket["owner_id"] == user.id or is_admin(conn, user)


def can_reassign_ticket(conn: sqlite3.Connection, user: LabUser) -> bool:
    return is_admin(conn, user)
