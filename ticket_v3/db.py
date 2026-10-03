"""V3 ticket fixtures in a separate module; old app/db.py stays frozen."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
);
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    shared_with_id TEXT REFERENCES users(id),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'closed'))
);
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    ticket_id INTEGER NOT NULL REFERENCES tickets(id),
    author_id TEXT NOT NULL REFERENCES users(id),
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    ticket_id INTEGER REFERENCES tickets(id),
    action TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def seed(db_path: str | Path) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(path)
    try:
        conn.executescript(SCHEMA)
        with conn:
            # A V3 app may reuse this file; clear its optional child table first.
            has_v3_notes = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ticket_notes'"
            ).fetchone()
            if has_v3_notes:
                conn.execute("DELETE FROM ticket_notes")
            for table in ("audit", "comments", "tickets", "users"):
                conn.execute(f"DELETE FROM {table}")
            conn.executemany(
                "INSERT INTO users (id, name, role) VALUES (?, ?, ?)",
                [
                    ("A", "User A", "user"),
                    ("B", "User B", "user"),
                    ("M", "Administrator", "admin"),
                ],
            )
            conn.executemany(
                """INSERT INTO tickets
                   (id, owner_id, shared_with_id, title, body, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    (101, "A", None, "A's private ticket", "a-private-101", "open"),
                    (201, "B", None, "B's private ticket", "b-private-201", "open"),
                    (301, "B", "A", "B's shared ticket", "b-shared-301", "open"),
                ],
            )
            conn.executemany(
                "INSERT INTO comments (id, ticket_id, author_id, body) VALUES (?, ?, ?, ?)",
                [(1, 201, "B", "comment-private-201"),
                 (2, 301, "B", "comment-private-301")],
            )
            conn.execute(
                """INSERT INTO audit (id, actor_id, ticket_id, action, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (1, "M", 201, "fixture-created", "2026-01-01T00:00:00Z"),
            )
    finally:
        conn.close()


def seed_v3(db_path: str | Path) -> None:
    """Add V3-only rows after seed(); historical P01–P06 fixtures stay intact."""
    conn = get_connection(db_path)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS ticket_notes (
            id INTEGER PRIMARY KEY,
            ticket_id INTEGER NOT NULL REFERENCES tickets(id),
            body TEXT NOT NULL
        )""")
        with conn:
            conn.execute(
                """INSERT INTO tickets
                   (id, owner_id, shared_with_id, title, body, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (401, "B", "A", "B's archived ticket", "b-archived-401", "closed"),
            )
            conn.execute(
                "INSERT INTO ticket_notes (id, ticket_id, body) VALUES (?, ?, ?)",
                (1, 301, "reviewer-note-private-301"),
            )
    finally:
        conn.close()
