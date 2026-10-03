"""SQLite schema and repeatable fixtures for the expense-claim lab."""

from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('claimant', 'finance'))
);

CREATE TABLE IF NOT EXISTS payees (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claims (
    id INTEGER PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    shared_with_id TEXT REFERENCES users(id),
    payee_id TEXT NOT NULL REFERENCES payees(id),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    summary TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('submitted', 'approved'))
);

CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY,
    claim_id INTEGER NOT NULL REFERENCES claims(id),
    actor_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """Open a new connection; the caller must close it."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def seed(db_path: str | Path) -> None:
    """Create and reset one lab database. Call once while creating an app."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(path)
    try:
        conn.executescript(SCHEMA)
        with conn:
            # Delete children before their referenced parents.
            for table in ("history", "claims", "payees", "users"):
                conn.execute(f"DELETE FROM {table}")

            conn.executemany(
                "INSERT INTO users (id, name, role) VALUES (?, ?, ?)",
                [
                    ("A", "Claimant A", "claimant"),
                    ("B", "Claimant B", "claimant"),
                    ("M", "Finance reviewer", "finance"),
                ],
            )
            conn.executemany(
                "INSERT INTO payees (id, label) VALUES (?, ?)",
                [("payee-A", "Synthetic recipient A"),
                 ("payee-B", "Synthetic recipient B")],
            )
            conn.executemany(
                """INSERT INTO claims
                   (id, owner_id, shared_with_id, payee_id, amount_cents, summary, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (101, "A", None, "payee-A", 1500, "A's private claim", "submitted"),
                    (501, "B", None, "payee-B", 3200, "B's private claim", "submitted"),
                    (601, "B", "A", "payee-B", 900, "B's shared claim", "submitted"),
                ],
            )
            conn.executemany(
                """INSERT INTO history (id, claim_id, actor_id, action, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (1, 101, "A", "claim-created", "2026-01-01T00:00:00Z"),
                    (2, 501, "B", "claim-created", "2026-01-01T00:00:00Z"),
                    (3, 601, "B", "claim-created", "2026-01-01T00:00:00Z"),
                ],
            )
    finally:
        conn.close()
