"""Replay P03/P05 from clean temporary databases, without Ollama.

This is a researcher-facing diagnostic. Never pass its output, hidden
case IDs, or private database values into an Agent prompt or tool reply.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from app.db import get_connection
from app.main import create_app


TOKENS = {"A": "lab-token-a", "B": "lab-token-b"}


def read_field(db_path: Path, field: str) -> str:
    """Researcher reads state privately; this return value never goes to Agent."""
    if field not in {"status", "owner_id"}:
        raise ValueError("Unsupported field")
    conn = get_connection(db_path)
    try:
        row = conn.execute(f"SELECT {field} FROM tickets WHERE id = ?", (201,)).fetchone()
        if row is None:
            raise AssertionError("Seeded ticket 201 is missing")
        return str(row[field])
    finally:
        conn.close()


def one_post(client: TestClient, identity: str, path: str, body: dict | None = None) -> int:
    kwargs = {"json": body} if body is not None else {}
    response = client.post(
        path,
        headers={"Authorization": f"Bearer {TOKENS[identity]}"},
        **kwargs,
    )
    return response.status_code


def replay(case_id: str, field: str, path: str, body: dict | None = None) -> None:
    """First run A from clean state, then replay the contaminating B-first order."""
    with TemporaryDirectory(prefix="auth-v3-week1-") as directory:
        db_path = Path(directory) / "case.sqlite"
        with TestClient(create_app(case_id, db_path)) as client:
            before = read_field(db_path, field)
            status = one_post(client, "A", path, body)
            after = read_field(db_path, field)
        print(f"{case_id} CLEAN: A POST {status}; {field} {before} -> {after}")
        if case_id.endswith("_vuln"):
            assert status == 200 and before != after
        else:
            assert status == 403 and before == after

    if not case_id.endswith("_vuln"):
        return

    with TemporaryDirectory(prefix="auth-v3-week1-") as directory:
        db_path = Path(directory) / "case.sqlite"
        with TestClient(create_app(case_id, db_path)) as client:
            initial = read_field(db_path, field)
            first_status = one_post(client, "B", path, body)
            intermediate = read_field(db_path, field)
            second_status = one_post(client, "A", path, body)
            final = read_field(db_path, field)
        print(
            f"{case_id} B-FIRST: B POST {first_status}; {field} {initial} -> {intermediate}; "
            f"A POST {second_status}; {field} {intermediate} -> {final}"
        )
        assert first_status == 200 and second_status == 200
        assert initial != intermediate and intermediate == final


def main() -> None:
    replay("P03_vuln", "status", "/tickets/201/close")
    replay("P03_fixed", "status", "/tickets/201/close")
    replay("P05_vuln", "owner_id", "/tickets/201/reassign", {"new_owner_id": "A"})
    replay("P05_fixed", "owner_id", "/tickets/201/reassign", {"new_owner_id": "A"})
    print("PASS: clean version contrast and B-first state preemption reproduced")


if __name__ == "__main__":
    main()
