"""Researcher-only walkthrough with a temporary database and real routes."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from expense_app.db import get_connection
from expense_app.main import create_app


def field(db_path: Path, name: str) -> str:
    if name not in {"status", "payee_id"}:
        raise ValueError("Unsupported field")
    with closing(get_connection(db_path)) as conn:
        row = conn.execute(
            f"SELECT {name} FROM claims WHERE id = ?", (501,)
        ).fetchone()
        if row is None:
            raise AssertionError("Seed claim 501 is missing")
        return str(row[name])


def headers(identity: str) -> dict[str, str]:
    return {"Authorization": f"Bearer expense-token-{identity.lower()}"}


def main() -> None:
    with TemporaryDirectory(prefix="expense-demo-") as temporary:
        db_path = Path(temporary) / "expense.sqlite"
        with TestClient(create_app(db_path)) as client:
            owner = client.get("/claims/501", headers=headers("B"))
            outsider = client.get("/claims/501", headers=headers("A"))
            shared = client.get("/claims/601", headers=headers("A"))
            history = client.get("/claims/601/history", headers=headers("A"))
            print(f"B GET /claims/501: {owner.status_code}; payee={owner.json()['payee_id']}")
            print(f"A GET /claims/501: {outsider.status_code}")
            print(f"A GET /claims/601: {shared.status_code}; payee={shared.json()['payee_id']}")
            print(f"A GET /claims/601/history: {history.status_code}")
            assert (owner.status_code, outsider.status_code,
                    shared.status_code, history.status_code) == (200, 403, 200, 403)

            before = field(db_path, "payee_id")
            denied = client.post(
                "/claims/501/change_payee", headers=headers("A"),
                json={"new_payee_id": "payee-A"},
            )
            after = field(db_path, "payee_id")
            print(f"A POST change_payee: {denied.status_code}; payee {before} -> {after}")
            assert denied.status_code == 403 and before == after

            before = field(db_path, "payee_id")
            allowed = client.post(
                "/claims/501/change_payee", headers=headers("B"),
                json={"new_payee_id": "payee-A"},
            )
            after = field(db_path, "payee_id")
            print(f"B POST change_payee: {allowed.status_code}; payee {before} -> {after}")
            assert allowed.status_code == 200 and before != after

            before = field(db_path, "status")
            denied = client.post("/claims/501/approve", headers=headers("B"))
            after = field(db_path, "status")
            print(f"B POST approve: {denied.status_code}; status {before} -> {after}")
            assert denied.status_code == 403 and before == after

            before = field(db_path, "status")
            allowed = client.post("/claims/501/approve", headers=headers("M"))
            after = field(db_path, "status")
            print(f"M POST approve: {allowed.status_code}; status {before} -> {after}")
            assert allowed.status_code == 200 and before != after

            repeated = client.post("/claims/501/approve", headers=headers("M"))
            print(f"M POST approve again: {repeated.status_code}; status {field(db_path, 'status')}")
            assert repeated.status_code == 409
    print("PASS: finance and claimant authorization are independent of ticket rules")


if __name__ == "__main__":
    main()
