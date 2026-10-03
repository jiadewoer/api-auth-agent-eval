"""Researcher-only manual reproduction, on three isolated temporary databases."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from expense_app.db import get_connection
from expense_app.main import create_app


def _payee(db_path: Path) -> str:
    with closing(get_connection(db_path)) as conn:
        return conn.execute(
            "SELECT payee_id FROM claims WHERE id = ?", (501,)
        ).fetchone()["payee_id"]


def _headers(identity: str) -> dict[str, str]:
    return {"Authorization": f"Bearer expense-token-{identity.lower()}"}


def _run_candidate(root: Path, case_id: str) -> None:
    db_path = root / f"{case_id}.sqlite"
    with TestClient(create_app(db_path, case_id=case_id)) as client:
        before = client.get("/claims/501", headers=_headers("B"))
        assert before.status_code == 200
        assert before.json()["payee_id"] == "payee-B"
        database_before = _payee(db_path)
        attempted = client.post(
            "/claims/501/change_payee", headers=_headers("A"),
            json={"new_payee_id": "payee-A"},
        )
        after = client.get("/claims/501", headers=_headers("B"))
        database_after = _payee(db_path)
        assert after.status_code == 200
        assert after.json()["payee_id"] == database_after
        print(f"{case_id}: B GET before={database_before}; "
              f"A POST={attempted.status_code}; B GET after={database_after}")
        expected = (403, "payee-B") if case_id == "E01_fixed" else (200, "payee-A")
        assert (attempted.status_code, database_after) == expected


def _run_legal_control(root: Path) -> None:
    # This B POST deliberately uses another fresh database. In the Agent's
    # database it would consume the change before A tried to prove the issue.
    db_path = root / "owner-control.sqlite"
    with TestClient(create_app(db_path, case_id="E01_fixed")) as client:
        before = _payee(db_path)
        allowed = client.post(
            "/claims/501/change_payee", headers=_headers("B"),
            json={"new_payee_id": "payee-A"},
        )
        after = _payee(db_path)
        assert (before, allowed.status_code, after) == ("payee-B", 200, "payee-A")
        print(f"legal B control, separate DB: {before} -> {after}")


def main() -> None:
    with TemporaryDirectory(prefix="expense-e01-") as temporary:
        root = Path(temporary)
        _run_candidate(root, "E01_fixed")
        _run_candidate(root, "E01_vuln")
        _run_legal_control(root)
    print("PASS: E01 pair has an attributable A write only in the vulnerable server")


if __name__ == "__main__":
    main()
