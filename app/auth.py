"""Test-only reconstruction of the previously described auth.py; excluded from ZIP."""

from dataclasses import dataclass
import sqlite3

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


@dataclass(frozen=True)
class LabUser:
    id: str
    role: str


_USERS = {
    "lab-token-a": LabUser("A", "user"),
    "lab-token-b": LabUser("B", "user"),
    "lab-token-m": LabUser("M", "admin"),
}
_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> LabUser:
    if credentials is None or credentials.credentials not in _USERS:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _USERS[credentials.credentials]


def can_read_ticket(user: LabUser, ticket: sqlite3.Row) -> bool:
    return (user.role == "admin" or ticket["owner_id"] == user.id
            or ticket["shared_with_id"] == user.id)
