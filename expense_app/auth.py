"""Identify one synthetic lab user; authorization lives in permissions.py."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import Header, HTTPException


@dataclass(frozen=True)
class ExpenseUser:
    id: str
    role: Literal["claimant", "finance"]


_TOKENS = {
    "expense-token-a": ExpenseUser("A", "claimant"),
    "expense-token-b": ExpenseUser("B", "claimant"),
    "expense-token-m": ExpenseUser("M", "finance"),
}


def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
) -> ExpenseUser:
    """A valid token answers 'who'; it does not grant every permission."""
    scheme, _, token = (authorization or "").partition(" ")
    user = _TOKENS.get(token) if scheme.lower() == "bearer" else None
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
