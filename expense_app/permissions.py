"""Business rules for expense claims, independent of ticket permissions."""

from __future__ import annotations

import sqlite3

from expense_app.auth import ExpenseUser


def can_read_claim(user: ExpenseUser, claim: sqlite3.Row) -> bool:
    return (
        user.role == "finance"
        or claim["owner_id"] == user.id
        or claim["shared_with_id"] == user.id
    )


def can_read_private_details(user: ExpenseUser, claim: sqlite3.Row) -> bool:
    """Sharing the claim summary does not reveal its payee or history."""
    return user.role == "finance" or claim["owner_id"] == user.id


def can_approve(user: ExpenseUser) -> bool:
    return user.role == "finance"


def can_change_payee(user: ExpenseUser, claim: sqlite3.Row) -> bool:
    """The claimant may edit only their own claim; finance cannot edit it."""
    return user.role == "claimant" and claim["owner_id"] == user.id
