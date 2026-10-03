"""Evaluator-only routing for the two V3 apps; call public_spec_for_case for Agent input."""

from __future__ import annotations

from expense_app.case_catalog import (
    EXPENSE_CASE_IDS,
    internal_case_for as _expense_internal,
    public_spec_for_case as _expense_public,
)
from ticket_v3.case_catalog import (
    TICKET_CASE_IDS,
    internal_case_for as _ticket_internal,
    public_spec_for_case as _ticket_public,
)


def internal_case_for(case_id: str) -> dict:
    if case_id in EXPENSE_CASE_IDS:
        return _expense_internal(case_id)
    if case_id in TICKET_CASE_IDS:
        return _ticket_internal(case_id)
    raise ValueError("Unknown V3 case")


def public_spec_for_case(case_id: str) -> dict:
    if case_id in EXPENSE_CASE_IDS:
        return _expense_public(case_id)
    if case_id in TICKET_CASE_IDS:
        return _ticket_public(case_id)
    raise ValueError("Unknown V3 case")
