"""Map evaluator-only expense variants to one shared, label-free task.

Do not give a model ``internal_case_for`` or the path to the truth file.
The Agent-facing projection is only ``public_spec_for_case``.
"""

from __future__ import annotations

import json
from pathlib import Path


EXPENSE_CASE_IDS = frozenset(
    f"E{number:02d}_{variant}"
    for number in range(1, 5) for variant in ("fixed", "vuln")
)
_SPEC_PATH = Path(__file__).resolve().parents[1] / "cases" / "v3_expense_specs.json"
_PUBLIC_FIELDS = (
    "public_task_id", "target_method", "target_path", "request_body",
    "test_identities", "target_object", "visible_policy",
)


def _shared_spec(case_id: str) -> dict:
    if case_id not in EXPENSE_CASE_IDS:
        raise ValueError("Unknown expense case")
    document = json.loads(_SPEC_PATH.read_text(encoding="utf-8"))
    rows = [row for row in document["cases"] if row["pair_id"] == case_id.split("_")[0]]
    if len(rows) != 1:
        raise ValueError("Missing or duplicate expense task")
    return rows[0]


def internal_case_for(case_id: str) -> dict:
    """Evaluator-side routing metadata, never sent to the Agent."""
    return {**_shared_spec(case_id), "case_id": case_id, "app_id": "expense_lab_v1"}


def public_spec_for_case(case_id: str) -> dict:
    """Same public input for both versions; no label or internal path."""
    row = _shared_spec(case_id)
    return {key: row[key] for key in _PUBLIC_FIELDS}
