"""V3 ticket variants map to one label-free task per pair."""

from __future__ import annotations

import json
from pathlib import Path


TICKET_CASE_IDS = frozenset(
    f"T{number:02d}_{variant}"
    for number in range(1, 5) for variant in ("fixed", "vuln")
)
_SPEC_PATH = Path(__file__).resolve().parents[1] / "cases" / "v3_ticket_specs.json"
_PUBLIC_FIELDS = (
    "public_task_id", "target_method", "target_path", "request_body",
    "test_identities", "target_object", "visible_policy",
)


def _shared_spec(case_id: str) -> dict:
    if case_id not in TICKET_CASE_IDS:
        raise ValueError("Unknown V3 ticket case")
    document = json.loads(_SPEC_PATH.read_text(encoding="utf-8"))
    rows = [item for item in document["cases"] if item["pair_id"] == case_id.split("_")[0]]
    if len(rows) != 1:
        raise ValueError("Missing or duplicate V3 ticket task")
    return rows[0]


def internal_case_for(case_id: str) -> dict:
    return {**_shared_spec(case_id), "case_id": case_id, "app_id": "ticket_lab_v3"}


def public_spec_for_case(case_id: str) -> dict:
    row = _shared_spec(case_id)
    return {key: row[key] for key in _PUBLIC_FIELDS}
