"""V4 public tasks and private truth. Only public_spec_for_case may be sent."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "cases"
DEV_PAIRS = ("T05", "T06", "E05", "E06")
RESERVED_PAIRS = (
    "T07", "T08", "T09", "T10", "T11", "T12",
    "E07", "E08", "E09", "E10", "E11", "E12",
)
D3_RESERVED_PAIRS = (
    "T13", "T14", "T15", "T16", "T17", "T18",
    "E13", "E14", "E15", "E16", "E17", "E18",
)
DEV_CASE_IDS = tuple(f"{pair}_{variant}" for pair in DEV_PAIRS
                     for variant in ("fixed", "vuln"))
RESERVED_CASE_IDS = tuple(f"{pair}_{variant}" for pair in RESERVED_PAIRS
                          for variant in ("fixed", "vuln"))
D3_RESERVED_CASE_IDS = tuple(f"{pair}_{variant}" for pair in D3_RESERVED_PAIRS
                             for variant in ("fixed", "vuln"))
ALL_CASE_IDS = DEV_CASE_IDS + RESERVED_CASE_IDS + D3_RESERVED_CASE_IDS
PUBLIC_FIELDS = ("public_task_id", "target_method", "target_path",
                 "request_body", "target_object", "test_identities",
                 "visible_policy", "control_identity", "control_path")


def _split_for(case_id: str) -> str:
    if case_id in DEV_CASE_IDS:
        return "dev"
    if case_id in RESERVED_CASE_IDS:
        return "reserved"
    if case_id in D3_RESERVED_CASE_IDS:
        return "d3_reserved"
    raise ValueError("Not a V4 case")


def _spec(case_id: str) -> dict:
    split = _split_for(case_id)
    document = json.loads((ROOT / f"v4_{split}_specs.json").read_text(encoding="utf-8"))
    matches = [row for row in document["cases"] if row["pair_id"] == case_id.split("_")[0]]
    if len(matches) != 1 or matches[0]["split"] != split:
        raise ValueError("Missing or duplicate V4 task")
    return matches[0]


def public_spec_for_case(case_id: str) -> dict:
    row = _spec(case_id)
    return {key: row[key] for key in PUBLIC_FIELDS}


def internal_case_for(case_id: str) -> dict:
    return {**_spec(case_id), "case_id": case_id,
            "app_id": "ticket_lab_v4" if case_id.startswith("T") else "expense_lab_v4"}


def truth_for_case(case_id: str) -> dict:
    """Evaluator-only private truth; never called from an Agent-facing tool."""
    split = _split_for(case_id)
    return json.loads((ROOT / f"v4_{split}_truth.json").read_text(encoding="utf-8"))["cases"][case_id]
