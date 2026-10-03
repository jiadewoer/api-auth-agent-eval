"""Evaluator-only case routing and a deliberately small Agent-facing projection.

This module never opens truth.json. The evaluator may use internal_case_for;
only the return value of public_spec_for_case may be passed to an Agent.
"""

from __future__ import annotations

import json
from pathlib import Path


# Private mapping: each pair's two server variants share one public task.
_PAIR_BY_CASE = {
    "P01_fixed": "P01",
    "P01_vuln": "P01",
    "P02_fixed": "P02",
    "P02_vuln": "P02",
    "P03_fixed": "P03",
    "P03_vuln": "P03",
    "P04_fixed": "P04",
    "P04_vuln": "P04",
    "P05_fixed": "P05",
    "P05_vuln": "P05",
    "P06_fixed": "P06",
    "P06_vuln": "P06",
}


_INTERNAL_FIELDS = (
    "pair_id", "case_id", "split", "target_method", "target_path",
    "test_identities", "target_object", "visible_policy",
)

_PUBLIC_FIELDS = (
    "public_task_id", "target_method", "target_path", "test_identities",
    "target_object", "visible_policy",
)


def _shared_spec(case_id: str) -> dict:
    try:
        pair_id = _PAIR_BY_CASE[case_id]
    except KeyError as error:
        raise ValueError("Unknown case") from error
    path = Path(__file__).with_name("specs.json")
    with path.open(encoding="utf-8") as stream:
        specs = json.load(stream)
    matches = [item for item in specs["cases"] if item["pair_id"] == pair_id]
    if len(matches) != 1:
        raise ValueError("Missing or duplicate public task")
    return matches[0]


def internal_case_for(case_id: str) -> dict:
    """Assemble eight evaluator metadata fields from one shared pair spec."""
    shared = _shared_spec(case_id)
    combined = {**shared, "case_id": case_id}
    return {field: combined[field] for field in _INTERNAL_FIELDS}


def public_spec_for_case(case_id: str) -> dict:
    """Project a hidden variant onto its label-free Agent task."""
    shared = _shared_spec(case_id)
    return {field: shared[field] for field in _PUBLIC_FIELDS}
