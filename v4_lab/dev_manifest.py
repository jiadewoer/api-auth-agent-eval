"""Immutable identity for one V4 four-condition run directory."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from agent.config import TIMEOUT_SECONDS
from v3_agent.model_client import MODEL_DIGEST_PREFIX
from v4_lab.catalog import DEV_CASE_IDS, RESERVED_CASE_IDS, D3_RESERVED_CASE_IDS, internal_case_for
from v4_lab.prompts import CONDITIONS, ROOT as PROMPT_ROOT, prompt_sha256, render_prompt
from v4_lab.protocol import MAX_DECISIONS, MAX_REQUESTS
from v4_lab.runner import MODEL, NUM_CTX, ROOT, TEMPERATURE


HASH_FILES = (
    "agent/finding.py", "agent/config.py", "followup_v2/text_tool.py",
    "v3_agent/tools.py", "v3_agent/protocol.py", "v3_agent/model_client.py",
    "ticket_v3/main.py", "ticket_v3/db.py", "expense_app/main.py", "expense_app/db.py",
    "cases/v4_dev_specs.json", "cases/v4_dev_truth.json",
    "cases/v4_reserved_specs.json", "cases/v4_reserved_truth.json",
    "v4_lab/catalog.py", "v4_lab/apps.py", "v4_lab/stages.py", "v4_lab/protocol.py",
    "v4_lab/gate.py", "v4_lab/tools.py", "v4_lab/prompts.py", "v4_lab/runner.py",
    "v4_lab/dev_manifest.py", "v4_lab/run_ab_dev.py", "v4_lab/run_reserved.py",
    "v4_lab/prompts/base.txt", "v4_lab/prompts/order.txt", "v4_lab/prompts/types.txt",
    "cases/v4_d3_reserved_specs.json", "cases/v4_d3_reserved_truth.json",
    "v4_lab/run_d3_reserved.py",
)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def snapshot(provider: str, *, split: str = "dev") -> dict:
    if provider not in {"stub", "ollama"}:
        raise ValueError("Unknown provider")
    if split == "dev":
        case_ids, repeats, phase = DEV_CASE_IDS, 1, "V4_development"
    elif split == "reserved":
        case_ids, repeats, phase = RESERVED_CASE_IDS, 2, "V4_reserved_evaluation"
    elif split == "d3_reserved":
        case_ids, repeats, phase = D3_RESERVED_CASE_IDS, 2, "V4_D3_reserved_evaluation"
    else:
        raise ValueError("Unknown V4 split")
    if any(internal_case_for(case_id)["split"] != split for case_id in case_ids):
        raise ValueError("Runner includes the wrong split")
    base = render_prompt("R0C0")
    order = (PROMPT_ROOT / "order.txt").read_text(encoding="utf-8").strip()
    types = (PROMPT_ROOT / "types.txt").read_text(encoding="utf-8").strip()
    if (render_prompt("R1C0") != base + "\n" + order
            or render_prompt("R0C1") != base + "\n" + types
            or render_prompt("R1C1") != base + "\n" + order + "\n" + types):
        raise ValueError("Prompt arms do not follow the declared 2×2 factor design")
    versions = {}
    for name in ("fastapi", "httpx", "ollama", "pydantic", "pytest"):
        try:
            versions[name] = version(name)
        except PackageNotFoundError:
            versions[name] = None
    return {
        "schema_version": 1, "phase": phase, "provider": provider,
        "split": split, "cases": list(case_ids), "conditions": list(CONDITIONS),
        "repeats": repeats, "planned_runs": len(case_ids) * len(CONDITIONS) * repeats,
        "model": MODEL, "expected_model_digest_prefix": MODEL_DIGEST_PREFIX,
        "temperature": TEMPERATURE, "num_ctx": NUM_CTX,
        "timeout_seconds": TIMEOUT_SECONDS,
        "api_request_limit": MAX_REQUESTS, "model_decision_limit": MAX_DECISIONS,
        "shared_evidence_gate": True,
        "prompt_sha256": {condition: prompt_sha256(condition) for condition in CONDITIONS},
        "source_sha256": {name: _digest(ROOT / name) for name in HASH_FILES},
        "python_version": sys.version.split()[0], "dependency_versions": versions,
    }


def ensure_manifest(output: Path, provider: str, *, split: str = "dev") -> dict:
    current = snapshot(provider, split=split)
    path = output / "experiment_manifest.json"
    if path.exists():
        stored = json.loads(path.read_text(encoding="utf-8"))
        if {k: v for k, v in stored.items() if k != "created_at"} != current:
            raise ValueError("V4 manifest mismatch; use a new directory")
        return stored
    if output.exists() and any(output.iterdir()):
        raise ValueError("Nonempty directory without a manifest")
    output.mkdir(parents=True, exist_ok=True)
    stored = {**current, "created_at": datetime.now(timezone.utc).isoformat()}
    path.write_text(json.dumps(stored, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return stored
