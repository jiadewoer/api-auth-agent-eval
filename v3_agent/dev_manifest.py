"""Lock the development run's code, cases, model settings and A/B prompts."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from agent.config import TIMEOUT_SECONDS
from cases.v3_catalog import internal_case_for
from v3_agent.model_client import MODEL_DIGEST_PREFIX
from v3_agent.protocol import MAX_DECISIONS, MAX_REQUESTS
from v3_agent.runner import MODEL, NUM_CTX, PROMPTS, ROOT, TEMPERATURE


DEV_CASE_IDS = ("T01_fixed", "T01_vuln", "E01_fixed", "E01_vuln")
CONDITIONS = ("A", "B")
HASH_FILES = (
    "v3_agent/protocol.py", "v3_agent/tools.py", "v3_agent/gate.py",
    "v3_agent/grade.py", "v3_agent/runner.py", "v3_agent/model_client.py", "v3_agent/dev_manifest.py",
    "v3_agent/run_ab_dev.py", "v3_agent/freeze_dev.py",
    "v3_agent/summarize_dev.py", "v3_agent/run_dev.py",
    "followup_v2/text_tool.py", "agent/runner.py", "agent/config.py",
    "cases/v3_catalog.py", "cases/v3_ticket_specs.json", "cases/v3_expense_specs.json",
    "cases/v3_ticket_truth.json", "cases/v3_expense_truth.json",
    "ticket_v3/main.py", "expense_app/main.py",
)


def _hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _package_versions() -> dict[str, str | None]:
    result = {}
    for name in ("fastapi", "httpx", "ollama", "pydantic", "pytest"):
        try:
            result[name] = version(name)
        except PackageNotFoundError:
            result[name] = None
    return result


def snapshot(provider: str) -> dict:
    if provider not in ("stub", "ollama"):
        raise ValueError("Unknown provider")
    if any(internal_case_for(case_id)["split"] != "dev" for case_id in DEV_CASE_IDS):
        raise ValueError("Development runner contains a reserved case")
    baseline = PROMPTS["A"].read_text(encoding="utf-8").splitlines()
    evidence = PROMPTS["B"].read_text(encoding="utf-8").splitlines()
    if len(evidence) != len(baseline) + 1 or evidence[:-1] != baseline:
        raise ValueError("B prompt must be the A prompt plus exactly one sentence")
    return {
        "schema_version": 1, "phase": "development", "provider": provider,
        "split": "dev", "cases": list(DEV_CASE_IDS),
        "conditions": list(CONDITIONS), "repeats": 1,
        "model": MODEL, "expected_model_digest_prefix": MODEL_DIGEST_PREFIX,
        "temperature": TEMPERATURE, "num_ctx": NUM_CTX,
        "timeout_seconds": TIMEOUT_SECONDS,
        "api_request_limit": MAX_REQUESTS, "model_decision_limit": MAX_DECISIONS,
        "shared_evidence_gate": True, "shared_text_adapter": True,
        "prompt_sha256": {condition: _hash(path) for condition, path in PROMPTS.items()},
        "file_sha256": {relative: _hash(ROOT / relative) for relative in HASH_FILES},
        "python_version": sys.version.split()[0],
        "dependency_versions": _package_versions(),
    }


def ensure_manifest(output: Path, provider: str) -> dict:
    current = snapshot(provider)
    path = output / "experiment_manifest.json"
    if path.exists():
        stored = json.loads(path.read_text(encoding="utf-8"))
        if {k: v for k, v in stored.items() if k != "created_at"} != current:
            raise ValueError("Manifest mismatch: use a new output directory; do not mix configurations")
        return stored
    if (output / "results.jsonl").exists():
        raise ValueError("Results exist without a manifest; do not append")
    output.mkdir(parents=True, exist_ok=True)
    saved = {**current, "created_at": datetime.now(timezone.utc).isoformat()}
    path.write_text(json.dumps(saved, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return saved
