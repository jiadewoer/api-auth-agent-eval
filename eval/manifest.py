"""Build a frozen experiment record without sending internal metadata to models."""

from __future__ import annotations

import json
import platform
from datetime import datetime
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from agent.config import MODEL, MODEL_DIGEST_PREFIX, NUM_CTX, TEMPERATURE, frozen_config
from cases.catalog import internal_case_for
from eval.grade import GRADER_VERSION


CASE_IDS = [f"P{number:02d}_{variant}" for number in range(1, 7)
            for variant in ("vuln", "fixed")]

# Source snapshots matter because the prompt hashes alone cannot detect a
# changed authorization check, truth marker, grader or runner.
FROZEN_FILES = (
    "agent/config.py", "agent/runner.py", "agent/tools.py", "agent/finding.py",
    "app/main.py", "app/auth.py", "app/permissions.py", "app/db.py",
    "cases/catalog.py", "cases/specs.json", "cases/truth.json",
    "eval/grade.py", "eval/run_cases.py",
)


def source_hashes() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    return {name: sha256((root / name).read_bytes()).hexdigest()
            for name in FROZEN_FILES}


def _version(package: str) -> str | None:
    try:
        return version(package)
    except PackageNotFoundError:
        return None


def manifest_template() -> dict:
    a, b = frozen_config("baseline"), frozen_config("evidence")
    return {
        "manifest_version": 1,
        "hypothesis": "B's evidence-check prompt may reduce false positives but can cost decisions or requests.",
        "agents": {
            "baseline": {"version": "A", "prompt_path": "agent/prompts/baseline.txt",
                         "prompt_sha256": a["prompt_sha256"]},
            "evidence": {"version": "B", "prompt_path": "agent/prompts/evidence_check.txt",
                         "prompt_sha256": b["prompt_sha256"]},
        },
        "model_tag": MODEL, "model_digest_prefix": MODEL_DIGEST_PREFIX,
        "actual_model_digest": None,
        "temperature": TEMPERATURE, "num_ctx": NUM_CTX,
        "tool_spec_sha256": a["tool_spec_sha256"],
        "source_sha256": source_hashes(),
        "request_limit": a["request_limit"], "decision_limit": a["decision_limit"],
        "timeout_seconds": a["timeout_seconds"],
        "grader_version": GRADER_VERSION,
        "cases": {split: [case_id for case_id in CASE_IDS
                          if internal_case_for(case_id)["split"] == split]
                  for split in ("dev", "holdout")},
        "runs_per_case": None, "selected_split": None,
        "test_started_at": None, "python_version": None,
        "dependency_versions": None,
    }


def runtime_manifest(split: str, repeats: int, actual_digest: str | None = None) -> dict:
    manifest = manifest_template()
    manifest.update({
        "selected_split": split, "runs_per_case": repeats,
        "test_started_at": datetime.now().astimezone().isoformat(),
        "python_version": platform.python_version(),
        "dependency_versions": {name: _version(name)
                                for name in ("fastapi", "httpx", "ollama", "pydantic", "pytest")},
        "actual_model_digest": actual_digest,
    })
    return manifest


def write_template(path: str | Path) -> None:
    Path(path).write_text(json.dumps(manifest_template(), ensure_ascii=False, indent=2),
                          encoding="utf-8")
