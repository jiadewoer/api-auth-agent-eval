"""Frozen A-version settings; edit only before the four development runs."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from agent.tools import MAX_DECISIONS, MAX_REQUESTS


MODEL = "qwen3:4b-instruct"
# The short model ID was reported by the project's owner from `ollama list`.
# An installed model with a different digest is a different experimental setup.
MODEL_DIGEST_PREFIX = "0edcdef34593"
TEMPERATURE = 0.2
NUM_CTX = 4096
TIMEOUT_SECONDS = 120.0
PROMPT_PATH = Path(__file__).with_name("prompts") / "baseline.txt"
PROMPTS = {
    "baseline": PROMPT_PATH,
    "evidence": PROMPT_PATH.with_name("evidence_check.txt"),
}


def frozen_config(agent_name: str = "baseline") -> dict:
    if agent_name not in PROMPTS:
        raise ValueError("Unknown Agent version")
    prompt = PROMPTS[agent_name].read_text(encoding="utf-8").strip()
    return {
        "version": "A" if agent_name == "baseline" else "B",
        "agent_name": agent_name,
        "model": MODEL,
        "model_digest_prefix": MODEL_DIGEST_PREFIX,
        "temperature": TEMPERATURE,
        "num_ctx": NUM_CTX,
        "request_limit": MAX_REQUESTS,
        "decision_limit": MAX_DECISIONS,
        "timeout_seconds": TIMEOUT_SECONDS,
        "prompt_sha256": sha256(prompt.encode("utf-8")).hexdigest(),
        "tool_spec_sha256": _tool_spec_digest(),
    }


def _tool_spec_digest() -> str:
    import json
    from agent.tools import TOOL_SCHEMAS, _PUBLIC_API
    frozen = json.dumps({"tools": TOOL_SCHEMAS, "api": _PUBLIC_API},
                        sort_keys=True, ensure_ascii=False)
    return sha256(frozen.encode("utf-8")).hexdigest()
