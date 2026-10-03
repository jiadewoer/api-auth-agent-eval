"""V3-only Ollama selection; keep the archived V2 model configuration intact."""

from __future__ import annotations

from typing import Any

from agent.config import TIMEOUT_SECONDS
from v3_agent.runner import MODEL


# First twelve digits of the installed qwen3:8b digest recorded before this
# development configuration. The full digest is retained in every run.
MODEL_DIGEST_PREFIX = "500a1f067a9f"


def local_chat() -> tuple[Any, dict[str, str]]:
    from ollama import Client

    client = Client(host="http://127.0.0.1:11434", trust_env=False,
                    timeout=TIMEOUT_SECONDS)
    installed = next((item for item in client.list().models
                      if item.model == MODEL), None)
    if installed is None:
        raise ValueError(f"Expected V3 model {MODEL!r} is not installed")
    digest = installed.digest
    if not isinstance(digest, str) or not digest.startswith(MODEL_DIGEST_PREFIX):
        raise ValueError(
            f"V3 model digest mismatch for {MODEL!r}: expected prefix "
            f"{MODEL_DIGEST_PREFIX!r}, got {digest!r}. Stop and select a new "
            "development configuration instead of silently changing a model."
        )

    def chat_fn(**kwargs: Any) -> Any:
        if kwargs.get("model") != MODEL:
            raise ValueError("V3 chat requested a model other than the manifest model")
        return client.chat(**kwargs)

    return chat_fn, {"model": MODEL, "model_digest": digest}
