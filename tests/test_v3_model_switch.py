"""The V3 model switch must not silently use the archived V2 model."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from v3_agent.dev_manifest import HASH_FILES, snapshot
from v3_agent.model_client import MODEL_DIGEST_PREFIX, local_chat
from v3_agent.runner import MODEL


def _fake_client(monkeypatch, model: str, digest: str):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        def list(self):
            return SimpleNamespace(models=[SimpleNamespace(model=model, digest=digest)])

        def chat(self, **kwargs):
            calls.append(("chat", kwargs))
            return SimpleNamespace(message=SimpleNamespace(content="ok", tool_calls=[]))

    monkeypatch.setitem(sys.modules, "ollama", SimpleNamespace(Client=Client))
    return calls


def test_v3_digest_and_model_are_held_constant(monkeypatch):
    assert MODEL == "qwen3:8b"
    assert "v3_agent/model_client.py" in HASH_FILES
    manifest = snapshot("ollama")
    assert manifest["model"] == MODEL
    assert manifest["expected_model_digest_prefix"] == MODEL_DIGEST_PREFIX

    digest = MODEL_DIGEST_PREFIX + "a" * 52
    calls = _fake_client(monkeypatch, MODEL, digest)
    chat_fn, runtime = local_chat()
    assert runtime == {"model": MODEL, "model_digest": digest}
    options = {"temperature": 0.2, "num_ctx": 4096}
    chat_fn(model=MODEL, messages=[{"role": "user", "content": "test"}],
            tools=[], options=options)
    assert calls[1][1]["model"] == MODEL
    assert calls[1][1]["options"] == options
    with pytest.raises(ValueError, match="other than the manifest model"):
        chat_fn(model="qwen3:4b-instruct", messages=[])
    assert len(calls) == 2


@pytest.mark.parametrize("name,digest", [
    ("qwen3:4b-instruct", MODEL_DIGEST_PREFIX + "a" * 52),
    ("qwen3:8b", "0edcdef34593" + "a" * 52),
])
def test_missing_or_changed_model_refuses_to_start(monkeypatch, name, digest):
    _fake_client(monkeypatch, name, digest)
    with pytest.raises(ValueError, match="not installed|digest mismatch"):
        local_chat()
