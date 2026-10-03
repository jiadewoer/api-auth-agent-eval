"""Exactly two independent prompt factors for V4 development."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parent / "prompts"
CONDITIONS = ("R0C0", "R1C0", "R0C1", "R1C1")


def render_prompt(condition: str) -> str:
    if condition not in CONDITIONS:
        raise ValueError("Unknown V4 condition")
    fragments = ["base.txt"]
    if condition[1] == "1":
        fragments.append("order.txt")
    if condition[3] == "1":
        fragments.append("types.txt")
    return "\n".join((ROOT / name).read_text(encoding="utf-8").strip()
                     for name in fragments)


def prompt_sha256(condition: str) -> str:
    return sha256(render_prompt(condition).encode("utf-8")).hexdigest()
