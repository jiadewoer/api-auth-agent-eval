"""Stage-three type prompt regression checks."""

from __future__ import annotations

from v4_lab.prompts import render_prompt


def test_c_prompt_uses_two_step_type_decision() -> None:
    prompt = render_prompt("R0C1")

    assert "两步判断" in prompt
    assert "A 如果操作的是自己拥有的同类对象" in prompt
    assert "本次目标对象属于别人" in prompt
    assert "共享给 A 只允许读" in prompt
    assert "即使对象属于 A 也需要管理员、财务或 M" in prompt
    assert "不要按 HTTP 方法、路径名字、状态码" in prompt


def test_type_guidance_is_only_in_c_conditions() -> None:
    assert "两步判断" not in render_prompt("R0C0")
    assert "两步判断" not in render_prompt("R1C0")
    assert "两步判断" in render_prompt("R0C1")
    assert "两步判断" in render_prompt("R1C1")


def test_type_prompt_does_not_name_development_cases() -> None:
    prompt = render_prompt("R1C1")

    for private_marker in ("T05", "T06", "E05", "E06", "501", "502", "701", "702"):
        assert private_marker not in prompt
