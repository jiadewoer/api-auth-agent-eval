"""Guard the Stage 5 prompt boundary between verdict and vulnerability type."""

from v4_lab.prompts import render_prompt


def test_verdict_is_decided_before_type_and_negative_types_are_null() -> None:
    prompt = render_prompt("R1C1")
    assert prompt.index("先根据本轮真实请求判断 verdict") < prompt.index("仅当 verdict 为 vulnerable 时")
    assert "not_vulnerable，vulnerability_type 必须为 null" in prompt
    assert "insufficient_evidence，vulnerability_type 也必须为 null" in prompt
    assert "A 的目标请求返回 403" in prompt
    assert "前读、A 的目标请求、合法读取身份的后读" in prompt


def test_amendment_affects_only_c_arms_and_has_no_case_answers() -> None:
    for condition in ("R0C0", "R1C0"):
        assert "先根据本轮真实请求判断 verdict" not in render_prompt(condition)
    for condition in ("R0C1", "R1C1"):
        prompt = render_prompt(condition)
        assert "先根据本轮真实请求判断 verdict" in prompt
        for marker in ("T05", "T06", "E05", "E06", "T07", "T12", "E07", "E12"):
            assert marker not in prompt
