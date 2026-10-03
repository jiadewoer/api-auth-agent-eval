"""Verify both tool-call and tool-result messages reach the second chat call."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from agent.minimal_tool import read_api_spec, run_once


def test_tool_call_is_validated_executed_and_returned_to_model():
    received = []
    tool_call = SimpleNamespace(function=SimpleNamespace(name="read_api_spec", arguments={}))
    first_message = SimpleNamespace(content="", tool_calls=[tool_call])
    last_message = SimpleNamespace(content="GET 和 POST 路由。", tool_calls=[])

    def fake_chat(*, model, messages, tools=None):
        received.append((model, deepcopy(messages), tools))
        if len(received) == 1:
            assert tools == [read_api_spec]
            return SimpleNamespace(message=first_message)
        assert tools is None
        return SimpleNamespace(message=last_message)

    trace = run_once(fake_chat)
    assert len(received) == 2
    assert received[1][1][1].tool_calls[0].function.name == "read_api_spec"
    assert received[1][1][2] == {
        "role": "tool", "tool_name": "read_api_spec", "content": read_api_spec()
    }
    assert trace["answer"] == "GET 和 POST 路由。"


@pytest.mark.parametrize("name,args", [("unexpected_tool", {}), ("read_api_spec", {"path": "/"})])
def test_unexpected_tool_or_arguments_are_rejected(name, args):
    def fake_chat(*, model, messages, tools=None):
        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=args))
        message = SimpleNamespace(content="", tool_calls=[call])
        return SimpleNamespace(message=message)

    with pytest.raises(RuntimeError, match="Rejected"):
        run_once(fake_chat)
