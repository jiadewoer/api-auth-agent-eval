"""One real Ollama tool call, with a visible and limited execution trace.

Run from the project root: python -m agent.minimal_tool
This exercise never starts a lab case and never reads truth.json.
"""

from __future__ import annotations

from typing import Any, Callable


MODEL = "qwen3:4b-instruct"
HOST = "http://127.0.0.1:11434"


def read_api_spec() -> str:
    """Read a short, public specification of the synthetic ticket API."""
    return "\n".join(
        [
            "GET /tickets/{ticket_id}: read a ticket when authorized.",
            "GET /tickets/{ticket_id}/comments: read private comments when authorized.",
            "POST /tickets/{ticket_id}/close: close a ticket when authorized.",
            "POST /tickets/{ticket_id}/reassign: administrator-only reassignment.",
            "GET /admin/export: administrator-only export.",
            "GET /admin/audit: administrator-only audit records.",
        ]
    )


def run_once(chat_fn: Callable[..., Any], model: str = MODEL) -> dict:
    """Let the model request one allowlisted tool, execute it, then ask again."""
    messages: list[Any] = [
        {
            "role": "user",
            "content": (
                "请先调用 read_api_spec 工具一次，读取接口说明；"
                "收到工具结果后，用一句中文概括有哪些 GET 和 POST 路由。"
                "不要猜测未提供的接口。"
            ),
        }
    ]

    # Step 1: the model proposes a tool call; it has not executed Python.
    proposed = chat_fn(model=model, messages=messages, tools=[read_api_spec])
    calls = proposed.message.tool_calls or []
    if len(calls) != 1:
        raise RuntimeError(
            f"Expected exactly one tool call; got {len(calls)}. "
            "The model may have answered without using the tool."
        )

    call = calls[0]
    name = call.function.name
    arguments = call.function.arguments
    # Step 2: Python validates the name and arguments before executing anything.
    if name != "read_api_spec" or arguments not in (None, {}):
        raise RuntimeError("Rejected an unexpected tool name or arguments")

    # Keep the assistant's original tool-call message in the conversation.
    messages.append(proposed.message)
    result = read_api_spec()
    # Step 3: give the actual Python return value back with the tool role.
    messages.append({"role": "tool", "tool_name": name, "content": result})

    # Step 4: ask the model to decide its final answer from the tool result.
    final = chat_fn(model=model, messages=messages)
    if final.message.tool_calls:
        raise RuntimeError("Unexpected second tool call in final response")
    messages.append(final.message)
    return {
        "tool_name": name,
        "tool_result": result,
        "answer": final.message.content,
        "messages": messages,
    }


def main() -> None:
    try:
        from ollama import Client
    except ImportError as error:
        raise SystemExit("Install the SDK in this project's .venv: python -m pip install ollama") from error

    # Explicit loopback host avoids a different OLLAMA_HOST setting. Disabling
    # proxy environment use keeps this local HTTP request on the local machine.
    client = Client(host=HOST, trust_env=False)
    try:
        trace = run_once(client.chat)
    except ConnectionError as error:
        raise SystemExit(
            "Cannot reach local Ollama at 127.0.0.1:11434. "
            "Check http://127.0.0.1:11434/api/version before retrying."
        ) from error

    print(f"模型提出工具调用: {trace['tool_name']}()")
    print("Python 已校验并执行；工具结果如下：")
    print(trace["tool_result"])
    print("工具结果已返回模型；模型最终回答：")
    print(trace["answer"])


if __name__ == "__main__":
    main()
