"""Versioned follow-up run: constrained text-tool adapter for all four arms."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from fastapi.testclient import TestClient

from agent.config import MODEL, NUM_CTX, PROMPTS, TEMPERATURE, frozen_config
from agent.runner import CASE_IDS, _model_failure, _tool_failure
from agent.tools import MAX_DECISIONS
from app.main import create_app
from cases.catalog import public_spec_for_case
from followup.conditions import CONDITIONS, model_tools
from followup.gate import FollowupTools
from followup_v2.text_tool import parse_text_tool_call


def run_condition(
    case_id: str, condition_name: str, chat_fn: Callable[..., Any],
    log_dir: str | Path, runtime_metadata: dict | None = None,
) -> dict:
    if case_id not in CASE_IDS or condition_name not in CONDITIONS:
        raise ValueError("Unknown case or condition")
    condition = CONDITIONS[condition_name]
    start = time.perf_counter()
    public = public_spec_for_case(case_id)
    root = Path(log_dir)
    root.mkdir(parents=True, exist_ok=True)
    run_id = uuid4().hex[:12]
    log_path = root / f"agent_{run_id}.jsonl"
    db_path = root / f"agent_{run_id}.sqlite"
    result_path = root / f"agent_{run_id}.json"
    prompt = PROMPTS["baseline"].read_text(encoding="utf-8").strip()
    schema = model_tools(condition)
    run_error = None
    previous_unparsed: str | None = None
    repeated_unparsed = 0
    previous_rejected: str | None = None
    repeated_rejected = 0

    def repeated_evidence_rejection(arguments: Any, result: dict) -> bool:
        """Three identical unsupported claims are a logged failure, not a verdict."""
        nonlocal previous_rejected, repeated_rejected
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                arguments = {}
        fields = ("verdict", "vulnerability_type", "identity", "resource", "evidence_request_ids")
        claim = {key: arguments.get(key) for key in fields} if isinstance(arguments, Mapping) else {}
        signature = json.dumps({"claim": claim, "issues": result["error"].get("issues", [])},
                               sort_keys=True, ensure_ascii=False, default=str)
        if signature == previous_rejected:
            repeated_rejected += 1
        else:
            previous_rejected, repeated_rejected = signature, 1
        return repeated_rejected >= 3

    app = create_app(case_id, db_path)
    with TestClient(app) as client:
        tools = FollowupTools(client, log_path, run_id=run_id, db_path=db_path,
                              public=public, evidence_gate=condition.evidence_gate)
        messages: list[Any] = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(public, ensure_ascii=False)},
        ]
        while not tools.submitted and tools.decision_count < MAX_DECISIONS:
            try:
                response = tools.model_step(
                    chat_fn, model=MODEL, messages=messages, tools=schema,
                    options={"temperature": TEMPERATURE, "num_ctx": NUM_CTX},
                )
            except Exception:
                code = tools.last_model_error_code or "MODEL_EXCEPTION"
                run_error = {"category": _model_failure(code), "code": code}
                break
            try:
                message = response.message
                calls = message.tool_calls or []
                messages.append(message)
            except (AttributeError, TypeError):
                run_error = {"category": "model_output_error", "code": "MALFORMED_MODEL_RESPONSE"}
                break
            if not calls:
                content = getattr(message, "content", None)
                tools.record_model_text(content)
                parsed = parse_text_tool_call(content)
                if parsed is not None:
                    name, arguments = parsed
                    # The model's plain text is untrusted: run exactly the
                    # same validator and allowlist as a native tool call.
                    result = tools.dispatch(name, arguments)
                    tools._log("text_tool_adapter", arguments={"name": name},
                               response_body={"executed": "error" not in result,
                                              "error_code": (result.get("error") or {}).get("code")})
                    # There was no native tool_calls message. Use a user-role
                    # observation; Ollama need not accept an orphan tool reply.
                    messages.append({"role": "user", "content": json.dumps(
                        {"validated_tool_name": name, "validated_tool_result": result},
                        ensure_ascii=False)})
                    if "error" in result:
                        code = result["error"]["code"]
                        if code == "EVIDENCE_CHECK_FAILED":
                            if repeated_evidence_rejection(arguments, result):
                                run_error = {"category": "model_output_error",
                                             "code": "REPEATED_EVIDENCE_REJECTION"}
                                break
                        else:
                            run_error = {"category": _tool_failure(code), "code": code}
                            break
                    if tools.submitted:
                        break
                    previous_unparsed, repeated_unparsed = None, 0
                    continue
                if isinstance(content, str) and content == previous_unparsed:
                    repeated_unparsed += 1
                else:
                    previous_unparsed, repeated_unparsed = content, 1
                if repeated_unparsed >= 3:
                    run_error = {"category": "model_output_error", "code": "REPEATED_UNPARSED_TEXT"}
                    break
                messages.append({"role": "user", "content": (
                    "请使用原生工具调用；如模型不能产生 tool_calls，"
                    "只输出一个完整 JSON 对象："
                    '{"name":"允许的工具名","arguments":{...}}。'
                    "不要输出代码块、前后说明或多个 JSON 对象。"
                )})
                continue
            for call in calls:
                try:
                    name, arguments = call.function.name, call.function.arguments
                except (AttributeError, TypeError):
                    run_error = {"category": "model_output_error", "code": "MALFORMED_TOOL_CALL"}
                    break
                result = tools.dispatch(name, arguments)
                messages.append({"role": "tool", "tool_name": name,
                                 "content": json.dumps(result, ensure_ascii=False)})
                if "error" in result:
                    code = result["error"]["code"]
                    if code == "EVIDENCE_CHECK_FAILED":
                        # E1 gives model-visible, truth-free feedback. Retry consumes
                        # a model decision but no extra API request by itself.
                        if repeated_evidence_rejection(arguments, result):
                            run_error = {"category": "model_output_error",
                                         "code": "REPEATED_EVIDENCE_REJECTION"}
                            break
                        continue
                    run_error = {"category": _tool_failure(code), "code": code}
                    break
                if tools.submitted:
                    break
            if run_error:
                break

        if not tools.submitted and run_error is None:
            run_error = {"category": "no_conclusion", "code": "NO_CONCLUSION"}
        if run_error:
            tools.record_run_error(**run_error)
        config = frozen_config("baseline")
        config.update({
            "experiment": "followup-v2-text-adapter", "condition": condition_name,
            "guided_schema": condition.guided_schema,
            "evidence_gate": condition.evidence_gate,
            "tool_spec_sha256": sha256(json.dumps(schema, sort_keys=True,
                ensure_ascii=False).encode("utf-8")).hexdigest(),
        })
        record = {
            "run_id": run_id, "case_id": case_id,
            "condition": condition_name,
            "status": "submitted" if tools.submitted else "run_error",
            "run_error": run_error, "finding": tools.finding if tools.submitted else None,
            "api_requests": tools.request_count,
            "model_decisions": tools.decision_count,
            "gate_rejections": tools.gate_rejections,
            "write_observations": tools.write_observations,
            "duration_s": round(time.perf_counter() - start, 3),
            "config": config, "runtime": dict(runtime_metadata or {}),
            "log_path": str(log_path), "db_path": str(db_path),
            "result_path": str(result_path),
        }
    result_path.write_text(json.dumps(record, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    return record
