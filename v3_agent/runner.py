"""One V3 case, one fresh TestClient, database, model conversation and trace."""

from __future__ import annotations

import json
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from fastapi.testclient import TestClient

from cases.v3_catalog import internal_case_for, public_spec_for_case
from expense_app.main import create_app as expense_app
from followup_v2.text_tool import parse_text_tool_call
from ticket_v3.main import create_app as ticket_app
from v3_agent.protocol import MAX_DECISIONS
from v3_agent.tools import TOOL_SCHEMAS, V3Tools


ROOT = Path(__file__).resolve().parents[1]
PROMPT = ROOT / "v3_agent/prompts/dev_baseline.txt"
PROMPTS = {"A": PROMPT, "B": ROOT / "v3_agent/prompts/evidence_check.txt"}
MODEL = "qwen3:8b"
TEMPERATURE = 0.2
NUM_CTX = 4096
RECOVERABLE_TOOL_ERRORS = {"INVALID_ROUTE", "INVALID_BODY", "INVALID_ARGUMENTS", "INVALID_FINDING"}
MAX_TOOL_REJECTIONS = 3

# Shared by A and B. This clarifies the tool protocol using fields already in
# the public task; it supplies neither a verdict nor an evidence sequence.
COMMON_TOOL_GUIDANCE = (
    "The preceding JSON is the public task. For A's target send_request, copy "
    "target_method and target_path exactly; pass request_body exactly as "
    "json_body (null when request_body is null). Use a documented GET route "
    "for a read; do not change a POST route into a GET route. In "
    "submit_finding, identity is A and resource is target_object.kind + '_' "
    "+ target_object.id. Cite actual request IDs. If an evidence check returns "
    "issues, correct the cited evidence or submission fields before trying "
    "again. Evidence-check acceptance alone does not establish a vulnerability; "
    "choose a verdict from the observed HTTP responses and visible state."
)


def _tool_category(code: str) -> str:
    if code == "REQUEST_LIMIT":
        return "budget_exceeded"
    if code in {"INVALID_FINDING", "UNKNOWN_EVIDENCE"}:
        return "finding_validation_error"
    if code.startswith("HTTP_EXCEPTION:"):
        return "lab_exception"
    return "tool_parameter_error"


def run_case(case_id: str, chat_fn: Callable[..., Any], output: str | Path,
             runtime: Mapping[str, Any] | None = None, *, condition: str = "A") -> dict:
    if condition not in PROMPTS:
        raise ValueError("Unknown A/B condition")
    prompt_file = PROMPTS[condition]
    internal = internal_case_for(case_id)  # Evaluator routing, never sent to chat_fn.
    public = public_spec_for_case(case_id)
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    run_id = uuid4().hex[:12]
    log_path, db_path = out / f"agent_{run_id}.jsonl", out / f"agent_{run_id}.sqlite"
    result_path = out / f"agent_{run_id}.json"
    started = time.perf_counter()
    tools: V3Tools | None = None
    failure: dict | None = None

    try:
        app = (ticket_app(case_id, db_path) if internal["app_id"] == "ticket_lab_v3"
               else expense_app(db_path, case_id=case_id))
        with TestClient(app) as client:
            tools = V3Tools(client, app_id=internal["app_id"], public=public,
                            db_path=db_path, log_path=log_path, run_id=run_id)
            messages: list[Any] = [
                {"role": "system", "content": prompt_file.read_text(encoding="utf-8").strip()},
                {"role": "user", "content": json.dumps(public, ensure_ascii=False)},
                {"role": "user", "content": COMMON_TOOL_GUIDANCE},
            ]
            repeated_gate: tuple[str, int] | None = None
            repeated_text: tuple[str, int] | None = None
            parameter_rejections = 0
            pending_feedback: str | None = None

            def process(name: str, arguments: Any, *, text_tool: bool = False) -> dict:
                nonlocal failure, repeated_gate, parameter_rejections, pending_feedback
                result = tools.dispatch(name, arguments)
                if text_tool:
                    tools._log("text_tool_adapter", arguments={"name": name},
                               response_body={"executed": "error" not in result,
                                              "error_code": (result.get("error") or {}).get("code")})
                    messages.append({"role": "user", "content": json.dumps(
                        {"validated_tool_name": name, "validated_tool_result": result},
                        ensure_ascii=False)})
                else:
                    messages.append({"role": "tool", "tool_name": name,
                                     "content": json.dumps(result, ensure_ascii=False)})
                if "error" in result:
                    code = result["error"]["code"]
                    if code == "EVIDENCE_CHECK_FAILED":
                        signature = json.dumps({"arguments": arguments,
                                                "issues": result["error"].get("issues")},
                                               sort_keys=True, default=str)
                        if repeated_gate and repeated_gate[0] == signature:
                            repeated_gate = (signature, repeated_gate[1]+1)
                        else:
                            repeated_gate = (signature, 1)
                        if repeated_gate[1] >= 3:
                            failure = {"category": "model_output_error", "code": "REPEATED_EVIDENCE_REJECTION"}
                    elif code in RECOVERABLE_TOOL_ERRORS:
                        # The invalid attempt remains in the trace. The model must
                        # correct its own call; no tool input is rewritten here.
                        parameter_rejections += 1
                        if parameter_rejections >= MAX_TOOL_REJECTIONS:
                            failure = {"category": _tool_category(code), "code": code}
                        else:
                            pending_feedback = code
                    else:
                        failure = {"category": _tool_category(code), "code": code}
                return result

            def deliver_feedback() -> None:
                nonlocal pending_feedback
                if pending_feedback and not failure and not tools.submitted:
                    messages.append({"role": "user", "content": (
                        "The tool rejected a call with " + pending_feedback + ". "
                        "Recheck the public task and API specification. "
                        "Use a documented method/path and copy request_body exactly "
                        "for the target request. For submit_finding, supply every "
                        "required field: verdict, vulnerability_type, identity, "
                        "resource, evidence_request_ids, explanation. "
                        "Do not repeat rejected arguments."
                    )})
                pending_feedback = None

            while not tools.submitted and tools.decision_count < MAX_DECISIONS and not failure:
                try:
                    response = tools.model_step(
                        chat_fn, model=MODEL, messages=messages, tools=TOOL_SCHEMAS,
                        options={"temperature": TEMPERATURE, "num_ctx": NUM_CTX},
                    )
                except Exception:
                    code = tools.last_model_error_code or "MODEL_EXCEPTION"
                    category = "model_service_unavailable" if code == "MODEL_SERVICE_UNAVAILABLE" else \
                               "model_timeout" if code == "MODEL_TIMEOUT" else "model_exception"
                    failure = {"category": category, "code": code}
                    break
                try:
                    message = response.message
                    calls = message.tool_calls or []
                    messages.append(message)
                except (AttributeError, TypeError):
                    failure = {"category": "model_output_error", "code": "MALFORMED_MODEL_RESPONSE"}
                    break
                if not calls:
                    content = getattr(message, "content", None)
                    tools.record_model_text(content)
                    parsed = parse_text_tool_call(content)
                    if parsed is not None:
                        name, arguments = parsed
                        process(name, arguments, text_tool=True)
                        deliver_feedback()
                        repeated_text = None
                        continue
                    signature = content if isinstance(content, str) else ""
                    if repeated_text and repeated_text[0] == signature:
                        repeated_text = (signature, repeated_text[1]+1)
                    else:
                        repeated_text = (signature, 1)
                    if repeated_text[1] >= 3:
                        failure = {"category": "model_output_error", "code": "REPEATED_UNPARSED_TEXT"}
                        break
                    if signature.strip() in {"vulnerable", "not_vulnerable", "insufficient_evidence"}:
                        reminder = (
                            "单独的结论词不是提交。请调用 submit_finding，并提供 "
                            "verdict、vulnerability_type、identity、resource、"
                            "evidence_request_ids、explanation 六个字段；若只能输出文本，"
                            '输出 {"name":"submit_finding","arguments":{...}}。'
                        )
                    else:
                        reminder = (
                            "请调用一个工具；若仅能输出文本，只输出完整 JSON 对象 "
                            '{"name":"工具名","arguments":{...}}。'
                        )
                    messages.append({"role": "user", "content": reminder})
                    continue
                for call in calls:
                    try:
                        name, arguments = call.function.name, call.function.arguments
                    except (AttributeError, TypeError):
                        failure = {"category": "model_output_error", "code": "MALFORMED_TOOL_CALL"}
                        break
                    process(name, arguments)
                    if failure or tools.submitted:
                        break
                deliver_feedback()
            if not tools.submitted and failure is None:
                failure = {"category": "no_conclusion", "code": "NO_CONCLUSION"}
            if failure:
                tools.record_run_error(**failure)
    except Exception as error:
        # Preserve the failed run instead of dropping it or calling it a fixed case.
        if tools is None:
            tools = V3Tools(None, app_id=internal["app_id"], public=public,
                            db_path=db_path, log_path=log_path, run_id=run_id)
        failure = {"category": "lab_exception", "code": "LAB_EXCEPTION:" + type(error).__name__}
        tools.record_run_error(**failure)

    record = {
        "run_id": run_id, "case_id": case_id, "app_id": internal["app_id"],
        "condition": condition,
        "public_task_id": public["public_task_id"],
        "status": "submitted" if tools.submitted else "run_error",
        "run_error": failure, "finding": tools.finding if tools.submitted else None,
        "api_requests": tools.request_count, "model_decisions": tools.decision_count,
        "gate_rejections": tools.gate_rejections,
        "write_observations": tools.write_observations,
        "duration_s": round(time.perf_counter()-started, 3),
        "config": {"model": MODEL, "temperature": TEMPERATURE, "num_ctx": NUM_CTX,
                   "request_limit": 8, "decision_limit": MAX_DECISIONS,
                   "prompt_sha256": sha256(prompt_file.read_bytes()).hexdigest()},
        "runtime": dict(runtime or {}), "log_path": str(log_path),
        "db_path": str(db_path), "result_path": str(result_path),
    }
    result_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return record
