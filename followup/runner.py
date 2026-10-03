"""One independent follow-up run; original agent.runner is never modified."""

from __future__ import annotations

import json
import time
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
                tools.record_model_text(getattr(message, "content", None))
                messages.append({"role": "user", "content": (
                    "如果还没有请求目标接口，先调用 send_request。"
                    "如果已取得合法对照和 A 的目标请求，并完成必要的状态检查，"
                    "下一步只调用 submit_finding；证据不足则提交 insufficient_evidence。"
                    "不要继续以普通文本作答。"
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
            "experiment": "followup-v1", "condition": condition_name,
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
