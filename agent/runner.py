"""Run one candidate authorization check with one local case and one model.

Only the public case projection and permitted tool responses reach the model.
The evaluator's truth file is deliberately never imported here.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from fastapi.testclient import TestClient

from agent.config import (
    MODEL, MODEL_DIGEST_PREFIX, NUM_CTX, PROMPTS, TEMPERATURE,
    TIMEOUT_SECONDS, frozen_config,
)
from agent.tools import AgentTools, MAX_DECISIONS, TOOL_SCHEMAS
from app.main import create_app
from cases.catalog import public_spec_for_case


DEV_CASE_IDS = ("P01_vuln", "P01_fixed", "P04_vuln", "P04_fixed")
CASE_IDS = tuple(f"P{number:02d}_{variant}" for number in range(1, 7)
                 for variant in ("fixed", "vuln"))


class ModelDigestMismatchError(RuntimeError):
    pass


class ModelNotFoundError(RuntimeError):
    pass


def local_chat() -> tuple[Callable[..., Any], dict]:
    """Check the installed model's digest at first chat call, without exposing it."""
    runtime: dict = {"model_digest": None}
    try:
        from ollama import Client
    except ImportError:
        def missing_sdk(**_kwargs: Any) -> Any:
            raise ImportError("The ollama Python SDK is not installed")
        return missing_sdk, runtime

    client = Client(host="http://127.0.0.1:11434", trust_env=False,
                    timeout=TIMEOUT_SECONDS)
    checked = False

    def checked_chat(**kwargs: Any) -> Any:
        nonlocal checked
        if not checked:
            inventory = client.list()
            installed = next((item for item in inventory.models if item.model == MODEL), None)
            if installed is None:
                raise ModelNotFoundError("Configured local model is not installed")
            runtime["model_digest"] = installed.digest
            if not installed.digest or not installed.digest.startswith(MODEL_DIGEST_PREFIX):
                raise ModelDigestMismatchError("Installed model differs from frozen A version")
            checked = True
        return client.chat(**kwargs)

    return checked_chat, runtime


def _tool_failure(code: str) -> str:
    if code == "INVALID_JSON":
        return "invalid_json"
    if code in {"INVALID_FINDING", "UNKNOWN_EVIDENCE"}:
        return "finding_validation_error"
    if code == "REQUEST_LIMIT":
        return "budget_exceeded"
    if code.startswith("HTTP_EXCEPTION:"):
        return "lab_exception"
    if code in {"INVALID_ROUTE", "INVALID_IDENTITY", "INVALID_ARGUMENTS",
                "BODY_TOO_LARGE", "INVALID_BODY", "UNKNOWN_REQUEST", "UNKNOWN_TOOL"}:
        return "tool_parameter_error"
    return "tool_error"


def _model_failure(code: str) -> str:
    if code in {"MODEL_SERVICE_UNAVAILABLE", "MODEL_NOT_INSTALLED", "MODEL_SDK_MISSING"}:
        return "model_service_unavailable"
    if code == "MODEL_TIMEOUT":
        return "model_timeout"
    if code == "MODEL_RESOURCE_ERROR":
        return "model_resource_error"
    if code == "MODEL_VERSION_MISMATCH":
        return "model_version_mismatch"
    return "model_exception"


def run_case(
    case_id: str, chat_fn: Callable[..., Any],
    log_dir: str | Path = "results/tmp", model: str = MODEL,
    runtime_metadata: dict | None = None,
    agent_name: str = "baseline",
) -> dict:
    """Make a fresh database, ask at most 16 times, and persist every outcome."""
    if case_id not in CASE_IDS:
        raise ValueError("Unknown internal case")
    if agent_name not in PROMPTS:
        raise ValueError("Unknown Agent version")
    start = time.perf_counter()
    public = public_spec_for_case(case_id)
    root = Path(log_dir)
    root.mkdir(parents=True, exist_ok=True)
    run_id = uuid4().hex[:12]
    log_path = root / f"agent_{run_id}.jsonl"
    db_path = root / f"agent_{run_id}.sqlite"
    result_path = root / f"agent_{run_id}.json"
    prompt = PROMPTS[agent_name].read_text(encoding="utf-8").strip()
    run_error: dict | None = None

    try:
        app = create_app(case_id, db_path)  # This call alone seeds this run's DB.
    except Exception as error:
        # Preserve a reviewable record even if the lab cannot be initialized.
        failure = {"category": "lab_exception", "code": "LAB_INIT_EXCEPTION:" + type(error).__name__}
        tools = AgentTools(None, log_path, run_id=run_id, db_path=db_path)
        tools.record_run_error(**failure)
        record = {
            "run_id": run_id, "case_id": case_id, "agent_name": agent_name, "status": "run_error",
            "run_error": failure, "model_decisions": 0, "api_requests": 0,
            "finding": None, "write_observations": [],
            "duration_s": round(time.perf_counter() - start, 3),
            "config": frozen_config(agent_name),
            "runtime": dict(runtime_metadata or {}),
            "log_path": str(log_path), "db_path": str(db_path),
            "result_path": str(result_path),
        }
        result_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        return record
    with TestClient(app) as client:
        tools = AgentTools(client, log_path, run_id=run_id, db_path=db_path)
        messages: list[Any] = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(public, ensure_ascii=False)},
        ]

        while not tools.submitted and tools.decision_count < MAX_DECISIONS:
            try:
                response = tools.model_step(
                    chat_fn, model=model, messages=messages, tools=TOOL_SCHEMAS,
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
                messages.append({
                    "role": "user",
                    "content": (
                        "如果还没有请求目标接口，先调用 send_request。"
                        "如果已取得合法对照和 A 的目标请求，并完成必要的状态检查，"
                        "下一步只调用 submit_finding；证据不足则提交 insufficient_evidence。"
                        "不要继续以普通文本作答。"
                    ),
                })
                continue

            for call in calls:
                try:
                    name, arguments = call.function.name, call.function.arguments
                except (AttributeError, TypeError):
                    run_error = {"category": "model_output_error", "code": "MALFORMED_TOOL_CALL"}
                    break
                result = tools.dispatch(name, arguments)
                messages.append({
                    "role": "tool", "tool_name": name,
                    "content": json.dumps(result, ensure_ascii=False),
                })
                if "error" in result:
                    code = result["error"]["code"]
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
        record = {
            "run_id": run_id, "case_id": case_id, "agent_name": agent_name,
            "status": "submitted" if tools.submitted else "run_error",
            "run_error": run_error,
            "model_decisions": tools.decision_count,
            "api_requests": tools.request_count,
            "finding": tools.finding if tools.submitted else None,
            "write_observations": tools.write_observations,
            "duration_s": round(time.perf_counter() - start, 3),
            "config": frozen_config(agent_name),
            "runtime": dict(runtime_metadata or {}),
            "log_path": str(log_path), "db_path": str(db_path),
            "result_path": str(result_path),
        }
    result_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one frozen A-version development case")
    parser.add_argument("--case-id", choices=DEV_CASE_IDS, default="P01_fixed")
    parser.add_argument("--agent", choices=tuple(PROMPTS), default="baseline")
    args = parser.parse_args()
    chat_fn, runtime = local_chat()
    result = run_case(args.case_id, chat_fn, runtime_metadata=runtime,
                      agent_name=args.agent)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
