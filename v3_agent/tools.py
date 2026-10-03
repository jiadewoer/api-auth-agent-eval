"""Bounded cross-app tools; only the runner holds a TestClient and bearer tokens."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from pydantic import ValidationError

from agent.finding import Finding
from v3_agent.protocol import (
    MAX_BODY_BYTES, MAX_DECISIONS, MAX_REQUESTS, bearer_for, public_api_for,
    resource_for, route_match, valid_body, write_target,
)


def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": required, "additionalProperties": False},
    }}


TOOL_SCHEMAS = [
    _schema("read_api_spec", "Read the current task's public API contract. Optional path must equal the task target_path.", {
        "path": {"type": "string", "description": "Optional exact target_path from the public task, not a URL."},
    }, []),
    _schema("send_request", "Send a bounded request to a local allowlisted route.", {
        "identity": {"type": "string", "enum": ["A", "B", "M"]},
        "method": {"type": "string", "enum": ["GET", "POST"]},
        "path": {"type": "string", "description": "Relative path only; no URL or host."},
        "json_body": {"type": ["object", "null"], "description": "Use public request_body for POST; null for GET and bodyless POST."},
    }, ["identity", "method", "path"]),
    _schema("inspect_response", "Recall an earlier request from this run.", {
        "request_id": {"type": "string"},
    }, ["request_id"]),
    _schema("submit_finding", "Submit a verdict and cite real request IDs.", {
        "verdict": {"type": "string", "enum": ["vulnerable", "not_vulnerable", "insufficient_evidence"]},
        "vulnerability_type": {"type": ["string", "null"], "enum": ["BOLA", "BFLA", "", None]},
        "identity": {"type": "string", "enum": ["A", "B", "M"]},
        "resource": {"type": "string", "description": "target_object.kind + '_' + target_object.id"},
        "evidence_request_ids": {"type": "array", "items": {"type": "string"}},
        "explanation": {"type": "string", "minLength": 1, "maxLength": 4096},
    }, ["verdict", "vulnerability_type", "identity", "resource", "evidence_request_ids", "explanation"]),
]


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        value = re.sub(r"(?i)(?:lab|expense)-token-[a-z0-9_-]+", "[REDACTED]", value)
        return value[:2048] + ("...[TRUNCATED]" if len(value) > 2048 else "")
    if isinstance(value, dict):
        return {str(k): _redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


class V3Tools:
    """State belongs to one app instance, one run and one temporary database."""

    def __init__(
        self, client: Any, *, app_id: str, public: Mapping[str, Any],
        db_path: str | Path, log_path: str | Path, run_id: str | None = None,
        evidence_gate: bool = True,
    ) -> None:
        if app_id not in {"ticket_lab_v3", "expense_lab_v1"}:
            raise ValueError("Unknown V3 app")
        self.client = client
        self.app_id = app_id
        self.public = dict(public)
        self.db_path = Path(db_path)
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or uuid4().hex[:12]
        self.evidence_gate = evidence_gate
        self.step = 0
        self.request_count = 0
        self.decision_count = 0
        self.gate_rejections = 0
        self.submitted = False
        self.finding: dict | None = None
        self._requests: dict[str, dict] = {}
        self.write_observations: list[dict] = []
        self.last_model_error_code: str | None = None

    def _log(self, tool_name: str, *, arguments: Any = None,
             identity: str | None = None, request_id: str | None = None,
             response_status: int | None = None, response_body: Any = None,
             error: str | None = None, elapsed_ms: float = 0.0) -> None:
        self.step += 1
        row = {"run_id": self.run_id, "step": self.step, "tool_name": tool_name,
               "arguments": _redact(arguments), "identity": identity,
               "request_id": request_id, "response_status": response_status,
               "response_body": _redact(response_body),
               "elapsed_ms": round(elapsed_ms, 3), "error": error}
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    def _error(self, tool_name: str, code: str, arguments: Any = None) -> dict:
        # The model receives only a stable code, not its potentially dangerous input.
        self._log(tool_name, arguments=arguments, error=code)
        return {"error": {"code": code, "message": "Tool request rejected"}}

    def _private_field(self, target: tuple[str, int, str]) -> Any:
        table, object_id, field = target
        if (table, field) not in {
            ("tickets", "status"), ("tickets", "owner_id"),
            ("tickets", "shared_with_id"), ("claims", "status"),
            ("claims", "payee_id"),
        }:
            raise ValueError("Private state field not allowlisted")
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(f"SELECT {field} FROM {table} WHERE id = ?", (object_id,)).fetchone()
        return row[0] if row else None

    def read_api_spec(self, path: str | None = None) -> dict:
        if self.submitted:
            return self._error("read_api_spec", "ALREADY_SUBMITTED")
        if path is not None and (not isinstance(path, str) or path != self.public["target_path"]):
            return self._error("read_api_spec", "INVALID_ROUTE", {"path": path})
        result = {"spec": public_api_for(self.app_id)}
        self._log("read_api_spec", arguments={"path": path} if path is not None else {},
                  response_body=result)
        return result

    def send_request(self, identity: str, method: str, path: str,
                     json_body: dict | None = None) -> dict:
        started = time.perf_counter()
        args = {"identity": identity, "method": method, "path": path, "json_body": json_body}
        if self.submitted:
            return self._error("send_request", "ALREADY_SUBMITTED", args)
        if not isinstance(identity, str) or identity not in {"A", "B", "M"}:
            return self._error("send_request", "INVALID_IDENTITY", args)
        match = route_match(self.app_id, method, path)
        if match is None:
            return self._error("send_request", "INVALID_ROUTE", args)
        try:
            body_len = len(json.dumps(json_body, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            return self._error("send_request", "INVALID_BODY", args)
        if body_len > MAX_BODY_BYTES:
            return self._error("send_request", "BODY_TOO_LARGE", args)
        if not valid_body(self.app_id, method, path, json_body):
            return self._error("send_request", "INVALID_BODY", args)
        if self.request_count >= MAX_REQUESTS:
            return self._error("send_request", "REQUEST_LIMIT", args)
        self.request_count += 1
        request_id = f"r{self.request_count:03d}"
        target = write_target(self.app_id, path) if method == "POST" else None
        try:
            before = self._private_field(target) if target else None
            response = self.client.request(
                method, path,
                headers={"Authorization": "Bearer " + bearer_for(self.app_id, identity)},
                **({"json": json_body} if json_body is not None else {}),
            )
            body = response.json()
            after = self._private_field(target) if target else None
        except Exception as error:
            code = "HTTP_EXCEPTION:" + type(error).__name__
            self._log("send_request", arguments=args, identity=identity,
                      request_id=request_id, error=code,
                      elapsed_ms=(time.perf_counter() - started) * 1000)
            return {"request_id": request_id,
                    "error": {"code": code, "message": "API request failed"}}
        result = {"request_id": request_id, "status_code": response.status_code,
                  "body": _redact(body)}
        self._requests[request_id] = {**result, "identity": identity,
                                      "method": method, "path": path}
        if target:
            table, object_id, field = target
            # Private snapshots stay in the runner result, never in tool output.
            self.write_observations.append({
                "run_id": self.run_id, "request_id": request_id,
                "identity": identity, "method": method, "path": path,
                "table": table, "object_id": object_id, "field": field,
                "before": before, "after": after,
            })
        self._log("send_request", arguments=args, identity=identity,
                  request_id=request_id, response_status=response.status_code,
                  response_body=result["body"],
                  elapsed_ms=(time.perf_counter() - started) * 1000)
        return result

    def inspect_response(self, request_id: str) -> dict:
        if self.submitted:
            return self._error("inspect_response", "ALREADY_SUBMITTED", {"request_id": request_id})
        if not isinstance(request_id, str) or request_id not in self._requests:
            return self._error("inspect_response", "UNKNOWN_REQUEST", {"request_id": request_id})
        result = dict(self._requests[request_id])
        self._log("inspect_response", arguments={"request_id": request_id},
                  identity=result["identity"], request_id=request_id,
                  response_status=result["status_code"], response_body=result["body"])
        return result

    def submit_finding(self, **arguments: Any) -> dict:
        if self.submitted:
            return self._error("submit_finding", "ALREADY_SUBMITTED", arguments)
        try:
            finding = Finding.model_validate(arguments)
        except ValidationError:
            return self._error("submit_finding", "INVALID_FINDING", arguments)
        if any(rid not in self._requests for rid in finding.evidence_request_ids):
            return self._error("submit_finding", "UNKNOWN_EVIDENCE", arguments)
        if self.evidence_gate:
            from v3_agent.gate import evidence_issues
            issues = evidence_issues(self.public, finding, self._requests)
            if issues:
                self.gate_rejections += 1
                self._log("evidence_gate",
                          arguments={"request_ids": finding.evidence_request_ids},
                          response_body={"issues": issues}, error="EVIDENCE_CHECK_FAILED")
                return {"error": {"code": "EVIDENCE_CHECK_FAILED", "issues": issues}}
            self._log("evidence_gate",
                      arguments={"request_ids": finding.evidence_request_ids},
                      response_body={"accepted": True})
        self.finding = _redact(finding.model_dump(mode="json"))
        self.submitted = True
        self._log("submit_finding", arguments=arguments, response_body={"accepted": True})
        return {"accepted": True}

    def dispatch(self, name: str, arguments: Mapping[str, Any] | str | None) -> dict:
        allowed = {
            "read_api_spec": (self.read_api_spec, {"path"}, set()),
            "send_request": (self.send_request,
                             {"identity", "method", "path", "json_body"},
                             {"identity", "method", "path"}),
            "inspect_response": (self.inspect_response, {"request_id"}, {"request_id"}),
            "submit_finding": (self.submit_finding,
                               {"verdict", "vulnerability_type", "identity", "resource",
                                "evidence_request_ids", "explanation"},
                               {"verdict", "vulnerability_type", "identity", "resource",
                                "evidence_request_ids", "explanation"}),
        }
        if self.submitted:
            return self._error("tool_dispatch", "ALREADY_SUBMITTED", arguments)
        if not isinstance(name, str) or name not in allowed:
            return self._error("tool_dispatch", "UNKNOWN_TOOL", {"name": name})
        # Ollama can encode an empty-parameter call as JSON null. Normalize
        # only this no-argument tool; request and finding tools stay strict.
        if name == "read_api_spec" and arguments is None:
            self._log("tool_argument_normalization", arguments={
                "name": name, "original": None, "normalized": {},
            })
            arguments = {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except (TypeError, ValueError):
                return self._error(name, "INVALID_JSON")
        fn, permitted, required = allowed[name]
        if not isinstance(arguments, Mapping) or not required.issubset(arguments) or not set(arguments).issubset(permitted):
            return self._error(name, "INVALID_ARGUMENTS", arguments)
        return fn(**arguments)

    def record_run_error(self, category: str, code: str) -> None:
        self._log("run_error", arguments={"category": category}, error=code)

    def model_step(self, chat_fn: Callable[..., Any], **kwargs: Any) -> Any:
        if self.decision_count >= MAX_DECISIONS:
            raise RuntimeError("DECISION_LIMIT")
        self.decision_count += 1
        start = time.perf_counter()
        try:
            response = chat_fn(**kwargs)
        except Exception as error:
            self.last_model_error_code = (
                "MODEL_TIMEOUT" if "timeout" in type(error).__name__.lower()
                else "MODEL_SERVICE_UNAVAILABLE" if "connection" in type(error).__name__.lower()
                else "MODEL_EXCEPTION:" + type(error).__name__
            )
            self._log("model_decision", arguments={"count": self.decision_count},
                      error=self.last_model_error_code,
                      elapsed_ms=(time.perf_counter() - start) * 1000)
            raise
        self._log("model_decision", arguments={"count": self.decision_count},
                  elapsed_ms=(time.perf_counter() - start) * 1000)
        return response

    def record_model_text(self, content: Any) -> None:
        self._log("model_text", response_body={"content": content})
