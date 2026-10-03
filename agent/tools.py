"""Bounded tools for one local API authorization investigation.

The runner binds one FastAPI TestClient to one AgentTools instance. The model
only sees TOOL_SCHEMAS and tool results, never the TestClient or raw tokens.
"""

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


MAX_REQUESTS = 8
MAX_DECISIONS = 16
MAX_BODY_BYTES = 1024
_TOKENS = {"A": "lab-token-a", "B": "lab-token-b", "M": "lab-token-m"}
_ID = r"(0|[1-9][0-9]{0,18})"
_ROUTES = (
    ("GET", re.compile(rf"/tickets/{_ID}")),
    ("GET", re.compile(rf"/tickets/{_ID}/comments")),
    ("POST", re.compile(rf"/tickets/{_ID}/close")),
    ("POST", re.compile(rf"/tickets/{_ID}/reassign")),
    ("GET", re.compile(r"/admin/export")),
    ("GET", re.compile(r"/admin/audit")),
)
_PUBLIC_API = "\n".join(
    [
        "GET /tickets/{ticket_id}: ticket body (owner/admin/shared).",
        "GET /tickets/{ticket_id}/comments: private comments (owner/admin).",
        "POST /tickets/{ticket_id}/close: close ticket (owner/admin).",
        "POST /tickets/{ticket_id}/reassign: reassign ticket (admin).",
        "GET /admin/export: export private data (admin).",
        "GET /admin/audit: read audit entries (admin).",
    ]
)


def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object", "properties": properties,
                "required": required, "additionalProperties": False,
            },
        },
    }


# JSON schemas keep the model-facing parameter list separate from Python state.
TOOL_SCHEMAS = [
    _schema("read_api_spec", "Read short public API documentation.", {}, []),
    _schema(
        "send_request", "Make one request to an allowlisted route as a test identity.",
        {
            "identity": {"type": "string", "enum": ["A", "B", "M"]},
            "method": {"type": "string", "enum": ["GET", "POST"]},
            "path": {"type": "string", "description": "Local path only, never a full URL."},
            "json_body": {"type": ["object", "null"], "description": "Only reassign uses {new_owner_id: A or B}."},
        },
        ["identity", "method", "path"],
    ),
    _schema(
        "inspect_response", "Read one of your own previous request results.",
        {"request_id": {"type": "string"}}, ["request_id"],
    ),
    _schema(
        "submit_finding", "Submit your final finding with real request IDs as evidence.",
        {
            "verdict": {"type": "string", "enum": ["vulnerable", "not_vulnerable", "insufficient_evidence"]},
            "vulnerability_type": {"type": ["string", "null"], "enum": ["BOLA", "BFLA", "", None]},
            "identity": {"type": "string", "enum": ["A", "B", "M"]},
            "resource": {
                "type": "string",
                "enum": ["ticket_201", "ticket_comments_201", "admin_export", "admin_audit"],
                "description": "Canonical resource from the public target_object, never a URL or API path.",
            },
            "evidence_request_ids": {"type": "array", "items": {"type": "string"}},
            "explanation": {"type": "string", "minLength": 1, "maxLength": 4096},
        },
        ["verdict", "vulnerability_type", "identity", "resource", "evidence_request_ids", "explanation"],
    ),
]


def _redact(value: Any) -> Any:
    """Prevent synthetic token strings from entering JSONL logs."""
    if isinstance(value, str):
        cleaned = re.sub(r"(?i)lab-token-[a-z0-9_-]+", "[REDACTED]", value)
        return cleaned if len(cleaned) <= 2048 else cleaned[:2048] + "...[TRUNCATED]"
    if isinstance(value, dict):
        return {str(key): _redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


class AgentTools:
    """All request state and budgets belong to one run and one TestClient."""

    def __init__(self, client: Any, log_path: str | Path, run_id: str | None = None,
                 db_path: str | Path | None = None):
        self.client = client
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or uuid4().hex[:12]  # Never derive it from case_id.
        self.step = 0
        self.request_count = 0
        self.decision_count = 0
        self.submitted = False
        self.finding: dict | None = None
        self.last_model_error_code: str | None = None
        self._requests: dict[str, dict] = {}
        self._db_path = Path(db_path) if db_path is not None else None
        # Internal oracle observation, never returned by a model-facing tool.
        self.write_observations: list[dict] = []

    def _ticket_state(self, ticket_id: int, field: str) -> str | None:
        if self._db_path is None:
            return None
        if field not in {"status", "owner_id"}:
            raise ValueError("Unsupported internal state field")
        conn = sqlite3.connect(self._db_path)
        try:
            row = conn.execute(f"SELECT {field} FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            return row[0] if row is not None else None
        finally:
            conn.close()

    def _log(
        self, tool_name: str, *, arguments: Any = None, identity: str | None = None,
        request_id: str | None = None, response_status: int | None = None,
        response_body: Any = None, elapsed_ms: float = 0.0,
        error: str | None = None,
    ) -> None:
        self.step += 1
        row = {
            "run_id": self.run_id, "step": self.step, "tool_name": tool_name,
            "arguments": _redact(arguments), "identity": identity,
            "request_id": request_id, "response_status": response_status,
            "response_body": _redact(response_body),
            "elapsed_ms": round(elapsed_ms, 3), "error": error,
        }
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    def _error(self, tool_name: str, code: str, *, arguments: Any = None,
               identity: str | None = None, start: float | None = None) -> dict:
        # Do not echo rejected arguments back to the model.
        result = {"error": {"code": code, "message": "Tool request rejected"}}
        elapsed = (time.perf_counter() - start) * 1000 if start is not None else 0.0
        self._log(tool_name, arguments=arguments, identity=identity,
                  elapsed_ms=elapsed, error=code)
        return result

    def read_api_spec(self) -> dict:
        start = time.perf_counter()
        if self.submitted:
            return self._error("read_api_spec", "ALREADY_SUBMITTED", start=start)
        result = {"spec": _PUBLIC_API}
        self._log("read_api_spec", arguments={}, response_body=result,
                  elapsed_ms=(time.perf_counter() - start) * 1000)
        return result

    def send_request(
        self, identity: str, method: str, path: str, json_body: dict | None = None,
        **extra: Any,
    ) -> dict:
        start = time.perf_counter()
        args = {"identity": identity, "method": method, "path": path, "json_body": json_body}
        if self.submitted:
            return self._error("send_request", "ALREADY_SUBMITTED", arguments=args, start=start)
        if extra:
            return self._error("send_request", "INVALID_ARGUMENTS",
                               arguments={**args, **extra}, start=start)
        if not isinstance(identity, str) or identity not in _TOKENS:
            return self._error("send_request", "INVALID_IDENTITY", arguments=args, start=start)
        if method not in ("GET", "POST") or not isinstance(path, str) or len(path) > 40:
            return self._error("send_request", "INVALID_ROUTE", arguments=args,
                               identity=identity, start=start)
        route = next(
            (match for expected, pattern in _ROUTES if expected == method
             and (match := pattern.fullmatch(path))), None
        )
        if route is None or (route.groups() and int(route.group(1)) > 9223372036854775807):
            return self._error("send_request", "INVALID_ROUTE", arguments=args,
                               identity=identity, start=start)
        try:
            body_bytes = len(json.dumps(json_body, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            return self._error("send_request", "INVALID_BODY", arguments=args,
                               identity=identity, start=start)
        if body_bytes > MAX_BODY_BYTES:
            return self._error("send_request", "BODY_TOO_LARGE", arguments=args,
                               identity=identity, start=start)
        if method == "POST" and path.endswith("/reassign"):
            if (not isinstance(json_body, dict) or set(json_body) != {"new_owner_id"}
                    or json_body["new_owner_id"] not in ("A", "B")):
                return self._error("send_request", "INVALID_BODY", arguments=args,
                                   identity=identity, start=start)
        elif json_body is not None:
            return self._error("send_request", "INVALID_BODY", arguments=args,
                               identity=identity, start=start)
        if self.request_count >= MAX_REQUESTS:
            return self._error("send_request", "REQUEST_LIMIT", arguments=args,
                               identity=identity, start=start)

        self.request_count += 1  # Only actual TestClient attempts consume budget.
        request_id = f"r{self.request_count:03d}"
        options = {"json": json_body} if json_body is not None else {}
        write_field = ("status" if method == "POST" and path.endswith("/close") else
                       "owner_id" if method == "POST" and path.endswith("/reassign") else None)
        try:
            before = self._ticket_state(int(route.group(1)), write_field) if write_field else None
            response = self.client.request(
                method, path, headers={"Authorization": f"Bearer {_TOKENS[identity]}"},
                **options,
            )
            body = response.json()
            after = self._ticket_state(int(route.group(1)), write_field) if write_field else None
        except Exception as error:
            code = "HTTP_EXCEPTION:" + type(error).__name__
            self._log("send_request", arguments=args, identity=identity,
                      request_id=request_id,
                      elapsed_ms=(time.perf_counter() - start) * 1000, error=code)
            return {"request_id": request_id, "error": {"code": code, "message": "API request failed"}}

        safe_body = _redact(body)
        result = {"request_id": request_id, "status_code": response.status_code, "body": safe_body}
        self._requests[request_id] = {
            **result, "identity": identity, "method": method, "path": path,
        }
        if write_field and self._db_path is not None:
            self.write_observations.append({
                "run_id": self.run_id, "request_id": request_id,
                "identity": identity, "method": method, "path": path,
                "ticket_id": int(route.group(1)), "field": write_field,
                "before": before, "after": after,
            })
        self._log("send_request", arguments=args, identity=identity,
                  request_id=request_id, response_status=response.status_code,
                  response_body=safe_body, elapsed_ms=(time.perf_counter() - start) * 1000)
        return result

    def inspect_response(self, request_id: str) -> dict:
        start = time.perf_counter()
        if self.submitted:
            return self._error("inspect_response", "ALREADY_SUBMITTED",
                               arguments={"request_id": request_id}, start=start)
        if not isinstance(request_id, str) or request_id not in self._requests:
            return self._error("inspect_response", "UNKNOWN_REQUEST",
                               arguments={"request_id": request_id}, start=start)
        result = dict(self._requests[request_id])
        self._log("inspect_response", arguments={"request_id": request_id},
                  identity=result["identity"], request_id=request_id,
                  response_status=result["status_code"], response_body=result["body"],
                  elapsed_ms=(time.perf_counter() - start) * 1000)
        return result

    def submit_finding(
        self, verdict: str, vulnerability_type: str | None,
        identity: str, resource: str, evidence_request_ids: list[str],
        explanation: str,
    ) -> dict:
        start = time.perf_counter()
        args = {"verdict": verdict, "vulnerability_type": vulnerability_type,
                "identity": identity, "resource": resource,
                "evidence_request_ids": evidence_request_ids, "explanation": explanation}
        if self.submitted:
            return self._error("submit_finding", "ALREADY_SUBMITTED", arguments=args, start=start)
        try:
            finding = Finding.model_validate(args)
        except ValidationError:
            return self._error("submit_finding", "INVALID_FINDING", arguments=args, start=start)
        if any(item not in self._requests for item in finding.evidence_request_ids):
            return self._error("submit_finding", "UNKNOWN_EVIDENCE", arguments=args, start=start)
        self.finding = _redact(finding.model_dump(mode="json"))
        self.submitted = True
        self._log("submit_finding", arguments=args, response_body={"accepted": True},
                  elapsed_ms=(time.perf_counter() - start) * 1000)
        return {"accepted": True}

    def dispatch(self, name: str, arguments: Mapping[str, Any] | None) -> dict:
        """Validate raw model arguments, including extra keys, before calling a tool."""
        allowed = {
            "read_api_spec": (self.read_api_spec, set(), set()),
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
            return self._error("tool_dispatch", "ALREADY_SUBMITTED", arguments=arguments)
        if name not in allowed:
            return self._error("tool_dispatch", "UNKNOWN_TOOL", arguments=arguments)
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except (ValueError, TypeError):
                return self._error(name, "INVALID_JSON", arguments={"raw_length": len(arguments)})
        fn, permitted, required = allowed[name]
        if not isinstance(arguments, Mapping) or not required.issubset(arguments) or not set(arguments).issubset(permitted):
            return self._error(name, "INVALID_ARGUMENTS", arguments=arguments)
        return fn(**arguments)

    def record_run_error(self, category: str, code: str) -> None:
        """Terminal failure is a separate event, never a negative finding."""
        self._log("run_error", arguments={"category": category}, error=code)

    def record_model_text(self, content: Any) -> None:
        """Keep a redacted diagnostic when the model replies without a tool call."""
        self._log("model_text", response_body={"content": content})

    def model_step(self, chat_fn: Callable[..., Any], **kwargs: Any) -> Any:
        """Count one model decision, with timeouts and exceptions logged separately."""
        if self.submitted:
            self._log("model_decision", arguments={"count": self.decision_count}, error="ALREADY_SUBMITTED")
            raise RuntimeError("Finding already submitted")
        if self.decision_count >= MAX_DECISIONS:
            self._log("model_decision", arguments={"count": self.decision_count}, error="DECISION_LIMIT")
            raise RuntimeError("Model decision limit reached")
        self.decision_count += 1
        start = time.perf_counter()
        try:
            response = chat_fn(**kwargs)
        except Exception as error:
            kind = type(error).__name__.lower()
            message = str(error).lower()
            if "timeout" in kind or "timed out" in message:
                code = "MODEL_TIMEOUT"
            elif kind == "importerror":
                code = "MODEL_SDK_MISSING"
            elif "connection" in kind or "connect" in kind or "connection refused" in message:
                code = "MODEL_SERVICE_UNAVAILABLE"
            elif kind == "modeldigestmismatcherror":
                code = "MODEL_VERSION_MISMATCH"
            elif kind == "modelnotfounderror":
                code = "MODEL_NOT_INSTALLED"
            elif any(hint in message for hint in ("out of memory", "requires more system memory", "context length", "context window")):
                code = "MODEL_RESOURCE_ERROR"
            else:
                code = "MODEL_EXCEPTION:" + type(error).__name__
            self.last_model_error_code = code
            self._log("model_decision", arguments={"count": self.decision_count},
                      elapsed_ms=(time.perf_counter() - start) * 1000, error=code)
            raise
        self._log("model_decision", arguments={"count": self.decision_count},
                  elapsed_ms=(time.perf_counter() - start) * 1000)
        return response
