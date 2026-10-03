"""V4 development tools, isolated from the frozen V3 protocol and gate."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping

from pydantic import ValidationError

from agent.finding import Finding
from v3_agent.tools import TOOL_SCHEMAS, V3Tools, _redact
from v4_lab.gate import evidence_issues
from v4_lab.protocol import (MAX_BODY_BYTES, MAX_REQUESTS, bearer_for, public_api_for,
                             route_match, valid_body, write_target)


class V4Tools(V3Tools):
    """Reuse V3 log/dispatch mechanics while keeping V4 routes and truth separate."""

    def __init__(self, client: Any, *, app_id: str, public: Mapping[str, Any],
                 db_path: str | Path, log_path: str | Path, run_id: str,
                 evidence_gate: bool = True) -> None:
        if app_id not in {"ticket_lab_v4", "expense_lab_v4"}:
            raise ValueError("Unknown V4 app")
        super().__init__(client, app_id="ticket_lab_v3" if app_id == "ticket_lab_v4"
                         else "expense_lab_v1", public=public, db_path=db_path,
                         log_path=log_path, run_id=run_id, evidence_gate=evidence_gate)
        self.app_id = app_id

    def _private_field(self, target: tuple[str, int, str]) -> Any:
        table, object_id, field = target
        if (table, field) not in {("tickets", "priority"), ("claims", "cost_center"),
                                  ("claims", "review_state")}:
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
        if not route_match(self.app_id, method, path):
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
                method, path, headers={"Authorization": "Bearer " + bearer_for(self.app_id, identity)},
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
            issues = evidence_issues(self.public, finding, self._requests)
            if issues:
                self.gate_rejections += 1
                self._log("evidence_gate", arguments={"request_ids": finding.evidence_request_ids},
                          response_body={"issues": issues}, error="EVIDENCE_CHECK_FAILED")
                return {"error": {"code": "EVIDENCE_CHECK_FAILED", "issues": issues}}
            self._log("evidence_gate", arguments={"request_ids": finding.evidence_request_ids},
                      response_body={"accepted": True})
        self.finding = _redact(finding.model_dump(mode="json"))
        self.submitted = True
        self._log("submit_finding", arguments=arguments, response_body={"accepted": True})
        return {"accepted": True}


__all__ = ["TOOL_SCHEMAS", "V4Tools"]
