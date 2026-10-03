"""Run only the two V3 development pairs; stub validates plumbing, Ollama tests model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from v3_agent.grade import grade_run
from v3_agent.protocol import read_control, resource_for
from v3_agent.runner import run_case


DEV_CASE_IDS = ("T01_fixed", "T01_vuln", "E01_fixed", "E01_vuln")


def _native(name: str, arguments: dict) -> Any:
    return SimpleNamespace(message=SimpleNamespace(
        content="", tool_calls=[SimpleNamespace(function=SimpleNamespace(
            name=name, arguments=arguments))]
    ))


def deterministic_stub(*, messages: list, **_kwargs: Any) -> Any:
    """A deterministic driver, not an LLM; it receives only the public messages."""
    public = json.loads(messages[1]["content"])
    output = [(msg["tool_name"], json.loads(msg["content"])) for msg in messages
              if isinstance(msg, dict) and msg.get("role") == "tool"]
    method, path = public["target_method"], public["target_path"]
    legal, control_path = read_control(public) if method == "POST" else ("B", path)
    if not output:
        return _native("read_api_spec", {})
    requests = [row for name, row in output if name == "send_request" and "error" not in row]
    if not requests:
        return _native("send_request", {"identity": legal, "method": "GET", "path": control_path,
                                        "json_body": None})
    if len(requests) == 1:
        return _native("send_request", {"identity": "A", "method": method,
                                        "path": path, "json_body": public["request_body"]})
    if method == "POST" and len(requests) == 2:
        return _native("send_request", {"identity": legal, "method": "GET", "path": control_path,
                                        "json_body": None})
    candidate = requests[1]
    if method == "POST":
        field = public["target_object"]["field"]
        before, after = requests[0]["body"][field], requests[2]["body"][field]
        supported = (candidate["status_code"] == 200 and before != after)
        denied = (candidate["status_code"] == 403 and before == after)
    else:
        supported = candidate["status_code"] == 200 and bool(candidate["body"])
        denied = candidate["status_code"] == 403
    verdict = "vulnerable" if supported else "not_vulnerable" if denied else "insufficient_evidence"
    kind = ("BFLA" if path.endswith("/approve") else "BOLA") if verdict == "vulnerable" else None
    return _native("submit_finding", {
        "verdict": verdict, "vulnerability_type": kind,
        "identity": "A", "resource": resource_for(public),
        "evidence_request_ids": [result["request_id"] for result in requests],
        "explanation": "Deterministic development harness checked the observed HTTP sequence.",
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("stub", "ollama"), required=True)
    parser.add_argument("--case-id", choices=DEV_CASE_IDS, help="Default: all four development versions")
    parser.add_argument("--output", default="results/tmp/v3-stage4-dev")
    args = parser.parse_args()
    root = Path(args.output)
    cases = (args.case_id,) if args.case_id else DEV_CASE_IDS
    if args.provider == "ollama":
        from v3_agent.model_client import local_chat  # V3 model and digest are isolated from V2.
        chat_fn, runtime = local_chat()
        runtime["provider"] = "ollama"
    else:
        chat_fn, runtime = deterministic_stub, {"provider": "deterministic_stub"}
    rows: list[dict] = []
    for case_id in cases:
        record = run_case(case_id, chat_fn, root, runtime=runtime)
        trace = [json.loads(line) for line in Path(record["log_path"]).read_text(encoding="utf-8").splitlines()]
        grade = grade_run(record, trace)
        grade_path = root / f"grade_{record['run_id']}.json"
        grade_path.write_text(json.dumps(grade, ensure_ascii=False, indent=2), encoding="utf-8")
        rows.append({"case_id": case_id, "run_id": record["run_id"],
                     "status": record["status"], "run_error": record["run_error"],
                     "verdict": (record.get("finding") or {}).get("verdict"),
                     "verdict_correct": grade["verdict_correct"],
                     "evidence_valid": grade["evidence_valid"],
                     "api_requests": record["api_requests"],
                     "trace_path": record["log_path"], "grade_path": str(grade_path)})
    errors = sum(row["status"] == "run_error" for row in rows)
    print(json.dumps({"provider": args.provider, "dev_only": True,
                      "ok": errors == 0, "run_errors": errors, "rows": rows},
                     ensure_ascii=False, indent=2))
    if errors:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
