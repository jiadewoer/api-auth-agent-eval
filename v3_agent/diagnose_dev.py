"""Inspect failed development tool calls without opening hidden truth or SQLite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def diagnose(directory: str | Path) -> dict:
    folder = Path(directory)
    records = sorted(folder.glob("agent_*.json"))
    if not records:
        raise FileNotFoundError(f"No agent_*.json result records in {folder}")
    cases: list[dict] = []
    for path in records:
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["status"] != "run_error":
            continue
        trace_path = Path(record["log_path"])
        if not trace_path.is_absolute() and not trace_path.exists():
            trace_path = folder / trace_path.name
        events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
        errors = [
            {"step": event["step"], "tool_name": event["tool_name"],
             "arguments": event["arguments"], "error": event["error"]}
            for event in events if event.get("error") and event["tool_name"] != "run_error"
        ]
        cases.append({"case_id": record["case_id"], "run_id": record["run_id"],
                      "api_requests": record["api_requests"],
                      "run_error": record["run_error"], "first_failed_call": errors[0] if errors else None})
    return {"input": str(folder), "total_records": len(records),
            "run_error_count": len(cases), "failures": cases}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="A V3 development output directory")
    args = parser.parse_args()
    print(json.dumps(diagnose(args.input), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
