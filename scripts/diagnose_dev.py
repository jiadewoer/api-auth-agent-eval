"""Explain dev run errors from persisted JSONL without reading hidden truth."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def diagnose(output_dir: str | Path) -> list[dict]:
    root = Path(output_dir)
    rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    explanations = []
    for row in rows:
        log_path = row.get("log_path")
        events = ([json.loads(line) for line in Path(log_path).read_text(encoding="utf-8").splitlines()]
                  if log_path and Path(log_path).exists() else [])
        errors = [{"tool": e["tool_name"], "code": e["error"],
                   "arguments": e.get("arguments")}
                  for e in events if e.get("error") and e["tool_name"] != "run_error"]
        explanations.append({
            "case_id": row["case_id"], "agent": row["agent_name"],
            "run_id": row.get("run_id"), "status": row["status"],
            "run_error": row.get("run_error"),
            "api_requests": (row.get("grade") or {}).get("api_requests"),
            "model_decisions": sum(e["tool_name"] == "model_decision" for e in events),
            "failing_calls": errors,
            "last_tool_names": [e["tool_name"] for e in events[-5:]],
        })
    return explanations


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect dev run failures and invalid tool arguments")
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    print(json.dumps(diagnose(args.input), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
