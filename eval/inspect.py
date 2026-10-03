"""Show one real run's requests and separate verdict/evidence grades."""

import argparse
import json
from pathlib import Path


def inspect(root: str | Path, run_id: str) -> dict:
    rows = [json.loads(line) for line in (Path(root) / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    matches = [row for row in rows if row["run_id"] == run_id]
    if len(matches) != 1:
        raise ValueError("The run ID must occur exactly once in this result directory")
    row = matches[0]
    trace = [json.loads(line) for line in Path(row["log_path"]).read_text(encoding="utf-8").splitlines()]
    requests = [{key: event.get(key) for key in
                 ("request_id", "identity", "arguments", "response_status", "response_body", "error")}
                for event in trace if event["tool_name"] == "send_request"]
    return {"case_id": row["case_id"], "agent_name": row["agent_name"],
            "repeat_index": row["repeat_index"], "run_id": run_id,
            "requests": requests, "finding": row["finding"], "grade": row["grade"]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect the actual requests behind one scored finding")
    parser.add_argument("--input", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.input, args.run_id), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
