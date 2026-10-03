"""Require all 32 independent run records, then calculate transparent counts."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from statistics import mean

from eval.manifest import manifest_template


AGENTS = ("baseline", "evidence")


def _rows(root: Path) -> tuple[dict, list[dict]]:
    manifest = json.loads((root / "experiment_manifest.json").read_text(encoding="utf-8"))
    frozen = manifest_template()
    for field in ("agents", "model_tag", "model_digest_prefix", "temperature",
                  "num_ctx", "tool_spec_sha256", "request_limit", "decision_limit",
                  "grader_version", "cases", "source_sha256"):
        if manifest.get(field) != frozen[field]:
            raise ValueError(f"Frozen experiment changed: {field}")
    if manifest["selected_split"] != "holdout" or manifest["runs_per_case"] != 2:
        raise ValueError("Expected holdout with two planned repeats")
    rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    cases = frozen["cases"]["holdout"]
    expected = {(case_id, agent, repetition)
                for case_id in cases for agent in AGENTS for repetition in range(2)}
    keys = [(r["case_id"], r["agent_name"], r["repeat_index"]) for r in rows]
    if len(rows) != 32 or len(set(keys)) != 32 or set(keys) != expected:
        missing, extra = sorted(expected - set(keys)), sorted(set(keys) - expected)
        raise ValueError(f"Expected 32 unique holdout rows; missing={missing}, extra={extra}")
    seen_runs: set[str] = set()
    seen_databases: set[str] = set()
    for r in rows:
        if r["run_id"] is None:
            # Explicit runner failure remains in the denominator and is visible.
            if r["status"] != "run_error" or r.get("run_error") is None:
                raise ValueError("Missing run ID without explicit technical failure")
            continue
        run_id, db = r["run_id"], r["db_path"]
        if run_id in seen_runs or db in seen_databases:
            raise ValueError("A run_id or SQLite database was reused")
        seen_runs.add(run_id)
        seen_databases.add(db)
        for field in ("log_path", "db_path", "result_path"):
            if not r.get(field) or not Path(r[field]).exists():
                raise ValueError(f"Missing {field} for {run_id}")
        raw = json.loads(Path(r["result_path"]).read_text(encoding="utf-8"))
        if any(raw[k] != r[k] for k in ("run_id", "case_id", "agent_name")):
            raise ValueError(f"Original finding belongs to a different run: {run_id}")
        if raw["finding"] != r["finding"]:
            raise ValueError(f"Finding does not match original run: {run_id}")
        trace = [json.loads(line) for line in Path(r["log_path"]).read_text(encoding="utf-8").splitlines()]
        if any(t["run_id"] != run_id for t in trace):
            raise ValueError(f"Mixed request trace: {run_id}")
        if len({t["step"] for t in trace}) != len(trace):
            raise ValueError(f"Repeated trace step: {run_id}")
        if raw["config"]["prompt_sha256"] != manifest["agents"][r["agent_name"]]["prompt_sha256"]:
            raise ValueError(f"Wrong prompt hash for {run_id}")
        if r["status"] == "graded" and (not isinstance(r.get("grade"), dict)
                                           or r["grade"].get("run_error")):
            raise ValueError(f"Invalid grade record: {run_id}")
    return manifest, rows


def summarize(root: str | Path) -> dict:
    manifest, rows = _rows(Path(root))
    output = {"total_rows": len(rows), "independent_holdout_pairs": 4,
              "paired_observations_per_agent": 8,
              "manifest": manifest, "agents": {}}
    for agent in AGENTS:
        subset = [r for r in rows if r["agent_name"] == agent]
        positives = [r for r in subset if r["case_id"].endswith("_vuln")]
        negatives = [r for r in subset if r["case_id"].endswith("_fixed")]
        reports = [r for r in subset if (r.get("finding") or {}).get("verdict") == "vulnerable"
                   and r["status"] == "graded"]
        paired = sum(
            all((next(r for r in subset if r["case_id"] == f"{pair}_{variant}"
                      and r["repeat_index"] == repetition).get("grade") or {}).get("verdict_correct") is True
                for variant in ("vuln", "fixed"))
            for pair in ("P02", "P03", "P05", "P06") for repetition in range(2)
        )
        grades = [(r.get("grade") or {}) for r in subset]
        errors = Counter((r.get("run_error") or {}).get("category") for r in subset
                         if r["status"] == "run_error")
        observed_request_count = sum(g.get("api_requests", 0) for g in grades)
        metrics = {
            "vulnerability_detected": [sum(r["grade"]["verdict_correct"] is True
                                           for r in positives if r.get("grade")), 8],
            "fixed_false_positives": [sum(r["grade"].get("false_positive", False)
                                          for r in negatives if r.get("grade")), 8],
            "valid_evidence_among_vulnerability_reports": [
                sum(r["grade"]["evidence_valid"] is True for r in reports), len(reports)],
            "paired_correct": [paired, 8],
            "abstentions": [sum(g.get("abstained", False) for g in grades), 16],
            "run_errors": [sum(r["status"] == "run_error" for r in subset), 16],
            "run_error_categories": dict(errors),
            "false_negatives": sum(g.get("false_negative", False) for g in grades),
            "classification_errors": sum(g.get("classification_error", False) for g in grades),
            "correct_verdict_invalid_evidence": sum(g.get("verdict_correct") is True
                                                    and not g.get("evidence_valid") for g in grades),
            "mean_api_requests_all_runs": round(observed_request_count / 16, 3),
            "mean_duration_s_recorded_runs": round(mean(g.get("duration_s", 0)
                for g in grades if "duration_s" in g), 3) if any("duration_s" in g for g in grades) else None,
            "duration_n": sum("duration_s" in g for g in grades),
        }
        output["agents"][agent] = metrics
    return output


def markdown(summary: dict, root: str | Path) -> str:
    def cell(agent: str, key: str) -> str:
        item = summary["agents"][agent][key]
        return f"{item[0]}/{item[1]}" if isinstance(item, list) else str(item)

    pairs = [
        ("漏洞版正确检出", "vulnerability_detected"),
        ("修复版误报", "fixed_false_positives"),
        ("漏洞报告中的有效证据", "valid_evidence_among_vulnerability_reports"),
        ("成对正确", "paired_correct"),
        ("主动证据不足", "abstentions"),
        ("技术失败", "run_errors"),
        ("平均 API 请求数（16 次）", "mean_api_requests_all_runs"),
        ("平均耗时（仅有记录）", "mean_duration_s_recorded_runs"),
    ]
    lines = ["# 权限核验 Agent 对照实验报告", "", "## 研究问题", "",
             "同一 Qwen 本地模型、相同工具和请求预算下，增加提交前的证据核对提示是否改变误报和调查成本？", "",
             "## 威胁模型", "", "测试者只可用 A/B/M 虚构身份调用允许的本地路由；模型只看公开任务与工具响应。真实标签和状态快照只由评分器读取。", "",
             "## 案例设计与真值", "", "六对合成案例中 P01/P04 用于开发，P02/P03/P05/P06 用于正式评测。每对只有一处授权检查不同；读类用受保护字段，写类用数据库状态前后差异。", "",
             "## 模型、工具与硬件", "", f"模型：`{summary['manifest']['model_tag']}`；实际摘要：`{summary['manifest']['actual_model_digest']}`；温度：`{summary['manifest']['temperature']}`；上下文：`{summary['manifest']['num_ctx']}`。", "", "硬件请填写本机实测显存、CPU、RAM、系统和功耗；本文件无法从远程推断。", "",
             "## A/B 变量", "", "A 使用 baseline.txt，B 使用 evidence_check.txt；后者额外提醒核对身份、合法对照、实际内容和写入状态。", "",
             "## 预定指标", "", "结论正确与证据有效分别计数；同时记录误报、漏报、弃答、技术失败、请求数、耗时与成对正确。", "",
             "## 结果表", "", "| 指标 | A：普通调查 | B：证据核对 |", "| --- | ---: | ---: |"]
    lines.extend(f"| {label} | {cell('baseline', key)} | {cell('evidence', key)} |" for label, key in pairs)
    for agent in AGENTS:
        m = summary["agents"][agent]
        lines += ["", f"{agent} 技术失败分类：`{m['run_error_categories']}`；平均耗时仅有 {m['duration_n']}/16 条可用。"]
    lines += ["", "## 代表性轨迹（人工分析）", "",
              "从 results.jsonl 中选正确发现、正确排除、误报、漏报或弃答各一条（不存在某类时明确写无），逐一填入真实 run_id、请求 ID、观察、结论和判分原因。不要把不存在的轨迹编出来。", "",
              "## 局限和改进", "",
              "只有一个自建工单应用、六对合成案例，正式只有四个独立案例对；已知候选接口，单个本地模型。重复两轮不产生新应用或新案例，也不能代表真实企业系统或所有越权漏洞。", "",
              "如果你已看过保留集代码或答案，请注明：这里的 holdout 仅表示没有拿来调 Agent 提示，不是研究者从未见过的盲测。", "",
              f"结果目录：`{root}`。上表由汇总器从完整 32 条记录计算。", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Strictly validate and summarize 32 formal runs")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", help="Directory for summary.json and report.md; defaults to --input")
    args = parser.parse_args()
    summary = summarize(args.input)
    root = Path(args.output or args.input)
    root.mkdir(parents=True, exist_ok=True)
    (root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "report.md").write_text(markdown(summary, args.input), encoding="utf-8")
    print(json.dumps({"checked_rows": 32, "summary": str(root / "summary.json"),
                      "report": str(root / "report.md")}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
