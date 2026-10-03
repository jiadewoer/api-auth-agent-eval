# API 授权核验 Agent：受控合成实验

这是一个在本地 FastAPI 靶场上评测授权核验 Agent 的研究型项目。工单与费用申请 API 都是自行构造的合成环境；每个任务有漏洞版和修复版。Agent 通过受限工具发起请求，独立评分器结合真实响应和状态变化，检查结论、证据顺序及 BOLA/BFLA 类型。

## 当前正式结果：V4-D3-R1

冻结提示后，在新的 12 对任务实例上评测四组条件，每个版本运行两次，共 192 条。12 对实例沿用此前的四类接口行为，因此不能当作 12 个独立应用或真实系统检出率。

| 条件 | 修复版明确判对 | 漏洞版类型与证据正确 | 同对两版均正确 | 运行错误 |
| --- | ---: | ---: | ---: | ---: |
| R0C0 | 1/24 | 1/24 | 0/24 | 42/48 |
| R1C0 | 24/24 | 8/24 | 8/24 | 0/48 |
| R0C1 | 2/24 | 2/24 | 0/24 | 43/48 |
| R1C1 | 24/24 | 22/24 | 22/24 | 0/48 |

`R` 是按顺序取证的提示，`C` 是漏洞类型归因提示。`R1C1` 尚有两次将 BFLA 报为 BOLA。错误运行均保留在分母内。完整方法、逐对结果、审计范围、哈希和局限见 [V4-D3-R1 实验报告](V4_D3_R1_Reserved_Experiment_Report.md)。本仓库同时提供[正式运行的汇总、清单、结果与逐条轨迹](results/tmp/v4-d3-r1-reserved-ollama-189927228c064652978406172978ba3a/)，共 192 条；未纳入每条运行的临时 SQLite 数据库。报告所审计的 manifest SHA-256 为 `2ab27433512d9f1cd68daf1371191e5f6422684e2ded82aa8d91b74d858d18da`，results SHA-256 为 `d73a0d9a10209e706a6ffab18a1a31d35912ce5f489575c6207449e5ddf116eb`。

## 目录

| 路径 | 内容 |
| --- | --- |
| `ticket_v3/`、`expense_app/` | 当前两套本地合成 API |
| `v4_lab/` | V4 四条件提示、受限工具、评分阶段、运行器 |
| `cases/v4_d3_reserved_*` | 新预留任务的公开规格和仅供评分的真值 |
| `tests/` | 授权行为、案例隔离、评分和运行流程测试 |
| `results/tmp/v4-d3-r1-reserved-ollama-*/` | 当前正式结果：清单、192 条结果、Agent 轨迹与阶段评分；其他本机结果仍被忽略 |
| `research/` | 实验协议、演进记录和旧阶段研究笔记 |
| `app/`、`agent/`、`eval/`、`followup*/`、`v3_agent/` | 旧实验及当前运行器依赖；请保留源码 |
| `report.md`、`summary.json`、`reports/` | **早期实验**的材料，并非上表 V4-D3-R1 的结果 |

真值 JSON 可用于独立复核，运行时不会发送给模型。公开这些预留案例后，未来实验须使用新的预留集。

## 本地验证

在项目根目录创建 Python 虚拟环境并安装依赖（Windows PowerShell）：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe -m pytest -q
```

`requirements.txt` 是最低依赖清单；`requirements.lock.txt` 记录当时使用的一组固定版本。Linux/macOS 把 Python 路径改为 `.venv/bin/python`。

不调用模型的确定性管线检查：

```powershell
.\.venv\Scripts\python.exe -m v4_lab.run_d3_reserved --provider stub --output results/tmp/v4-d3-stub-local
```

它会产生 192 条 **stub** 记录，只验证案例、日志和评分流程，不能当成模型成绩。使用一个全新的输出目录；同一目录再次运行会核对清单并跳过已保存的条目。正式模型运行需本机 Ollama 及 `qwen3:8b`，且代码会核验模型 digest 前缀；不同 digest 须作为新的实验配置记录，不能宣称逐字节复现上表。

除上述冻结的正式结果外，其他运行目录、数据库、虚拟环境、缓存和本机配置由 `.gitignore` 排除。项目中的 Bearer token 是虚构靶场身份标识，不能复用于真实服务。
