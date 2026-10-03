# V4 阶段二：四条件开发运行器

状态：**开发实验可运行；未冻结、未生成或运行 V4 预留案例。** 旧 V3-E1 归档仅作事后诊断。新四对 T05/T06/E05/E06 是公开的开发案例，不计入未来未见评估。

## 因子与共同设置

| 条件 | 显式取证顺序 R | 通用类别定义 C |
|---|---|---|
| R0C0 | 无 | 无 |
| R1C0 | 有 | 无 |
| R0C1 | 无 | 有 |
| R1C1 | 有 | 有 |

`v4_lab/prompts.py` 从 `base.txt`、`order.txt`、`types.txt` 机械拼接，并在 `dev_manifest.py` 校验四条件差异。公共任务、工具、证据门、模型、温度、上下文、请求上限、决策上限和错误恢复规则一致。开发起点采用 `qwen3:8b`、温度 0.2、上下文 4096、最多 8 次实际 API 请求与 16 次模型决策；模型摘要由本机 Ollama 检查并记录。C 段只描述可见的 BOLA/BFLA 一般区别，没有具体案例答案。

V4 工具仅允许新应用的公开 GET/POST 路由。每条运行拥有独立 SQLite、对话与轨迹；模型只看到公共案例、工具反馈，不读取 `cases/v4_dev_truth.json` 或写入快照。证据门要求同一合法身份前读、A 目标写入、后读的请求编号，并拒绝其间对同一字段的其他 POST；独立的 `v4_lab/stages.py` 在报告后按私有真值标 S1–S4。**证据门不判 BOLA/BFLA**，所以类型错误可以在 S3 通过后独立落在 S4。

## 运行纪律

在项目根目录，先用全新目录跑确定性脚本；再用另一个全新目录跑真实 Ollama。两者绝不能混入一个目录，也不能复用 V3 的任何结果目录：

```powershell
$stubDir = 'results\tmp\v4-dev-stub-' + [guid]::NewGuid().ToString('N')
& .\.venv\Scripts\python.exe -m v4_lab.run_ab_dev --provider stub --output $stubDir

$modelDir = 'results\tmp\v4-dev-ollama-' + [guid]::NewGuid().ToString('N')
& .\.venv\Scripts\python.exe -m v4_lab.run_ab_dev --provider ollama --output $modelDir
```

真实模型如有运行错误，命令返回 2，但仍保留所有 32 个开发计划键的原始记录和阶段评分。相同命令再次对**同一目录**执行时仅跳过已保存的键；配置、源码或依赖发生变化则拒绝继续，须另起配置与结果目录。`results.jsonl` 中的失败行不能选择性覆盖。`experiment_manifest.json` 保存公共/私有源码、提示、预算、依赖和模型配置的 SHA-256；每条运行另存 agent JSON、JSONL、SQLite 与阶段 JSON。

确定性驱动在本隔离环境里完成 32/32、无运行错误，所有四条件各 4 条漏洞版均达到 S4；它根据公开政策执行固定脚本，只验证机制接线，不构成模型检测性能证据。真实 Qwen 结果必须从用户机器新目录产生。之后应检查四组各自的 S1–S4、修复版误报、工具/模型失败，决定是否需一次明确记录的**开发阶段**修订。

## 预留集仍未就绪

下一阶段要独立设计、核验至少 12 对新预留写入案例；审核权限边界、公共可见性、固定版行为与私有真值，并预先锁定四条件提示和排程。不能把本次 32 条开发记录或 V3-E1 的已见案例重命名为 V4 预留结果。
