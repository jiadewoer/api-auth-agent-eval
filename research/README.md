# 研究版增量：先保证结论可信，再扩展案例

这份目录是加到原项目根目录的**研究协议和分析器**。它不修改已有 `app/`、`agent/`、`eval/`、`followup/`，也不篡改已经冻结的 32 次结果。它不是一篇完成的论文，更不意味着顶会录用。

## 当前作品的准确定位

已有作品是可复现的岗位作品与**单应用先导实验**：六对合成案例；P01、P04 开发，P02、P03、P05、P06 在第一次提示词实验中作保留案例；4 个独立保留对、2 次重复、1 个 Qwen 模型、1 个工单应用。第一次实验 32 条实际运行记录。后一轮 `followup/` 为 2×2 方法实现，**尚未得到真实模型结果**，其复用案例也不是新的盲测。

已有 `followup/gate.py` 按 `/tickets/201` 等具体路径识别受保护字段，`agent/tools.py` 允许的路由和身份也是为当前工单应用编写。因此当前实现**不能直接宣称跨应用方法**。新应用进入研究之前要把这两处改为任务合同驱动的适配器，且用从未调参的应用检验。

`research/audit.py` 核对案例登记、公开说明和内部真值之间的关系。`research/analyze.py` 拒绝缺失或重复的正反版本，以**应用、案例对、重复次数**三个层级计算，不能把 32 行说成 32 个独立问题。`pilot_analysis.json` 是用已经发生的旧实验重算得到的**事后诊断**，不用于显著性或新贡献主张。

## Windows PowerShell 从原项目运行

将 `research/` 目录与 `tests/test_research_protocol.py` 复制到项目根目录。在 `D:\projects\api-auth-agent-eval` 内：

```powershell
.\.venv\Scripts\python.exe -m research.audit
.\.venv\Scripts\python.exe -m pytest -q tests/test_research_protocol.py
.\.venv\Scripts\python.exe -m research.analyze --input results/tmp/formal-v3/results.jsonl --split pilot_formal --reference baseline --treatment evidence --output results/tmp/pilot_reanalysis.json
Get-Content -Encoding UTF8 .\results\tmp\pilot_reanalysis.json
```

如果旧正式结果在别的目录，替换 `--input` 的路径。`audit` 应输出 `applications: 1`、`independent_pairs: 6`（包含开发案例）；旧正式结果分析应输出 `independent_case_pairs: 4`、`attempted_runs: 32`、`status: pilot_descriptive_only`。代码不会为你自动生成第二个应用，也不会调用 Ollama。需要单独运行 `followup/README.md` 的命令才能采集第二轮数据。

## 看懂最重要的数

`attributable_pair_success` 在**同一案例对、同一次重复**同时要求：(1) 漏洞版结论正确、漏洞类型正确且引用的实际请求证据有效；(2) 修复版正确排除；(3) 两次均无技术失败。若只有漏洞版答对而引用不存在的请求，这对计 0。`fixed_false_positives` 另列；出错不能被当成“修复版正确”。

现有结果按这个事后终点是 A 0/8、B 1/8。这不是“B 被证明更好”，因为原实验没有预先把这个指标定为主终点，只有一个应用和四对保留案例，B 的技术失败更多；跨应用置信区间刻意返回 `null`。不要把 0/8 与 1/8 用于顶会结论。

## 后续研究的入口

按 [STUDY_PROTOCOL.md](STUDY_PROTOCOL.md) 设计**新应用和新案例**，完成审查后将其登记到 `research/registry.json`，并给新应用分别编写可重复重置、受控请求、真实状态 oracle 与测试。首先用两个新应用做工程迁移试验；冻结代码与指标后，再建设足以跨应用比较的正式数据。将来新 JSONL 仍用 `--input` 分析，同时把 `--split`、`--reference`、`--treatment` 换成研究清单中定义的值。

注意：如果将来只有三、四个应用，分析器仍会给描述性差异，但不会给跨应用区间；达到五个应用后给**探索性的**应用与案例对两层自助采样区间。是否足以支持论文主张，还需看任务的真实性、案例质量、效应稳定性与领域同行评审，不能凭应用数量自动判断。
