# 下一轮实验：工具协议 × 提交前证据检查

这是一项**新实验**，不覆盖原来的 32 条正式结果。原来的 `app/`、`agent/`、`cases/`、`eval/`、提示词、评分器、`summary.json` 都保持原样；只新增 `followup/` 和一份测试。`followup/run.py` 在开始前会核对 `summary.json` 保存的旧源码哈希，防止你不小心把两个实验版本混在一起。

## 一句话说明四组

两个开关各有“关/开”，组合成四组；**四组都使用原来的 `baseline.txt` 提示、同一 Qwen、相同任务、最多 8 个 API 请求和 16 次模型决策**。

| 组别 | T：模型看到的请求工具协议 | E：提交前证据检查 |
| --- | --- | --- |
| `T0E0` | 原始 `send_request` 说明 | 原始结构检查：请求 ID 存在即可提交 |
| `T1E0` | 明确要求 `json_body`；给出转派请求体示例 | 原始结构检查 |
| `T0E1` | 原始请求工具说明 | 提交时检查所引用的可见请求；不符则反馈问题并允许重试 |
| `T1E1` | 明确请求体说明 | 同一提交前证据检查 |

T1 **只改模型看到的 JSON 工具描述**，Python 后端仍调用同一个 `AgentTools.send_request`，真实路由、身份、预算不变。它专门针对上一轮 P05 漏传 `json_body` 的失败；我们要看实际 `INVALID_BODY` 是否减少，不能事先宣布会减少。

E1 **只改提交阶段**：检查模型引用的本轮请求是否包含 A 对目标接口的实际尝试、恰当身份的合法对照、读到的受保护字段；写类要求在 A 的 POST 前后有可见的合法 GET，且状态变化能归因于 A。失败会得到具体问题并可在剩余预算内重试或主动弃答。检查器不读 `truth.json`、`case_id`、评分器输出或 SQLite 内部状态；它不能把“有漏洞/已修复”告诉模型。E1 的反馈和重试可能**增加**模型决策、请求、耗时甚至失败数，这些都必须报告。

## 怎么理解“两个实验变量”

当 E 固定为 E0，比较 `T1E0` 与 `T0E0`，看到的是改变请求工具描述后的结果。当 T 固定为 T0，比较 `T0E1` 与 `T0E0`，看到的是加入提交检查后的结果。`T1E1` 用来看两项改动一起出现时有没有额外影响。各组对相同案例的正反版本各跑相同次数，执行顺序在案例之间轮转；不是把旧 A/B 成绩拿来和新实验混比。

这里的 T 是**工具参数说明改良**，不是放宽工具权限；E 是**程序反馈介入**，不是第二个大模型裁判。两者影响的代码路径不同。提示词始终取 `agent/prompts/baseline.txt`。

### 预先写下要看的指标

1. T 是否减少 `INVALID_BODY`、`INVALID_ARGUMENTS`，尤其是 P05；同时看是否引入新的工具错误。
2. E 是否减少修复版误报、提高“结论正确且证据有效”，同时看检出、主动证据不足与未提交是否恶化。
3. 每组单列 `run_error` 和分类错误；不要把“没提交”当成修复版答对。
4. 比较每组平均 API 请求、模型决策数与耗时。请求越多可能意味着介入有成本。
5. 成对正确要求同一对的漏洞版、修复版在同一次重复都答对。只报告观察值，不以 64 次运行冒充 64 个独立案例。

一个例子：P02 修复版 A 请求评论返回 `403`，模型却提交 `vulnerable`。E1 会检查它引用的 A 请求，不接受“B 读到了评论，所以 A 也读到了”这种论证，并返回 `A_did_not_show_matching_protected_content`。模型若改报 `not_vulnerable` 且引用 B 的合法 GET 与 A 的被拒 GET，提交可被接受。**这不是读取隐藏真值**；两次响应本来就在模型工具结果中。

写操作例子：B 已先把工单关闭，A 再 POST 得到 `200`，但工单从 `closed` 到 `closed`。E1 不会仅凭这个 `200` 接受“确认越权”；它要求在 A 请求前后看到可归因于 A 的 `open → closed`。E1 的程序只看可见 GET 快照；最终评分器仍独立用请求对应的真实数据库状态判分。

## 在你的 Windows 笔记本执行

把本文件所在的整个 `followup/` 目录和 `tests/test_followup.py` 放到原项目根目录；**不要替换原来的 `agent/`、`eval/`、`summary.json`**。在 PowerShell 中进入项目目录：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
ollama list
Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/version'
```

第一条应比原先的 135 个测试多 6 个；若失败，先检查文件有没有放错位置。Ollama 需要原模型摘要前缀 `0edcdef34593`，否则运行器会按原设置拒绝继续；不要默默换模型后和旧实验直接比较。

**先在开发案例 P01/P04 小规模试跑**（4 个场景 × 4 组 = 16 次）：

```powershell
.\.venv\Scripts\python.exe -m followup.run --split dev --repeats 1 --output results/tmp/followup-dev-01
.\.venv\Scripts\python.exe -m followup.summarize --input results/tmp/followup-dev-01 --output results/tmp/followup-dev-01/summary.json
Get-Content -Encoding UTF8 .\results\tmp\followup-dev-01\summary.json
```

看 `results.jsonl` 每一行的 `case_id`、`condition`、`status`、`finding`、`grade`、`gate_rejections`。`gate_rejections` 是 E1 拒绝过多少次不充分的提交，**不是漏洞数**。若开发运行中模型服务中断，保留现有目录，排查服务后再决定是否从新目录重做；不要按成绩筛选重跑。

**再做旧案例复用诊断**。P02/P03/P05/P06 之前已经被我们看过，因此此处名为 `reused`，不再声称是新的盲测或真正未见过的保留集。第一轮 8 个场景 × 4 组 = 32 次；第二轮续跑新增 32 次，共 64 次。这些在 RTX 4060 上顺序执行，不会并发加载四个模型。

```powershell
.\.venv\Scripts\python.exe -m followup.run --split reused --repeats 1 --planned-repeats 2 --output results/tmp/followup-reused-01
.\.venv\Scripts\python.exe -m followup.run --split reused --repeats 2 --planned-repeats 2 --output results/tmp/followup-reused-01
.\.venv\Scripts\python.exe -m followup.summarize --input results/tmp/followup-reused-01 --output results/tmp/followup-reused-01/summary.json
```

第二条命令会跳过已有 `(case_id, condition, repeat_index)`，包括失败记录；输出应显示 `new_rows: 32`、`skipped: 32`。如果某次出现模型服务或资源系统故障，运行器会记录后中止，不能为了好看只补跑失败组。四组必须在相同模型、代码、提示、工具权限和预算下完整重做，或明确报告缺失。

**想回答这次实验是否有效，就先看** `summary.json` 的每组检出、误报、正确且有证据、成对正确、错误类别和平均成本，再逐条看 `runs/agent_<run_id>.jsonl`。模型决定了什么、工具实际返回什么、E1 是否拒绝、模型是否修正，必须能连到同一个 `run_id`。`truth.json` 只由 `eval.grade` 判分读取；不能拿真值写进提示或反馈。

## 哪些文件是这个增量新增的

`followup/conditions.py` 生成 T0/T1 的工具说明；`followup/gate.py` 在 E1 检查可见证据；`followup/runner.py` 管单次模型循环；`followup/run.py` 按四组顺序记录、续跑和保存新清单；`followup/summarize.py` 核对完整性并输出分项指标；`tests/test_followup.py` 用假模型检查机制，不把假模型测试结果当真实 Qwen 成绩。

这份增量只能建立一个**复用案例上的机制诊断**。若要形成能推广的研究结论，下一步需要预先设计新的案例对，最好来自另一个独立小应用；在看任何新模型输出之前冻结变量与判分，再做真正未见过的评测。
