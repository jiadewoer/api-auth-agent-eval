# 开发集协议修复 v2：先理解，再运行

本目录是**新增模块**，不替换 `followup/` 或任何旧结果。你已经跑过的 `followup-dev-01` 和 `followup-dev-v2` 都属于旧代码产生的记录；一个目录叫 v2 不代表代码已变。本模块运行时会写 `experiment: followup-v2-text-adapter`，源码哈希进入新 manifest，旧实验仍可用旧汇总器查看。

## 为什么改

在 `P01_vuln / T1E0` 的真实日志里，模型反复输出 `{"name":"submit_finding","arguments":{...}}`，但那是 `model_text`，不是 Ollama `tool_calls`；旧 runner 只提醒重试，最终用尽 16 次决策。`P01_fixed / T0E1` 则多次被证据门拒绝同一漏洞主张。还有一次模型服务中断，属于独立系统故障，不是这两个协议问题。

## 每个文件的责任

- `text_tool.py`：只解析**整段恰好一个** `{"name": ..., "arguments": {...}}` JSON。代码块、前后说明、多个 JSON、超大内容不解析；解析不等于授权。
- `runner.py`：原生 `tool_calls` 沿用原流程。若没有原生调用但有合法文本信封，仍由原来的 `AgentTools.dispatch` 验证身份、方法、路径、参数及预算；工具观察以 user 消息回到模型，因为原 assistant 消息没有原生工具调用。记录 `model_text`、`text_tool_adapter` 和真正的工具事件。同一无效普通文本连续三次，或同一无根据的证据门提交连续三次，就明确记为运行失败；**绝不替模型编造结论**。
- `run.py`：四组仍共享相同的 v2 适配器、原 baseline 提示、同一 T/E 变动、8 次 API 请求与 16 次决策。每次重建 DB 和消息。新 manifest 固定 v2 源码，不能与 v1 结果混用。
- `summarize.py`：只汇总完整且与当前 v2 源码哈希一致的目录，技术失败单列。
- `tests/test_followup_v2.py`：用假模型验证真实路由请求、工具白名单、证据门、循环失败分类与完整 16 格记录。假模型测试不是 Qwen 实验成绩。

## Windows PowerShell 安装

从本增量包中只复制 `followup_v2/` 和 `tests/test_followup_v2.py` 到项目根目录。先检查目标不存在；不要解压全量旧项目覆盖你现有文件：

```powershell
Set-Location 'D:\projects\api-auth-agent-eval'
Test-Path .\followup_v2
Test-Path .\tests\test_followup_v2.py
git status --short
```

若前两项均为 `False`，解压增量包到临时目录，再复制这两项。复制后：

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_followup_v2.py
.\.venv\Scripts\python.exe -m pytest -q
Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/version'
.\.venv\Scripts\python.exe -c "from ollama import Client; c=Client(host='http://127.0.0.1:11434',trust_env=False,timeout=60); print(c.chat(model='qwen3:4b-instruct', messages=[{'role':'user','content':'只回答 OK'}]).message.content)"
```

只在以上四项都通过后，使用一个**新的空目录**运行 16 条开发场景：

```powershell
.\.venv\Scripts\python.exe -m followup_v2.run --split dev --repeats 1 --output results/tmp/protocol-v2-dev-01
.\.venv\Scripts\python.exe -m followup_v2.summarize --input results/tmp/protocol-v2-dev-01 --output results/tmp/protocol-v2-dev-01/summary.json
Get-Content -Encoding UTF8 .\results\tmp\protocol-v2-dev-01\summary.json
```

如果出现 `MODEL_SERVICE_UNAVAILABLE` 等系统故障，运行器会先记录该条再中止；保留该目录作为故障证据。不要只补跑剩余条件并声称这一批是干净对照。恢复服务后另用空目录完整跑四组。

## 自己验收三件事

1. 在一个 `text_tool_adapter` 事件前能找到原始 `model_text`；它后面能找到真正的 `send_request` 或 `submit_finding` 事件。仅写了 JSON 而没有真实工具事件，不算调用成功。
2. `UNKNOWN_TOOL`、`INVALID_ARGUMENTS` 或 `REPEATED_UNPARSED_TEXT` 是失败，不应变成 `not_vulnerable`。E1 的重复拒绝记录为 `REPEATED_EVIDENCE_REJECTION`，也不是正确排除。
3. 四组所有新运行必须来自这次 v2 目录，不能把旧 `followup-dev-01` 的好成绩拼进来。先看技术失败、误报与有效证据，再讨论请求次数和耗时。**这只是开发集调试，不是新的保留集研究结论。**

### 面试怎么解释这次改动

“我发现模型会把工具调用序列化为普通文本，原 runner 不执行它，造成 `NO_CONCLUSION`。我新增了只接受完整 JSON 信封的适配器，再走原来的工具白名单和参数验证；还把重复无效提交明确分类为失败。两个版本的结果分别保存，避免把工程修复误报为模型能力提升。”
