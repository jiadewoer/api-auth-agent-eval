# V3 第一周动手课：从一次 `200` 到可归因的证据

先把本目录的三个文件放入你项目的 `research/`，再按顺序执行。你不需要现在编写第二个应用或跑新的 Ollama 实验。本周完成的是：**复现问题、写定研究问题与比较规则、保存验收记录**。

## 0. 进度在哪里

| 已经完成 | 本周交付 | 下一步 |
| --- | --- | --- |
| 工单 API、六对正反案例、受限 Agent、评分器和 `followup_v2` 四条件机制诊断 | V3 写入顺序协议、P03/P05 的干净与污染顺序复现、讲解与记录 | 第二周搭建独立费用申请 API；之后才有新评估数据 |

编制本包时，你上传的项目 ZIP 解压副本跑出了 **155 passed**，`research.audit` 报告 `applications: 1`、`independent_pairs: 6`。这验证了**上传副本**；若你上传后又在 D 盘修改过项目，仍需按下方命令再验一次。旧 V2 的 16 条开发、32 条复用记录不是新应用的正式实验。

## 1. 安全地放进你 Windows 项目

下载 `V3_Week1_Research_Package.zip` 到 `C:\Users\<username>\Downloads`（如果浏览器给了别的文件名，改下面 `$zip`）。**不要解压覆盖现有 `research/`**。在 PowerShell 一口气执行下列代码：

```powershell
Set-Location -LiteralPath 'D:\projects\api-auth-agent-eval' -ErrorAction Stop
$python = '.\.venv\Scripts\python.exe'
$zip = 'C:\Users\<username>\Downloads\V3_Week1_Research_Package.zip'

if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { throw "ZIP 不存在：$zip" }
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw '虚拟环境 Python 不存在' }
if (-not (Test-Path .\followup_v2\run.py)) { throw '当前目录不是包含 followup_v2 的项目根目录' }

$names = @('WRITE_ORDER_V3_PROTOCOL.md', 'WEEK1_V3_WALKTHROUGH.md',
           'V3_WEEKLY_LOG.md', 'replay_write_preemption.py')
foreach ($name in $names) {
    if (Test-Path -LiteralPath (Join-Path .\research $name)) {
        throw "目标文件已存在，先人工核对：$name"
    }
}

$stage = Join-Path $env:TEMP ('auth-v3-week1-' + [guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $zip -DestinationPath $stage -ErrorAction Stop
foreach ($name in $names) {
    $src = Join-Path (Join-Path $stage 'research') $name
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
        throw "ZIP 缺少：$name"
    }
}
New-Item -ItemType Directory -Path .\research -Force | Out-Null
foreach ($name in $names) {
    Copy-Item -LiteralPath (Join-Path (Join-Path $stage 'research') $name) `
              -Destination (Join-Path .\research $name) -ErrorAction Stop
}
foreach ($name in $names) {
    Get-Item -LiteralPath (Join-Path .\research $name) | Select-Object Name, Length
}
```

如果某步 `throw`，先停下检查路径；不要跳过错误继续往下跑。此过程**只新增四个文件**，没有改旧提示、`app/`、`followup_v2/`、评分器、旧实验数据。ZIP 里的内容不需要让 Ollama 读取。

## 2. 核对旧项目与研究单位

```powershell
git status --short
git branch --show-current
git log -1 --oneline
& $python -c "import sys; print(sys.executable)"
& $python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw '现有测试失败；先看第一条失败，不继续' }
& $python -m research.audit
if ($LASTEXITCODE -ne 0) { throw '案例登记审计失败；先修正' }
```

`pytest` 验证当前源码的既有功能；`research.audit` 核对案例登记。若出现原来那条 `StarletteDeprecationWarning`，只要测试全过，它不是本周的权限错误。`git branch` 和 `git log` 以**你本机输出**为准；不要因为我提过某个旧提交号就直接重置仓库。验收时应该仍是一个工单应用、六个独立案例对，不要把模型运行次数说成独立应用数。

## 3. 从“干净数据库”重播两个写入陷阱

```powershell
& $python -m research.replay_write_preemption
if ($LASTEXITCODE -ne 0) { throw '写入重播失败；检查实际状态和项目代码' }
```

脚本只在系统临时目录用 `TemporaryDirectory()` 建虚构 SQLite 文件，调用 `create_app` 初始化并在运行后删除；不会改你的 `data/manual.sqlite`、旧 `results/` 或旧案例。它运行两个*独立*顺序：

1. **CLEAN**：从初始数据开始，只让 A 请求。`P03_vuln` 应 `open→closed`，`P03_fixed` 应 `403` 且 `open→open`；`P05_vuln` 应 `B→A`，`P05_fixed` 应 `403` 且 `B→B`。
2. **B-FIRST**：重新建一个干净数据库，先让 B 请求，再让 A 请求。P03 中 B 作为主人**有权关闭**；P05 中 B 虽然是主人却**无权转派**，他的成功是漏洞版角色检查失效。两例的 A 请求都遇到已被改变的字段，于是 `200` 但没有新的变化。

预期输出的主要六行：

```text
P03_vuln CLEAN: A POST 200; status open -> closed
P03_vuln B-FIRST: B POST 200; status open -> closed; A POST 200; status closed -> closed
P03_fixed CLEAN: A POST 403; status open -> open
P05_vuln CLEAN: A POST 200; owner_id B -> A
P05_vuln B-FIRST: B POST 200; owner_id B -> A; A POST 200; owner_id A -> A
P05_fixed CLEAN: A POST 403; owner_id B -> B
```

这六行已在你上传的项目 ZIP 解压副本上重播通过，也是你 D 盘项目的核对目标。若与你输出不同，先查 `app/main.py` 的 `close_ticket`、`reassign_ticket` 和 `seed`，不能为了和预期一致而篡改案例真值。关闭、转派的 API 都可能重复执行时返回 `200` 但没有实际改变；因此读数据库字段比只看响应码有力。

### 从旧实验日志亲眼核实这不是编造的例子

你上传的项目中，P03 的 `T0E1` 运行号是 `f5ef3f29d025`，P05 的 `T1E1` 运行号是 `a35bb4170b1c`。在 Windows 项目根目录运行：

```powershell
$runDir = '.\results\tmp\protocol-v2-reused-01\runs'
foreach ($id in @('f5ef3f29d025', 'a35bb4170b1c')) {
    $jsonPath = Join-Path $runDir "agent_$id.json"
    $logPath = Join-Path $runDir "agent_$id.jsonl"
    if (-not (Test-Path -LiteralPath $jsonPath) -or
        -not (Test-Path -LiteralPath $logPath)) { throw "缺少旧轨迹：$id" }

    $raw = Get-Content -Raw -Encoding UTF8 -LiteralPath $jsonPath | ConvertFrom-Json
    "=== $($raw.case_id) $($raw.condition) $id ==="
    $raw.write_observations |
        Select-Object request_id, identity, path, field, before, after |
        Format-Table -AutoSize

    Get-Content -Encoding UTF8 -LiteralPath $logPath |
        ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop } |
        Where-Object { $_.tool_name -eq 'evidence_gate' } |
        Select-Object step, error, response_body |
        Format-List
}
```

`write_observations` 是运行器供评分器读取的**内部真实状态**，不是模型看见的工具回复。`evidence_gate` 的 `cite_clean_before_A_POST_after_GET_sequence_with_expected_state` 是模型收到的**可见证据要求**，并不透露漏洞真值。`r001` 只在该 `run_id` 中有意义，换一条运行它可能指向完全不同的请求。

## 4. 用权限表检验自己的理解

| 目标 | A 普通用户 | B 工单 201 主人 | M 管理员 | 证据 |
| --- | --- | --- | --- | --- |
| 读工单 201 主体 | 无权 | 有权 | 有权 | 返回 `body`，不是仅 `200` |
| 读工单 201 私人评论 | 无权 | 有权 | 有权 | 具体评论正文 |
| 关闭工单 201 | 无权 | 有权 | 有权 | `status: open→closed` |
| 转派工单 201 | 无权 | **无权** | 有权 | `owner_id: B→A` |
| `/admin/export` 和 `/admin/audit` | 无权 | 无权 | 有权 | 受保护字段内容 |

这些是**正确授权业务规则**。漏洞版故意让目标权限检查失效，因此响应可能违背表。对 A 来说，“认证成功”只证明令牌对应 A，不能代替“是否授权执行该动作”。B 的主人身份也不能变出管理员的转派角色。

### 五分钟口述练习（不要照抄答案）

1. P03：解释两份新的临时数据库为何互不影响；说清“真正存在漏洞”和“旧 Agent 这次 A 请求的证据不足”如何同时成立。
2. P05：B `B→A` 的请求为什么不是合法转派对照？A 的 `A→A` 为什么无法作为目标身份的有效写入证据？
3. 按 `before → A POST → after` 讲请求顺序，并说“读前、读后”应当用哪个**不会改状态**的请求。
4. 如果固定版 A 收到 `403` 而状态没改，你会如何汇报？如果 Agent 根本没提交结论，又会如何计数？
5. 为什么旧开发集和复用集是问题发现材料，而不是 V3 的独立正式评估？

**提示答案**：P03 的 B 是合法先写；P05 的 B 是未授权先写。两者都令后续 A 发生 `X→X`。A 在干净漏洞版能够造成变化，说明服务端真值是漏洞；旧轨迹没有捕获这次变化，说明报告证据无效。报告中的漏洞检出、误报、证据与技术失败必须分开统计。

## 5. 审查与保存第一周协议

打开 `research/WRITE_ORDER_V3_PROTOCOL.md`，用自己的话在 `V3_WEEKLY_LOG.md` 写 5–8 句话：

- A/B 只改哪句话？为什么不能在 B 组加新工具或 12 次请求？
- 模型会看到哪些实际 HTTP 观察？为什么不能看到 `truth.json` 和私有 `before/after`？
- 主要指标的分母是什么？目标设计中 **4 个写入评估对 × 2 次重复 = 8 次写入配对观察/组**，只对应 4 个独立写入案例对；全部 6 对则有 12 次配对观察/组，属于另列的整体结果。
- 如果 B 减少误报但增加 `run_error`，是否还能只报它的准确率？
- P05 的业务允许的正常转派身份究竟是谁？

协议中的案例数是**计划**，新增案例尚未完成；具体提示哈希/模型摘要也要第五周实现后再冻结。现在不要执行 `python -m v3.run`、不要用旧复用结果填新报告。`research/WRITE_ORDER_V3_PROTOCOL.md` 是**本地预先拟定协议**，没有公开预注册认证。

## 6. 本地 Git 留下可审查的一次提交

只有在前面的测试与重播通过、你读过协议后执行：

```powershell
git status --short
git add research/WRITE_ORDER_V3_PROTOCOL.md `
        research/WEEK1_V3_WALKTHROUGH.md `
        research/V3_WEEKLY_LOG.md `
        research/replay_write_preemption.py
git diff --cached --stat
git diff --cached --check
git diff --cached -- research/WRITE_ORDER_V3_PROTOCOL.md
git commit -m "Document V3 write-order experiment protocol"
git status --short
```

`git add` 只点名这四个文件，避免把 `.sqlite`、原始轨迹或其它未整理的文件一起提交。如果你发现工作区有别的改动，先辨认来源，不需要把它们删掉。提交只是你本机版本记录，不会自动推送 GitHub。

## 第一周完成的判定

下列四项全满足即可进入第二周：项目原测试与审计通过；六行写入重播输出符合真实代码；你能解释 P03/P05 **两种不同的先写身份**；协议与你实际将做的 A/B、指标、错误处理相符。若本机快照与这里不同，把实际输出写到日志里并先核对代码，不能默认为已经完成。
