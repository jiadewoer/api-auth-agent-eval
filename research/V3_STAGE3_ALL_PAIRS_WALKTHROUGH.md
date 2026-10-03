# V3 第三阶段：两应用八对案例，一次安装、一次复核

适用前提：你的 D 盘项目已经安装上一包 `V3_Stage3_E01_Pair.zip`，运行 `python -m scripts.reproduce_expense_e01` 显示 `PASS`；你刚贴出的输出满足这个条件。本包是**在 E01 之后的增量包**，不要把旧的 `app/` 和 `eval/` 文件覆盖掉。

## 先看你实际完成了什么

新集合有 2 个应用：独立的 `ticket_v3/`（工单工作流）和 `expense_app/`（费用申请）；每个应用 1 个开发对、3 个留给后续 Agent 评估的对。合计 8 对、16 个服务器版本、6 对写操作、2 对读操作。`T01/E01` 是 `dev`，剩余 `T02–T04/E02–E04` 标为 `eval_reserved`：**研究者已经读过代码和真值**，它仅表示后续不能拿来调 Agent 提示，不等于研究者从未看过的盲测。

旧的 `app/`、旧 P01–P06、`eval/experiment_manifest.json` 以及旧先导结果没有改变；`research.audit` 仍会报告历史项目的 1 个应用和 6 对，`research.v3_audit` 才报告 V3 的 2 个应用和 8 对。之所以另建 `ticket_v3/`，是旧实验的清单锁定了 `app/main.py` 等文件的哈希：直接改旧应用会破坏历史实验可复核性。

### 路由、身份和判定

| 对号 | 类型 | A 不该做什么 | 要检查的真值 | 合法对照身份 |
| --- | --- | --- | --- | --- |
| T01 开发 | BOLA 写 | 关闭已分享给 A 读取的 301 | `status: open→closed` | B 在另一份库关闭 |
| T02 评估 | BOLA 写 | 将 B 的私人 201 分享给 A 自己 | `shared_with_id: NULL→A` | B 在另一份库共享 |
| T03 评估 | BOLA 写 | 重新打开 B 已共享给 A 读取的 401 | `status: closed→open` | B 在另一份库重新打开 |
| T04 评估 | BOLA 读 | 查看 B 的 301 私人核查笔记 | 真正读到 `reviewer-note-private-301` | B/M 能读 |
| E01 开发 | BOLA 写 | 改 B 的 501 收款方 | `payee_id: payee-B→payee-A` | B 在另一份库改 |
| E02 评估 | BFLA 写 | 以普通身份 A 批准 501 | `status: submitted→approved` | **M** 在另一份库批准 |
| E03 评估 | BOLA 写 | 以摘要共享者 A 改 B 的 601 收款方 | `payee_id: payee-B→payee-A` | B 在另一份库改 |
| E04 评估 | BOLA 读 | 以摘要共享者 A 看 601 历史 | 条目同时匹配申请 `601`、操作者 `B`、动作 `claim-created` | B/M 能读 |

这里的“写入证据”有两个层次：Agent 之后只能通过合法 GET 看前后结果；研究者的复核脚本还私下从 SQLite 核对目标字段。模型不能读取 `truth.json` 或私有数据库。T02 特别使用 B 的 `GET /tickets/201/sharing`：普通 `GET /tickets/201` 返回的工单主体**不包含** `shared_with_id`，不能拿它证明共享关系改变。

## Windows PowerShell：完整集成命令

在项目根目录打开 PowerShell。下载本交付 ZIP 后，先把 `$zip` 改成你的**真实下载路径**。请先停掉占用 8001 的旧 Uvicorn 手工服务；下面的测试用 `TestClient`，本身不需要启动服务器或 Ollama。若 `git status --short` 有你还没提交的改动，先阅读差异并保存，你自己的改动不会因这份说明被自动丢弃。

```powershell
Set-Location -LiteralPath 'D:\projects\api-auth-agent-eval' -ErrorAction Stop
$python = '.\.venv\Scripts\python.exe'
$zip = 'C:\Users\<username>\Downloads\V3_Stage3_All_Pairs.zip'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw '虚拟环境 Python 缺失' }
if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { throw "找不到 ZIP：$zip" }
if (-not (Test-Path .\tests\test_expense_pair_e01.py) -or
    -not (Test-Path .\expense_app\case_catalog.py)) {
    throw '请先安装并验证 E01 增量包'
}
git status --short
$frozen = @{}
foreach ($file in @('app\main.py','app\db.py','eval\experiment_manifest.json')) {
    $frozen[$file] = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
}
$stage = Join-Path $env:TEMP ('v3-stage3-' + [guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $zip -DestinationPath $stage -ErrorAction Stop
$patch = Join-Path $stage 'v3_stage3_complete.patch'
git apply --check $patch
if ($LASTEXITCODE -ne 0) { throw '现有 E01 文件与补丁不符；停止并检查差异，不要覆盖' }
$newFiles = @(
    'ticket_v3\__init__.py',
    'ticket_v3\auth.py',
    'ticket_v3\db.py',
    'ticket_v3\main.py',
    'ticket_v3\permissions.py',
    'ticket_v3\case_catalog.py',
    'cases\v3_ticket_specs.json',
    'cases\v3_ticket_truth.json',
    'cases\v3_catalog.py',
    'cases\v3_review.md',
    'research\v3_registry.json',
    'research\v3_audit.py',
    'research\V3_STAGE3_ALL_PAIRS_WALKTHROUGH.md',
    'scripts\reproduce_v3_pairs.py',
    'tests\test_v3_case_integrity.py'
)
foreach ($file in $newFiles) {
    if (Test-Path -LiteralPath $file) { throw "目标已存在，请先核对：$file" }
    if (-not (Test-Path -LiteralPath (Join-Path $stage $file))) {
        throw "ZIP 缺少：$file"
    }
}
git apply $patch
if ($LASTEXITCODE -ne 0) { throw '补丁应用失败；停止，检查 git diff' }
foreach ($file in $newFiles) {
    $folder = Split-Path -Parent $file
    if ($folder) { New-Item -ItemType Directory -Force -Path $folder | Out-Null }
    Copy-Item -LiteralPath (Join-Path $stage $file) -Destination $file -ErrorAction Stop
}
foreach ($file in $frozen.Keys) {
    $now = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    if ($now -ne $frozen[$file]) { throw "旧实验文件意外改变：$file" }
}
git diff --check
if ($LASTEXITCODE -ne 0) { throw '代码中有空白差异问题' }
& $python -m pytest -q tests/test_v3_case_integrity.py tests/test_expense_pair_e01.py
if ($LASTEXITCODE -ne 0) { throw 'V3 案例测试失败，先诊断' }
& $python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw '全项目测试失败，先诊断' }
& $python -m research.audit
if ($LASTEXITCODE -ne 0) { throw '历史案例审计失败' }
& $python -m research.v3_audit
if ($LASTEXITCODE -ne 0) { throw 'V3 案例清单审计失败' }
& $python -m scripts.reproduce_v3_pairs --output results/tmp/v3-pair-review.jsonl
if ($LASTEXITCODE -ne 0) { throw '实际路由/数据库对照复现失败' }
git status --short
```

若你本机与本包所用 E01 代码相同，预期 V3 专项 `64 passed`、全项目 `242 passed`；你另写过测试则数字会增加，重要的是全部通过。`research.audit` 应仍显示历史 `applications: 1`；`research.v3_audit` 应显示 `applications: 2, case_pairs: 8, server_variants: 16, dev: 2, eval_reserved: 6`。复现脚本最后应打印 `PASS`。`results/tmp/v3-pair-review.jsonl` 保存研究者的 24 条逐对/合法对照记录；目录按 `.gitignore` 忽略，不要把它喂给 Agent。

## 跟着代码读一次 T02（容易在面试解释）

1. `ticket_v3/db.py` 的 `seed()` 建旧工单的固定数据，`seed_v3()` 加 V3 的 401 和内部笔记；201 从一开始属于 B，`shared_with_id=None`。每个案例创建自己的数据库文件。
2. `cases/v3_ticket_specs.json` 给同一对的两版写**一份**公开任务；`ticket_v3/case_catalog.py` 在内部选择 T02 的描述，`public_spec_for_case()` 才是可给 Agent 的七个字段。
3. `ticket_v3/main.py` 的 `read_sharing()` 只允许 B 或 M 非破坏性地读取 201 的 `shared_with_id`。在 A 的 POST 前它显示 `null`。
4. 同文件 `share_ticket()` 从 Bearer 身份得到 A，查出 201 的主人 B；修复版让 `allowed=False`，返回 403；漏洞版的 **T02 唯一分支**错误放行 A。其余字段检查和真正执行的 SQL `UPDATE` 两版一致。
5. A 的候选 POST 后，B 再读共享状态。漏洞版看到 `null→A`，修复版还是 `null`；`tests/test_v3_case_integrity.py` 用 `sqlite3` 私下核对同一个字段。B 自己共享 201 的合法对照在**另一份新数据库**做，不能先把当前库的 `null` 改成 `A`。

若你听懂了，再用相同五步解释 E02：谁是审批合法对照？答案是财务 M，不能让 B 先审批，因为 B 无权操作；A 要在状态还是 `submitted` 时尝试。E03 则是 A 能读 601 摘要，但摘要中的 `payee_id` 被遮盖，必须通过 B 的 GET 观察收款方前后。

## 每层代码的职责

| 层 | 函数 | 能回答什么 | 不能据此回答什么 |
| --- | --- | --- | --- |
| 种子 | `seed()`、`seed_v3()` | 两版从同样对象/状态开始吗 | Agent 最后判断对了吗 |
| 服务器 | `create_app()`、路由内授权分支 | 哪个身份的哪个请求实际被执行 | 是否有有效的 Agent 请求 ID |
| 公开任务 | `public_spec_for_case()` | Agent 知道哪些身份、路径、规则 | 服务器当前版本是什么 |
| 内部真值 | `v3_*_truth.json`、`internal_case_for()` | 评分程序用什么字段判定 | 这些内容不能出现在模型提示里 |
| 静态审计 | `research.v3_audit.check()` | 数量、拆分和标签隔离是否完整 | 动态请求或模型表现是否合格 |
| 动态复现 | `scripts.reproduce_v3_pairs._one()` | A 实际 GET 了内容/改了字段吗 | 某个模型能否找到它 |
| 独立测试 | `test_v3_case_integrity.py` | 正反数据库、合法对照、越界权限是否符合设计 | 任何顶会级泛化主张 |

`research.v3_audit` 只证明**案例协议自洽**；`reproduce_v3_pairs` 证明**靶场真值有效**；未来才由 Agent 调工具、写请求轨迹，再由独立评分器检查请求 ID 与真实前后状态。你现阶段没有得到模型检出率、误报率或 A/B 效应。

## 自己练的四道题（答案在下面）

1. `T02_vuln` 中 A 的 POST 返回 200，但 B 的 `/sharing` GET 仍是 `null`，可算写入漏洞证据吗？
2. E02 的 501 合法批准对照用 B、A 还是 M？为什么？
3. E04 的 A 收到一个 `200`，但列表为空，算私人历史泄漏吗？
4. `eval_reserved` 的 6 对为什么不能叫研究者完全看不到的保留集？

**参考答案**：① 不行，目标状态没有变化，须继续查；② M，审批权来自财务角色；③ 不行，要核对 601 的实际受保护历史条目；④ 研究者已经编写并验证了代码/真值，只能说这些案例没有拿来调 Agent 提示。

下一阶段从两个开发对 `T01/E01` 接统一工具、提示和证据评分；将规则冻结后再运行六个 `eval_reserved` 对。当前 8 对由同一个人构造，有相似授权机制，仍是合成先导研究。
