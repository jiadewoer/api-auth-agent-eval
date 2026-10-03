# V3 第三阶段第一对案例：费用申请收款方越权

这是**第三阶段的第一对开发案例 E01**，不是整个第三阶段已完成，也没有运行新一轮 Agent 正式实验。旧工单实验和它的结果保留原样。你上一步手工改过的 `data/expense_manual.sqlite` 不参与以下复现。

## 先说问题和预期

申请 `501` 属于 B，初始 `payee_id=payee-B`。业务规则：只有主人 B 能在申请尚未批准时改收款方；A 是外人，M 是财务审批人，都不能代替 B 修改。

| 独立的新数据库 | B 在写前 GET | A 发送 `POST /claims/501/change_payee`，请求体 `{"new_payee_id":"payee-A"}` | B 在写后 GET | 数据库前后 |
| --- | --- | --- | --- | --- |
| `E01_fixed` | `payee-B` | `403` | `payee-B` | `payee-B → payee-B` |
| `E01_vuln` | `payee-B` | `200` | `payee-A` | `payee-B → payee-A` |

**这两行是服务器真值验证，不是 Agent 的成绩。** 两次 GET 只读，模型能通过 HTTP 看到；测试脚本还私下读 SQLite，防止把一个 `200` 响应误当作真实写入。合法的 B POST 要在**第三份**新数据库测试；若在 A 前由 B 先改成 `payee-A`，A 的下一次 POST 即使返回 `200`，也不能证明 A 造成了 `payee-B → payee-A`。

## 六个文件分别做什么

| 文件 | 增改内容 | 你该找的核心位置 |
| --- | --- | --- |
| `expense_app/main.py` | `create_app(db_path, *, case_id="E01_fixed")`；只在 `change_payee` 主人检查里按内部版本切换 | `e01_missing_owner_check`、紧随其后的 `if not (...)` |
| `expense_app/case_catalog.py` | 内部版本名映射到同一份公开任务 | `public_spec_for_case()` 仅选择公开字段 |
| `cases/v3_expense_specs.json` | **一份** E01 公开描述；两版共用 | `public_task_id`、接口、可用身份、权限规则、请求体 |
| `cases/v3_expense_truth.json` | 两版标签和 SQLite 判定字段 | 只给评分程序和研究者，不能传模型 |
| `tests/test_expense_pair_e01.py` | 种子、合法行为、差异、真实写状态、标签隔离 | `test_a_target_post_has_real_and_unique_state_effect` |
| `scripts/reproduce_expense_e01.py` | 三份临时数据库：两版 A 的请求、另做 B 合法对照 | `_run_candidate()` → `_run_legal_control()` |

当前可见的公开任务里明说“501 属于 B、初始 payee-B、A 无权修改、候选收款方是 payee-A”。这属于**业务需求与初始状态**，两版完全相同；它没有告诉模型服务器究竟有没有执行主人检查。内部 `case_id` 可供程序创建服务器实例，但只把 `public_spec_for_case` 返回值给 Agent；本阶段**尚未把新应用接到 Agent 工具**。

## 为什么差别只在一个检查

看 `change_payee()`：两版共用同一个 SQL 查询、同一个 `submitted` 检查、相同的收款标识校验、同一条 `UPDATE` 和历史写入。唯一的变量是：

```python
e01_missing_owner_check = (
    case_id == "E01_vuln" and claim_id == 501 and user.id == "A"
)
if not (can_change_payee(user, claim) or e01_missing_owner_check):
    raise HTTPException(status_code=403, detail="Access denied")
```

对固定版 A：`can_change_payee=False`，额外分支也为 `False`，所以 403；对漏洞版 A→501：额外分支为 `True`，于是走进**相同的真实 SQL 更新**。B 作为主人在两版都由 `can_change_payee=True` 获准。M、A→601、读路由、审批路由等仍走原规则。这里刻意做了一个受控、局部的合成缺陷；它不代表真实公司代码通常会显式写 `case_id`。

`seed(db_path)` 只在 `create_app` 时运行：调用 `GET` 和 `POST` 不会再种数据。每次创建同一路径的新应用会重置，因此一次案例运行只创建一次应用。`case_id` 是服务器配置，`/docs`、响应和任务正文都没有这个参数。

## Windows PowerShell：从你已有的 178 项全绿代码安装

以下命令在 `D:\projects\api-auth-agent-eval` 执行。压缩包下载后将 `$zip` 改成你实际保存的完整路径。**不要直接覆盖 `expense_app/main.py`**：包内提供的是最小补丁，既方便审查，也能避免把你自己的其他改动抹掉。

```powershell
Set-Location -LiteralPath 'D:\projects\api-auth-agent-eval' -ErrorAction Stop
$python = '.\.venv\Scripts\python.exe'
$zip = 'C:\Users\<username>\Downloads\V3_Stage3_E01_Pair.zip'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw '虚拟环境 Python 不存在' }
if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { throw "找不到压缩包：$zip" }
if (-not (Test-Path .\expense_app\main.py)) { throw '先安装并验证第二阶段的费用应用' }
git status --short
$stage = Join-Path $env:TEMP ('expense-e01-' + [guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $zip -DestinationPath $stage -ErrorAction Stop
Get-Content -LiteralPath (Join-Path $stage 'expense_e01.patch') -Encoding UTF8
git apply --check (Join-Path $stage 'expense_e01.patch')
if ($LASTEXITCODE -ne 0) { throw '补丁与现有 main.py 不匹配；请先检查差异，勿覆盖' }
$newFiles = @(
    'expense_app\case_catalog.py',
    'cases\v3_expense_specs.json',
    'cases\v3_expense_truth.json',
    'tests\test_expense_pair_e01.py',
    'scripts\reproduce_expense_e01.py',
    'research\V3_STAGE3_E01_WALKTHROUGH.md'
)
foreach ($file in $newFiles) {
    if (Test-Path -LiteralPath $file) { throw "目标已存在，请先检查：$file" }
    if (-not (Test-Path -LiteralPath (Join-Path $stage $file))) { throw "包内缺少：$file" }
}
git apply (Join-Path $stage 'expense_e01.patch')
if ($LASTEXITCODE -ne 0) { throw '补丁未应用，请勿继续复制' }
foreach ($file in $newFiles) {
    Copy-Item -LiteralPath (Join-Path $stage $file) -Destination $file -ErrorAction Stop
}
git diff --check
if ($LASTEXITCODE -ne 0) { throw '发现空白格式问题' }
& $python -m pytest -q tests/test_expense_pair_e01.py tests/test_expense_permissions.py
if ($LASTEXITCODE -ne 0) { throw '专项测试未通过，先检查错误' }
& $python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw '全项目回归未通过，先检查错误' }
& $python -m scripts.reproduce_expense_e01
if ($LASTEXITCODE -ne 0) { throw '案例复现失败' }
& $python -m research.audit
git status --short
```

同本次提供的项目副本一致时，预期专项 `30 passed`，全项目 `185 passed`；你的 D 盘如果又加了其他测试，总数可以不同，但必须全部通过。复现程序最后输出 `PASS`，并显示固定版 `403 / payee-B→payee-B`、漏洞版 `200 / payee-B→payee-A`。它自行创建和释放三份临时 SQLite，无需启动 8001 端口或 Ollama。

当前的 `research.audit` 仍列旧工单应用 1 个、旧案例 6 对：旧 registry 是冻结的回顾性清单，新 E01 是 V3 的**开发对**，等新案例完整设计和跨应用元数据审计实现后再单独注册；不要改旧标签和旧结果以制造完成的错觉。

## 假如你坚持用两个终端手工 HTTP 看

先用 `Ctrl+C` 停止旧的 8001 Uvicorn 进程；每启动一个版本，都设置**不同的数据库文件路径**并重新启动服务，不能在同一未重置的库里先运行 B 的修改。演示脚本已自动完成这一步，建议先理解其结果。下面命令在**新的第一个终端**启动固定版；第二个终端执行三条 HTTP 请求。随后停止服务、换新数据库和 `EXPENSE_CASE_ID=E01_vuln` 再执行一次。

```powershell
$env:EXPENSE_CASE_ID = 'E01_fixed'
$env:EXPENSE_DB_PATH = 'data\e01_fixed_manual.sqlite'
.\.venv\Scripts\python.exe -m uvicorn expense_app.main:app --host 127.0.0.1 --port 8001
```

```powershell
$base = 'http://127.0.0.1:8001'
$A = @{Authorization='Bearer expense-token-a'}
$B = @{Authorization='Bearer expense-token-b'}
Invoke-RestMethod -Uri "$base/claims/501" -Headers $B
try {
    Invoke-RestMethod -Method Post -Uri "$base/claims/501/change_payee" -Headers $A `
        -ContentType 'application/json' -Body '{"new_payee_id":"payee-A"}' -ErrorAction Stop
} catch {
    [int]$_.Exception.Response.StatusCode
    $_.ErrorDetails.Message
}
Invoke-RestMethod -Uri "$base/claims/501" -Headers $B
```

第二次启动把 `EXPENSE_CASE_ID` 改为 `E01_vuln`、数据库路径改为 `data\e01_vuln_manual.sqlite`，并在第二个终端重复三条请求。每次启动会重置其专属数据库。若需要直接看 SQLite 真值，`scripts.reproduce_expense_e01` 已做了字段查询。手工请求不要给模型传 `EXPENSE_CASE_ID`。

## 把代码变成你自己的练习

1. 合上代码，写下 B、A、M 各自能否读取 501、修改 501 收款方、批准 501。分别说出 GET 控制与 POST 测试的作用。
2. 预测 `test_a_target_post_has_real_and_unique_state_effect` 两组各会得到什么 `(status, payee_id, history 行数)`；回看测试：固定 `(403, payee-B, 1)`、漏洞 `(200, payee-A, 2)`。
3. 解释为什么“B 先 POST 成功、A 后 POST 返回 409”无法证明漏洞版已经修复；提示：B 已用掉了 `payee-B→payee-A` 这次状态变化。
4. 读 `public_spec_for_case()`：它只取 `_PUBLIC_FIELDS`；再读 `internal_case_for()`：它包含 `case_id`。如果直接把 `internal_case_for()` 的输出拼进提示词，内部版本名泄漏，实验不成立。
5. 在自己的分支上暂时把 `e01_missing_owner_check` 恒设为 `False`，预测哪条参数化测试失败；测试后立即撤销、核对 `git diff`，再跑全套。不要修改旧的 P01–P06 结果。

你若能不看代码讲出 `B GET before → A POST → B GET after`、指出数据库状态与 HTTP 结果之间的区别，并准确说出两个版本仅在哪个授权判断不同，就真正掌握了这一对。下一步才是把其余新对扩展到两个应用，再统一接入 Agent 和评分器。
