# 第二阶段动手课：独立费用申请 API 的正确授权版

> 你可以连续做完，无需等待下一周。这里的“第二阶段”只表示实施顺序。项目依然只使用虚构身份、虚构申请与虚构收款标识。当前交付的是**正确授权版**；新的 `vuln/fixed` 成对案例、跨应用 Agent 工具和正式评估尚未实现。

## 0. 这一步解决什么问题

旧项目只有一个工单应用。新目录 `expense_app/` 独立管理用户角色、费用申请、收款人和操作历史；它不调用 `app/permissions.py`，也不修改你已经冻结的旧实验。这样将来才能检验调查方法能否适应另一套业务规则。两个应用仍运行在同一台电脑上；“两个应用”不意味着需要两台电脑或训练模型。

你应当能回答：**同一个人能看摘要，是否就能看收款人、查操作历史或修改申请？** 答案取决于具体操作，不能只看用户是否登录。

## 1. 新增文件与每个文件的责任

| 文件 | 它做什么 | 你读代码时找的关键句 |
| --- | --- | --- |
| `expense_app/db.py` | 建 `users/payees/claims/history` 四张表，`seed()` 重置虚构数据 | `sqlite3.Row`、外键、`?` 参数、`with conn:` |
| `expense_app/auth.py` | 从 `Authorization: Bearer ...` 识别 A/B/M | 无效令牌抛 `401`；这里不判断某张申请是否可读 |
| `expense_app/permissions.py` | 清晰的业务授权函数 | 主人、共享者、财务角色分别能做什么 |
| `expense_app/main.py` | 四个 FastAPI 路由；调用认证、授权、SQL | `create_app(db_path)` 创建时种数据；普通请求不会重种 |
| `expense_app/demo.py` | 用临时数据库走真实路由，打印状态前后对照 | 先看字段，再发 POST，再查字段 |
| `tests/test_expense_permissions.py` | 每项测试有自己的 `tmp_path` 数据库 | 拒绝时状态不变；允许时状态变化；重复操作 `409` |

`expense_app/__init__.py` 标明这是一个 Python 包。`research/WEEK2_EXPENSE_WALKTHROUGH.md` 就是当前讲解；这些文件全部是**新文件**。

## 2. 先理解数据：三个身份、三张申请

| 身份 | 角色 | 业务含义 |
| --- | --- | --- |
| A | claimant | 普通申请人，有自己的 101；收到 B 对 601 的摘要共享 |
| B | claimant | 普通申请人，拥有私人申请 501 和共享申请 601 |
| M | finance | 财务审核人，可看完整申请并审批；不能替申请人改收款人 |

| 申请 | 主人 | 显式共享给谁 | 初始收款标识 | 初始状态 |
| --- | --- | --- | --- | --- |
| 101 | A | 无 | `payee-A` | `submitted` |
| 501 | B | 无 | `payee-B` | `submitted` |
| 601 | B | A | `payee-B` | `submitted` |

金额用整数分（`amount_cents`），收款标识是虚构字符串，不是真实银行账户。`history` 记录创建、审批及真实发生的收款人变更。四张表位于费用应用自己的 SQLite 文件，和工单应用的 `tickets` 表**不是一套数据**。

## 3. 权限表：每个接口回答一个独立问题

| 接口 | A 对 501 | B 对 501 | M 对 501 | A 对共享的 601 |
| --- | --- | --- | --- | --- |
| `GET /claims/{id}` | `403` | `200`，含收款标识 | `200`，含收款标识 | `200`，但 `payee_id=null` |
| `GET /claims/{id}/history` | `403` | `200` | `200` | `403` |
| `POST /claims/{id}/approve` | `403` | `403` | `200`，`submitted→approved` | `403` |
| `POST /claims/{id}/change_payee` | `403` | `200`，仅在 `submitted` 时 | `403` | `403` |

**认证**回答“令牌对应谁”：A/B/M 有效，缺失或无效返回 `401`。**授权**回答“这个身份对这张申请能做这件事吗”：不允许返回 `403`。合法身份查不存在的申请返回 `404`。已审批再次审批或试图改已审批申请返回 `409`，表示当前业务状态与操作冲突。未知收款标识返回 `400`；请求体多余字段被 Pydantic 拒绝，返回 `422`。正确读或真实成功的写入返回 `200`。

特别记住：`601` 的分享仅涉及**摘要**；不会把历史或收款信息顺便送给 A。M 有财务审批权，但没有申请人编辑收款人的权力。这套规则与工单的“主人可关闭、管理员可转派”有实质区别。

## 4. 把完整代码放进你现有的 Windows 项目

把 `V3_Stage2_Expense_Lab.zip` 下载到 `C:\Users\<username>\Downloads`。在 PowerShell 里从项目根目录执行。先检查来源和目标，**如果同名文件已存在就停下，不覆盖自己的改动**：

```powershell
Set-Location -LiteralPath 'D:\projects\api-auth-agent-eval' -ErrorAction Stop
$python = '.\.venv\Scripts\python.exe'
$zip = 'C:\Users\<username>\Downloads\V3_Stage2_Expense_Lab.zip'

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw '找不到虚拟环境 Python' }
if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { throw "找不到 ZIP：$zip" }
if (-not (Test-Path .\research\WRITE_ORDER_V3_PROTOCOL.md) -or
    -not (Test-Path .\app\main.py)) { throw '请先核对项目目录与第一阶段文件' }

$newFiles = @(
    'expense_app\__init__.py',
    'expense_app\db.py',
    'expense_app\auth.py',
    'expense_app\permissions.py',
    'expense_app\main.py',
    'expense_app\demo.py',
    'tests\test_expense_permissions.py',
    'research\WEEK2_EXPENSE_WALKTHROUGH.md'
)
foreach ($name in $newFiles) {
    if (Test-Path -LiteralPath $name) { throw "目标已存在，先核对：$name" }
}

$stage = Join-Path $env:TEMP ('expense-stage-' + [guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $zip -DestinationPath $stage -ErrorAction Stop
foreach ($name in $newFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $stage $name) -PathType Leaf)) {
        throw "压缩包缺少：$name"
    }
}
New-Item -ItemType Directory -Path .\expense_app -Force | Out-Null
foreach ($name in $newFiles) {
    Copy-Item -LiteralPath (Join-Path $stage $name) -Destination $name -ErrorAction Stop
}
Get-ChildItem .\expense_app | Select-Object Name, Length
```

此包不替换 `app/`、`agent/`、`followup_v2/`、`cases/`、`eval/`、你的第一阶段笔记或旧结果。

## 5. 立刻运行测试和演示

```powershell
& $python -m pytest -q tests/test_expense_permissions.py
if ($LASTEXITCODE -ne 0) { throw '费用应用专项测试失败，停止' }

& $python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw '全项目测试失败，停止' }

& $python -m expense_app.demo
if ($LASTEXITCODE -ne 0) { throw '演示中的请求或状态断言失败，停止' }

& $python -m research.audit
git status --short
```

对和你上传 ZIP 相同的代码，预期专项测试 **23 passed**、全部 **178 passed**。旧 `research.audit` 仍应报告 `applications: 1`：它只登记了旧实验的工单案例；新费用应用的**正确版已存在**，但还没有新 `vuln/fixed` 对，不应提前把登记数字改成 2。`expense_app.demo` 最后应出现 `PASS`。原先 Starlette/TestClient 的 deprecation warning 若出现，可记录，但只要测试通过，它不是授权失败。

演示脚本用 `TemporaryDirectory()`，调用 `create_app()` 并在退出时关闭数据库连接、删除临时文件。它不会重建 `data/manual.sqlite`；导入 `expense_app.main` 时可能创建新的 `data/expense_manual.sqlite`，该虚构数据库已被你的 `*.sqlite` 忽略规则排除。运行时无需 Uvicorn 或 Ollama。

## 6. 逐段看代码：从请求头走到数据库

下面以 **A 修改 B 的 501 收款人** 为例。请求是 `POST /claims/501/change_payee`，JSON 是 `{"new_payee_id":"payee-A"}`：

1. `get_current_user()` 从 `Authorization` 头找 `expense-token-a`，得到 `ExpenseUser(id="A", role="claimant")`。这是**认证**，此时仍没权编辑任何一张申请。
2. `change_payee()` 从数据库取 501，读到 `owner_id="B"`、`payee_id="payee-B"`、`status="submitted"`。
3. `can_change_payee(user, claim)` 比较 `claim["owner_id"] == user.id`。`B != A`，所以抛 `403`；此时还没有执行 `UPDATE`。
4. 测试重新查询 SQLite，必须仍是 `payee-B`，且 `history` 没有新增。**只有响应 `403` 而不查状态，不能发现一种“先改库再报错”的严重实现错误。**

把身份换为 B：前三步通过；程序确认申请仍为 `submitted`、新收款标识存在，执行带 `?` 参数的 SQL `UPDATE`，并在同一 `with conn:` 事务里插入历史事件。测试观察 `payee-B→payee-A`。`WHERE ... payee_id = 旧值 AND status = 'submitted'` 再检查 `rowcount`，防止基于过期状态悄悄成功。

再看 **M 审批**：`can_approve()` 检查 `role == "finance"`，真实执行 `submitted→approved`，并新增一条 `claim-approved` 历史。重复审批返回 `409`、状态不变、历史不重复。它与旧工单“重复关闭返回 `200` 但不变”的约定不同，所以不能把 `200` 本身当成写入证据。

`GET /claims/601` 是字段级授权的例子：`can_read_claim()` 允许共享者 A 看摘要；`can_read_private_details()` 不允许他看 `payee_id`，所以 `ClaimOut` 显式把它置为 `None`。`GET /claims/601/history` 直接拒绝，不能让共享权限意外传播到另一条路由。

### 四个 Python 写法，你要能自己解释

- `sqlite3.Row`：让查询行按 `claim["owner_id"]` 取字段，不必记“第几列”。
- SQL `?`：把申请 ID、收款标识作为参数传入；不要把用户提供的值拼进 SQL 字符串。只有固定的列名在测试辅助函数中由白名单选出。
- `with conn:`：在正常退出时提交事务，发生异常时回滚；**它不替你关闭连接**，所以路由在 `finally` 中 `conn.close()`。
- `TestClient(create_app(tmp_path / "expense.sqlite"))`：在同一进程调用真实 FastAPI 路由，测试间使用不同文件；`create_app` 时重置一次，普通 GET 不会重种数据。

FastAPI 官方测试文档：[Testing](https://fastapi.tiangolo.com/tutorial/testing/)；Python 官方 `sqlite3` 文档：[Connection context manager](https://docs.python.org/3/library/sqlite3.html#how-to-use-the-connection-context-manager)。

## 7. 可选：启动独立服务器，用 PowerShell 亲手发 HTTP 请求

专项测试已经会执行真实路由；这部分用于练习真实终端请求。第一个终端从项目目录启动：

```powershell
.\.venv\Scripts\python.exe -m uvicorn expense_app.main:app --host 127.0.0.1 --port 8001
```

第二个 PowerShell 终端进入项目目录，再运行：

```powershell
$base = 'http://127.0.0.1:8001'
$A = @{ Authorization = 'Bearer expense-token-a' }
$B = @{ Authorization = 'Bearer expense-token-b' }
$M = @{ Authorization = 'Bearer expense-token-m' }
$body = '{"new_payee_id":"payee-A"}'

Invoke-RestMethod -Uri "$base/claims/501" -Headers $B
Invoke-RestMethod -Uri "$base/claims/601" -Headers $A

try {
    Invoke-RestMethod -Uri "$base/claims/501" -Headers $A -ErrorAction Stop
} catch {
    [int]$_.Exception.Response.StatusCode
    $_.ErrorDetails.Message
}

try {
    Invoke-RestMethod -Method Post -Uri "$base/claims/501/change_payee" `
        -Headers $A -ContentType 'application/json' -Body $body -ErrorAction Stop
} catch {
    [int]$_.Exception.Response.StatusCode
    $_.ErrorDetails.Message
}

Invoke-RestMethod -Method Post -Uri "$base/claims/501/change_payee" `
    -Headers $B -ContentType 'application/json' -Body $body
Invoke-RestMethod -Uri "$base/claims/501" -Headers $B

Invoke-RestMethod -Method Post -Uri "$base/claims/501/approve" -Headers $M
Invoke-RestMethod -Uri "$base/claims/501" -Headers $B
```

第一个窗口用 `Ctrl+C` 停止服务器。启动 `expense_app.main:app` 会创建并重置专用的 `data/expense_manual.sqlite`；因此手工测试顺序按上面从未修改的初始数据开始，避免旧状态影响判断。`/docs` 可在 `http://127.0.0.1:8001/docs` 查看公开接口，但 OpenAPI 页面显示的 `200` Schema 不是实际鉴权结果；带身份发请求才有证据。若 8001 端口已占用，改为未占用的本机端口并同步修改 `$base`。

## 8. 三个可检验的练习

**练习 A：先预测再运行。** A 对共享申请 601 发起摘要 GET、历史 GET、改收款人 POST，分别是什么状态？预期：`200`（但收款字段为 `null`）、`403`、`403` 且 `payee_id` 不变。

**练习 B：说明不同权限。** B 是 501 的主人，能改提交中的收款标识，但不能批准；M 能批准，却不能改收款标识。试着指出 `expense_app/permissions.py` 中分别是哪两个函数，不要只背状态码。

**练习 C：预测哪个测试失败。** 如果暂时在自己的编辑器里去掉 `can_read_claim()` 中的 `claim["shared_with_id"] == user.id`，那么 `test_shared_reader_sees_summary_but_not_payee_or_history` 对摘要的 `200` 断言会失败，实际得到 `403`。看完后用编辑器**撤销这一行改动**，用 `git diff -- expense_app/permissions.py` 核对，再运行专项测试恢复全部通过。不要改已冻结的旧项目文件。

## 9. 留下本地提交并准备下一步

把“我原先以为共享意味着什么、后来从哪条测试发现只共享摘要”以及一次写入前后值，追加到你自己的 `research/V3_WEEKLY_LOG.md`，不要覆盖第一阶段记录。然后：

```powershell
git status --short
git add expense_app/__init__.py expense_app/db.py expense_app/auth.py `
        expense_app/permissions.py expense_app/main.py expense_app/demo.py `
        tests/test_expense_permissions.py research/WEEK2_EXPENSE_WALKTHROUGH.md
git diff --cached --stat
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw '暂存内容检查失败' }
git commit -m "Add independent expense authorization lab"
git status --short
```

若你追加了 `V3_WEEKLY_LOG.md` 并希望同次提交，先审查差异，再**明确追加该文件**；上面默认只提交这八个新文件。**完成标准**：能按权限表解释四条路由；23 项专项和全项目测试通过；`expense_app.demo` 的状态对照正确；明白新应用此时还不是 Agent 的工具目标。下一阶段才做新案例对与跨应用工具适配。
