# V3 每周记录

## 第 1 周：协议与写操作机制复核

### 已由本轮工作核对的材料

- 来源：你本轮上传的 `api-auth-agent-eval.zip` 的解压副本（它不是对你 Windows D 盘的实时访问）。该副本运行 `pytest -q`：**155 passed**；运行 `python -m research.audit`：`applications=1`、`independent_pairs=6`、`dev=2`、`pilot_formal=4`。
- P03 在独立临时库重播：漏洞版 A 独立请求 `open→closed`，修复版 A `403` 且 `open→open`；漏洞版 B 先写后 A 请求是 `open→closed`，随后 `closed→closed`。
- P05 在独立临时库重播：漏洞版 A 独立请求 `B→A`，修复版 A `403` 且 `B→B`；漏洞版 B 先写后 A 请求是 `B→A`，随后 `A→A`。**B 对转派本来没有权限**。
- 协议文件：`research/WRITE_ORDER_V3_PROTOCOL.md`。本周没有在新评估集上运行模型，没有修改旧提示或旧结果。

### 请在你自己的 Windows 项目里执行后填写

- 日期与本机 Git 分支 / 提交：**待本机核对**。
- 本机 `python -m pytest -q` 测试数量与失败：**待本机核对**。
- 本机 `python -m research.audit`：**待本机核对**。
- 本机 `python -m research.replay_write_preemption` 六行输出是否相同：**待本机核对**。
- 本地 Git 提交编号：**待本机核对**。

### 自己写，不用 AI 代答

1. 我原先把 `200` 或谁先写当成了什么？现在怎样用状态变化纠正：
2. P03 中 B 合法关闭与 P05 中 B 未授权转派有什么关键区别：
3. A 版和 B 版唯一计划差异；什么条件必须相同：
4. 我如何证明一次 A 的写入确实改变了数据，而不是重复写同一个值：
5. 一个还不理解的 `TestClient`、数据库事务或证据评分问题，以及我找到的答案和出处：

### 第二周开始前

费用申请应用、V3 新案例、V3 提示和正式分数**尚未创建**。先完成上面的本机复核与口述，再实现新应用；不要把旧项目的 P03/P05 当作新的盲测结果。
