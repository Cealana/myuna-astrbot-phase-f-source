# Owner Memory Retrieval v2 Candidate

状态：`isolated_candidate`  
日期：`2026-07-21`  
策略版本：`owner-memory-retrieval-v2-deterministic-zh-candidate`

这是对 v1 检索链的独立重建，不是在线热修复。当前目录没有安装到
`/opt/myuna`，没有修改正式 Core，没有创建或启用 systemd 服务，没有连接 QQ，
没有写入记忆，也没有调用本地或云端模型。

## 为什么新建 v2

真实 QQ 测试暴露了两个相互独立的失败：

1. 长自然问句虽然进入 `deep`，但整句词法覆盖率被对话性文字稀释，返回空结果。
2. 缩短后的同义问句可以匹配 M001，却被 Core 判为 `recent`，在排名前被 3 天窗口过滤。

v1 还让 Core 预先选择模式、Worker 再执行排名，责任分散且难以定位。因此 v2
将检索规划收拢到独立检索服务，并按单一职责拆分。

## 组件

- `concepts.py`：中文概念词典、规范化与安全概念标签。
- `planner.py`：只决定意图、时间范围和安全计划，不做排名。
- `boundary.py`：只执行 namespace、敏感度、确认状态和时间边界。
- `scoring.py`：只计算字段级证据和候选分数。
- `diversity.py`：只处理深度检索中的近重复候选。
- `selection.py`：编排各组件、应用阈值与最多 1/3 条限制。
- `protocol.py`：定义 v2 Unix Socket 请求/响应合同；Core 不再传入 `mode`。
- `core_adapter.py`：Core 侧响应验证与 Prompt 上下文投影，不执行检索。

详细关系见 [ARCHITECTURE.md](ARCHITECTURE.md)，安全边界见
[SECURITY.md](SECURITY.md)。

## 当前验证结果

- 合成、协议与 Core 适配测试：`26/26`。
- 当前真实非 restricted 安全视图：`21/21`。
- 两条真实失败问句现在均以 M001 为第一名。
- 五类反向用例均为空结果：未知钥匙位置、未记录原话、未记录原因、命令式“记得”、
  运维端口问题。
- 模型调用：`false`。
- 记忆写入：`false`。
- restricted 包含：`false`。
- 查询正文和记忆正文输出：`false`。

## 运行测试

```bash
PYTHONPATH=./src python3 -m unittest discover -s tests -v
```

真实只读回归只能以现有只读运行用户执行：

```bash
runuser -u myuna_memory_runtime -- \
  env PYTHONPATH=/opt/myuna/owner-memory-read-v1 \
  python3 evaluate_live_safe.py
```

该命令只输出用例 ID、记忆 ID、分数和安全原因码，不输出正文。

## 当前禁止事项

- 不得直接覆盖 v1 Worker。
- 不得修改现有 `/etc/myuna/qq.env`。
- 不得将候选接入正式 QQ Core。
- 不得把 restricted 记忆加入回归视图。
- 不得为了提高命中率取消确认、namespace 或敏感度边界。
- 不得让 Core 与 Worker 同时保留两份模式分类逻辑。
