# Myuna Core

Myuna Core 是模型无关的运行骨架。当前版本提供配置校验、健康状态、只读状态接口、模型路由占位、脱敏审计，以及逐阶段验收的长期记忆契约。

它仍然不加载正式人格、不调用云模型、不写入真实长期记忆，也不拥有工具执行权限。

## 当前安全状态

- Definition：未激活。
- Providers：未配置。
- PostgreSQL / pgvector：已在独立 dev 数据库中使用 synthetic 数据验证，Core 不持有数据库权限。
- Embedding：固定本地 CPU worker 已通过 synthetic 检索验证，不是聊天模型。
- 记忆数据：仅有明确标记为虚构的中文 JSONL 测试集。
- `/healthz`：进程存活时返回 200。
- `/readyz`：在 Definition 与 Provider 都未批准前返回 503，这是预期行为。
- `/v1/status`：只返回非敏感状态。
- 监听：强制为 loopback；外部监听需要后续 ADR 和防火墙审查。

## Memory Stage 0

Stage 0 先固定边界和升级契约，不提前选择不可逆的实现：

- `memory/models.py`：带 schema 版本、来源、时区、时间精度、状态和修订关系的数据模型。
- `memory/interfaces.py`：存储、归档、检索、embedding、迁移、隐私控制等可替换协议。
- `memory/policy.py`：确定性的记忆准入策略，不调用模型。
- `memory/in_memory.py`：只供测试/开发使用的非持久化、追加式存储。
- `memory/retrieval.py`：带硬过滤、中文字符二元组和可解释 trace 的确定性检索。
- `memory/migrations.py`：纯 payload schema 迁移；不包含数据库迁移。
- `memory/evaluation.py`：只读取合成数据的策略与检索评测工具。

详细契约见 [`docs/memory-stage0-contract.md`](docs/memory-stage0-contract.md)。

## Memory Stage 5

Stage 5 增加 Core 到 synthetic retrieval worker 的严格 Unix Socket 适配器和元数据审计桥：

- `memory/worker_adapter.py`：响应校验、typed error、模式/降级约束和查询指纹。
- `docs/memory-stage5-adapter-contract.md`：允许/禁止字段与激活边界。
- `scripts/run_stage5_retrieval_smoke.py`：只使用固定 synthetic 查询的集成验证。

该适配器不会接入当前 HTTP POST 路径；Core 与 worker 在验收后仍保持 disabled/inactive。
查询正文、记忆正文和完整 trace 不进入 Core 审计。

## 本地测试

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -v
```

## 临时运行

```bash
set -a
. /etc/myuna/dev.env
set +a
PYTHONPATH=src python3 -m myuna_core
```

此仓库不保存 `.env`、API 密钥、真实用户记忆或 Myuna 原始设定包。
