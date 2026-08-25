# Myuna Phase 7：OpenClaw 控制面与恢复层计划

状态：`PROPOSED_DEFERRED`
记录日期：2026-07-20（Asia/Taipei）
Owner：Cealana
计划阶段：Phase 7
当前授权：仅记录、评审和保留；**未授权安装、接入、启用或开放网络**
建议规范编号：`OPENCLAW-CONTROL-PLANE-v0`

## 0. 文档用途与效力

本文件是 Owner 提出的 OpenClaw 集成方案的本地、可版本化需求基线，用于避免长对话压缩、任务切换或未来交接造成细节丢失。

它当前具有以下效力：

- 记录 Phase 7 的目标、边界、接口、风险模型、实施顺序和验收条件；
- 约束未来设计不得让 OpenClaw 取代 Myuna 或成为 Codex 的默认中间层；
- 约束未来 Telegram、Control UI 等新入口不得继承 QQ Owner 权限；
- 约束未来实施必须先审查当时的仓库与实际安装版本；
- 明确当前没有任何部署授权。

它当前不代表：

- 已经审查完 Myuna 全部代码；
- 已经确认 OpenClaw 的具体版本、配置格式或 API；
- 已经选择最终部署拓扑；
- 已经创建账号、Token、系统用户或服务；
- 已经开放 Telegram、端口、Shell、sudo、Docker socket 或外部工具；
- 已经批准 OpenClaw 读取 Myuna 记忆、数据库或 Secret；
- QQ 当前离线是提前部署 OpenClaw 的理由。

Phase 7 真正开始时，必须重新读取本文件、最新服务器状态、最新仓库和届时 OpenClaw 官方文档；发现冲突时提交 ADR，不得静默偏离。

## 1. 核心结论

### 1.1 角色分工

- **Myuna**：中央协调、策略、调度与权威任务状态；决定为什么做、何时做、谁来做、是否允许做。
- **Codex**：软件工程执行层；修改代码、调试、测试、审查，并在受控工作目录中完成工程任务。
- **OpenClaw**：系统操作、远程通信、外部工具连接、人工审批入口与有限恢复控制面。
- **Owner**：查看状态、提交请求、批准高风险操作，并在 Myuna 故障时调用有限恢复 Playbook。

### 1.2 不允许改变的主链路

Myuna 继续直接控制 Codex：

```text
Myuna → CodexAdapter → Codex
```

不得默认改为：

```text
Myuna → OpenClaw → Codex
```

OpenClaw 只可参与消息入口、系统操作和结果回传。例如：

```text
Owner Telegram message
→ cealana-remote
→ Myuna
→ CodexAdapter
→ Codex
→ Myuna
→ cealana-remote
→ Owner
```

### 1.3 OpenClaw 的恢复定位

OpenClaw 是 Myuna 之外的额外控制保险。恢复路径不得依赖 Myuna 主进程正常运行，但也不得提供常开任意 root Shell。

可恢复的典型范围：

- Myuna 主进程崩溃或无响应；
- Worker 卡死；
- 明确依赖服务异常；
- 已知配置更新导致启动失败；
- Codex 调用链故障；
- 需要收集受限诊断信息。

不能解决的共同故障：

- 主机断电；
- 家庭网络完全中断；
- Windows 主机死机；
- 整个存储设备失效；
- 同主机 Tailscale 与 Telegram 网络同时不可用。

这些情况需要真正的带外管理、第二节点或现场操作，OpenClaw 不能伪装成 BMC/IPMI。

## 2. 目标逻辑架构

```text
Owner
├─ Telegram private chat
├─ Control UI over Tailscale
└─ Tailscale + RDP / Chrome Remote Desktop (human fallback)
        │
        ▼
OpenClaw Control Plane
├─ cealana-remote
│  ├─ DeepSeek-backed low-risk conversation
│  ├─ status/query interface
│  ├─ task submission to Myuna
│  ├─ notification and approval interface
│  └─ limited recovery playbooks when Myuna is unavailable
│
└─ myuna-ops
   ├─ private machine-to-machine identity
   ├─ structured host/service operations
   ├─ restricted and redacted logs
   ├─ remote-node calls
   └─ structured results only

Myuna
├─ CodexAdapter
├─ OpenClawAdapter
├─ Policy Engine
├─ Approval Manager
├─ Task Store (authoritative)
└─ Audit Log
```

## 3. 信任边界

### 3.1 `cealana-remote`

面向 Owner 的远程入口，默认低权限。

允许：

- 查询经过筛选的 Myuna 与主机状态；
- 向 Myuna 提交任务；
- 接收通知；
- 展示和提交与原始操作绑定的审批；
- 在 Myuna 不可用时执行允许进入 recovery mode 的固定 Playbook。

禁止：

- 任意 Shell、PowerShell 或 sudo；
- Docker socket；
- SSH 私钥；
- 浏览器 Cookie；
- 任意读取 Myuna 数据库或记忆；
- 修改自己的策略、allowlist 或审批规则；
- 直接调用 Codex；
- 继承 QQ/AstrBot Owner 绑定；
- 因聊天提示而临时扩权。

### 3.2 `myuna-ops`

只供 Myuna 内部调用，不绑定公开聊天或群聊。

允许：

- 结构化系统状态；
- 固定运维 Playbook；
- allowlist 内的服务控制；
- 有界、脱敏日志；
- 经批准的远程节点操作。

禁止：

- 高级规划或取代 Myuna 调度；
- 保存 Myuna 的权威任务 DAG；
- 直接控制 Codex；
- 无审批高风险操作；
- 任意访问 Myuna 源码、数据库或 Secret。

### 3.3 身份隔离

两个 Agent 必须具备不同的：

- principal / actor identity；
- 配置目录；
- Secret；
- 工具 allowlist；
- 会话存储；
- 审计身份；
- 速率限制；
- 撤销和轮换路径。

Telegram principal 必须重新完成独立身份绑定。即使显示名或消息内容声称自己是 Cealana，也不得继承 QQ Owner principal。

## 4. 推荐部署隔离

Phase 7 的首选方案：

```text
Windows 11 host
├─ Tailscale / RDP / Chrome Remote Desktop
├─ optional minimal Windows host bridge
│  └─ fixed allowlisted Windows/WSL playbooks only
│
├─ Server-Ubuntu WSL2
│  └─ Myuna, database, Minecraft and current services
│
└─ OpenClaw-Control WSL2 (recommended)
   ├─ cealana-remote service account
   ├─ myuna-ops service account
   ├─ OpenClaw gateway bound to loopback/Tailscale only
   └─ independent audit and recovery state
```

推荐顺序：

1. 独立轻量 VM 或独立 WSL distro；
2. 同一主机、独立系统用户/服务/目录；
3. 同一用户与运行环境仅作为临时开发方案。

单独 WSL distro 的收益：

- Myuna Python/Node 依赖损坏不直接破坏 OpenClaw；
- 凭证、进程、目录与启动关系更清晰；
- OpenClaw 不需要获得 Server-Ubuntu 的广泛文件权限；
- 可独立备份、导出、升级和回滚。

局限：

- 两个 distro 仍共享 Windows 主机和物理网络；
- 从 OpenClaw-Control 操作 Server-Ubuntu 需要一个最小权限桥接层；
- WSL 整体无法启动时，Linux 内恢复面仍不可用；
- Windows 级故障可能需要 Windows 服务、计划任务或第二节点。

不得为了方便直接挂载 Docker socket、整个 `/srv/myuna`、整个 Windows 用户目录或管理员凭证。

## 5. `OpenClawAdapter` 合同

实际模块位置必须在 Phase 7 仓库审查后决定，不能现在硬编码。建议公开能力：

```text
health_check
get_host_status
get_service_status
read_service_logs
run_operation
run_playbook
get_operation_status
cancel_operation
send_notification
request_approval
```

### 5.1 请求 Schema

```text
OpenClawOperationRequest
├─ request_id
├─ correlation_id
├─ idempotency_key
├─ parent_request_id
├─ origin
├─ actor
├─ hop_count
├─ operation
├─ target
├─ arguments
├─ risk_level
├─ timeout_seconds
├─ requires_approval
├─ reason
└─ created_at
```

建议约束：

- ID 使用不可预测、可追踪的稳定格式；
- `origin` 为枚举，不接受任意自然语言；
- `actor` 引用已验证 principal；
- `arguments` 按 operation 使用不同强类型 Schema；
- `risk_level` 由服务端 Catalog 决定，调用方不能降低；
- `requires_approval` 由 Policy Engine 最终决定；
- `timeout_seconds` 受 Catalog 最大值约束；
- `hop_count` 超限立即拒绝；
- 同一危险操作的 `idempotency_key` 不得重复执行。

### 5.2 响应 Schema

```text
OpenClawOperationResult
├─ request_id
├─ operation_id
├─ status
├─ success
├─ started_at
├─ finished_at
├─ exit_code
├─ summary
├─ structured_data
├─ stdout_excerpt
├─ stderr_excerpt
├─ truncated
├─ approval_status
├─ audit_reference
└─ error
```

`stdout_excerpt` 与 `stderr_excerpt` 只允许保存经过脱敏和大小限制的摘录。正常逻辑应使用 `structured_data`，不得依赖解析自然语言。

### 5.3 错误类型

至少区分：

- `OpenClawUnavailableError`
- `OperationNotAllowedError`
- `InvalidOperationArgumentsError`
- `ApprovalRequiredError`
- `ApprovalDeniedError`
- `ApprovalExpiredError`
- `IdempotencyConflictError`
- `OperationTimeoutError`
- `OperationCancelledError`
- `OutputLimitExceededError`
- `HopLimitExceededError`
- `RecoveryModeViolationError`
- `RemoteNodeUnavailableError`
- `PartialOperationError`

不得吞掉异常或把所有错误压成一个字符串。

## 6. Operation Catalog

每个 Operation 必须声明：

- operation name；
- allowed targets；
- arguments schema；
- risk level；
- allowed actors；
- approval policy；
- maximum timeout；
- maximum output；
- cancellation support；
- recovery-mode eligibility；
- exact underlying executable/playbook；
- redaction rules；
- audit fields；
- idempotency behavior；
- rollback/verification method。

### 6.1 MVP 只读操作

| Operation | 默认风险 | 说明 |
|---|---:|---|
| `myuna.health` | L0 | 结构化健康检查 |
| `myuna.status` | L0 | 版本、状态与受限依赖摘要 |
| `myuna.recent_logs` | L0 | 有界、脱敏日志 |
| `worker.list` | L0 | 列出公开 Worker 状态 |
| `worker.status` | L0 | 单个 Worker 状态 |
| `host.metrics` | L0 | CPU、内存、负载摘要 |
| `disk.usage` | L0 | allowlist 卷和目录用量 |
| `port.inspect` | L0 | 指定 allowlist 端口状态 |
| `service.status` | L0 | allowlist 服务状态 |

### 6.2 MVP 有限写操作

| Operation | 默认风险 | 说明 |
|---|---:|---|
| `worker.restart` | L1/L2 | 是否有状态决定风险 |
| `myuna.restart` | L2 | 需要显式审批 |
| `service.restart` | L2 | 仅 allowlist 目标 |

### 6.3 Recovery Playbooks

- `recovery.check_myuna`
- `recovery.collect_diagnostics`
- `recovery.restart_myuna`
- `recovery.verify_myuna`
- `recovery.rollback_last_known_good_config`

配置回滚必须：

1. 验证备份存在；
2. 验证目标 ID 与 checksum；
3. 验证配置格式；
4. 展示影响和目标；
5. 获得绑定到 operation ID 的审批；
6. 回滚前备份当前配置；
7. 原子切换；
8. 运行健康检查；
9. 失败时保留诊断并按固定规则恢复或停止；
10. 通知 Owner 并返回 audit ID。

## 7. 风险等级与确定性策略

### Level 0：只读

可自动执行，但仍需要身份验证、速率限制、目标 allowlist、输出限制与审计。

### Level 1：低风险、范围明确

例如无状态 Worker 重启、固定健康检查、明确可重试任务、受控临时目录清理。可由 Policy 自动批准，也可根据来源要求确认。

### Level 2：有状态或服务影响

必须显式审批，例如重启 Myuna/Minecraft、停止服务、配置回滚、备份恢复、取消任务。

### Level 3：高风险管理操作

需要强审批、短有效期与更严格的执行主体，例如防火墙、软件安装删除、用户权限、数据库变更、Windows 重启、网络设置、OpenClaw/Myuna 核心环境升级。

### Forbidden：始终禁止

- 输出或读取 API key、Token、Cookie、私钥；
- 关闭审计；
- 绕过审批；
- 修改自身权限策略；
- 创建反向 Shell；
- 暴露公网管理端口；
- 未授权任意 root 脚本；
- 读取与任务无关的私人目录；
- 将完整环境变量交给模型；
- 通过自然语言把 Forbidden 降级为允许。

真正的权限判断必须由确定性的 Policy Engine/执行层完成，模型只可以提出请求，不可以授予权限。

## 8. 审批合同

每次审批至少包含：

- `approval_id`
- `operation_id`
- `request_digest`
- actor 与 target
- operation 与参数摘要
- 风险等级
- 原因与影响
- 可验证回滚方式
- 创建时间与过期时间
- 一次性 nonce
- 批准 principal
- 批准结果与时间

规则：

- 审批只绑定一份不可变请求摘要；
- 参数变化必须重新审批；
- 审批不能复用；
- 审批过期后 fail-closed；
- 同一聊天中的“可以”“继续”不能脱离 operation ID 自动套用；
- OpenClaw/Myuna/模型不得替 Owner 自行批准；
- recovery mode 也不绕过审批，只允许缩小可用操作集。

## 9. 幂等、重试、取消与长任务

- L2/L3 操作必须先在持久化 idempotency ledger 中登记；
- 同一 `idempotency_key` 与同一请求摘要返回原操作状态，不重复执行；
- 同一 key 对应不同摘要时拒绝；
- 网络重试不得等于操作重做；
- 只对 Catalog 标记为 retry-safe 的步骤自动重试；
- 长任务返回 `operation_id`，由状态查询或事件流更新；
- 支持取消的操作必须定义安全取消点；
- 部分成功必须逐步列出，不得伪装成成功或全失败；
- Myuna 重启后可根据 ledger 恢复查询，不得重复执行危险操作；
- 熔断时允许只读健康查询和恢复 Playbook，禁止普通写操作。

## 10. 防止 Agent 循环

每个请求必须包含：

- `origin`
- `actor`
- `correlation_id`
- `parent_request_id`
- `hop_count`
- `route_trace`

建议默认最大 hop 数为 4，具体值在测试后确定。

规则：

- 来源为 Myuna 的 OpenClaw 操作不得重新提交回 Myuna；
- Owner 经 OpenClaw 提交给 Myuna 后，OpenClaw 只展示状态、通知、审批和结果；
- OpenClaw 不复制 Myuna 的任务 DAG、长期记忆或权威状态；
- 同一 `correlation_id + operation + target` 的活动调用不得递归；
- 超限或检测到回环时 fail-closed 并审计。

## 11. 审计与脱敏

每次操作记录：

- 发起者和 principal；
- 渠道；
- user/Myuna/recovery mode 来源；
- operation、target 和参数摘要；
- 风险等级；
- Policy 决策；
- 审批请求、批准者和时间；
- 实际执行 playbook/版本；
- 开始、结束与耗时；
- 返回码；
- 结构化摘要；
- 截断标记；
- 重试次数；
- 最终状态；
- task/correlation/audit ID。

必须脱敏：

- API key；
- Token；
- Cookie；
- Authorization header；
- 数据库密码；
- 私钥；
- Secret 环境变量；
- URL 敏感查询参数；
- 二维码和登录凭据。

日志读取必须有最大行数、最大字符数、时间范围、服务范围、关键词规则、脱敏和截断标记。不得把完整大型日志直接发送给模型。

## 12. 远程接入安全

OpenClaw Gateway 默认：

- bind loopback；
- 经 Tailscale 或 SSH Tunnel 访问；
- 不做无保护公网端口转发；
- 强身份验证；
- principal allowlist；
- Token 轮换；
- 请求速率限制；
- 审批过期；
- 完整审计；
- 敏感字段脱敏。

Telegram：

- 仅允许明确 user ID；
- 默认禁止群聊；
- 如未来开放群聊，必须独立 group allowlist、命令 allowlist 与权限；
- 未知用户静默忽略或返回不泄露信息的拒绝；
- 高风险审批展示目标、影响、原因和过期时间；
- 审批绑定原始 operation ID 且一次性；
- 完成后只返回结果摘要和 audit ID；
- Telegram Bot Token 与 DeepSeek key 不进入仓库、Prompt 或审计正文。

## 13. Secret 与配置

未来至少配置：

```text
DEEPSEEK_API_KEY
DEEPSEEK_BASE_URL
DEEPSEEK_MODEL
OPENCLAW_GATEWAY_BASE_URL
OPENCLAW_MYUNA_OPS_CREDENTIAL
OPENCLAW_REMOTE_CREDENTIAL
TELEGRAM_BOT_TOKEN
TELEGRAM_OWNER_USER_ID
```

名称只是环境抽象建议，最终以实际 OpenClaw 版本和仓库配置系统为准。

要求：

- Secret Store 或 systemd credentials；
- 示例配置只留空值或 credential name；
- 不在 Git、日志、Prompt、错误或诊断包中保存值；
- 两个 Agent 不共用 Token；
- Myuna 与 OpenClaw 使用专用最小 Scope 凭证；
- 轮换不要求重建整个系统；
- Secret metadata 与 Secret value 分离。

## 14. Break-glass Shell

MVP 不实现任意 Shell。

若未来确有需要，必须同时满足：

- 默认关闭；
- 仅明确管理员 principal；
- 强确认与独立审批；
- 短有效期；
- 受限工作目录/容器/沙箱；
- 命令和输出完整审计并脱敏；
- 普通聊天提示不能启用；
- 模型不能修改审批策略；
- 禁止读取 Secret；
- 到期自动关闭；
- 不允许持久化成常开状态。

在这些条件没有通过专门安全评审前，`execute_command`、`run_shell`、`sudo`、`run_powershell` 均为 Forbidden API。

## 15. Phase 7 开始前的仓库审查

必须先确认，而不是根据本文件猜测：

1. Myuna 当前入口；
2. Planner/Dispatcher/Reviewer/Scheduler 的真实实现；
3. Worker 生命周期与任务状态；
4. CodexAdapter 或等价调用链；
5. 配置加载与版本化；
6. 数据库、Task Store、idempotency 与迁移；
7. 日志、审计和脱敏；
8. principal、权限和审批实现；
9. API、socket、消息总线和 channel envelope；
10. 测试目录、fixture 与 fake provider；
11. systemd、Windows、WSL 与容器部署；
12. 当前 QQ/AstrBot、未来 Discord 与 Telegram 的身份隔离；
13. 当前控制 Codex 的确切实现；
14. 当时 OpenClaw 的实际安装版本和官方文档；
15. 现有组件中哪些可复用、哪些必须新增。

审查产出至少包括：

- repository map；
- runtime dependency map；
- trust-boundary diagram；
- reusable components list；
- gap analysis；
- ADR draft；
- no-write Phase 7 implementation plan。

## 16. 实施阶段

### Stage 7.0：只读审查

不安装、不联网、不写 Secret。输出当前架构总结、差距、组件图、信任边界与实施提案。

### Stage 7.1：仓库内合同与 Fake

1. `OpenClawAdapter` interface；
2. Mock/Fake implementation；
3. Operation/Result strong schemas；
4. error types；
5. deterministic Policy checks；
6. audit/redaction utilities；
7. idempotency ledger abstraction；
8. unit tests。

不连接真实 OpenClaw。

### Stage 7.2：真实客户端（仍隔离）

- 版本隔离的 OpenClaw client；
- loopback-only test endpoint；
- timeout、cancel、retry、circuit breaker；
- fake credentials；
- integration tests；
- 不连接 Telegram，不启用系统写操作。

### Stage 7.3：只读 MVP

只启用 L0 operations，使用 synthetic/isolated targets。验证日志边界、速率限制、身份、hop limit 与不可用降级。

### Stage 7.4：恢复 Playbook 候选

实现固定脚本、allowlist、审批、原子回滚和诊断包；先用 fake services 验证，随后才能请求真实服务 gate。

### Stage 7.5：`myuna-ops` dev gate

仅 Myuna dev principal、loopback/Tailscale 内部路径、无公开聊天。逐项启用 operation。

### Stage 7.6：`cealana-remote` dev gate

独立 Telegram principal challenge、只读查询和通知优先；恢复 Playbook 另行 gate。

### Stage 7.7：生产提升

必须有备份、回滚、Golden/integration tests、Owner digest、短期观察与权限差异审计。不得一次性开放全部能力。

## 17. 测试矩阵

至少覆盖：

- 正常返回；
- OpenClaw 不可用；
- 连接超时和执行超时；
- 重复 idempotency key；
- 相同 key 不同请求；
- 审批通过、拒绝、超时和重复使用；
- Forbidden operation；
- target 不在 allowlist；
- 参数 Schema 错误；
- 输出截断；
- 敏感信息脱敏；
- Myuna 来源不会被重新提交给 Myuna；
- hop count 超限；
- 回环检测；
- Myuna 不可用时允许 recovery Playbook；
- Myuna 不可用时禁止普通高风险操作；
- recovery mode 过期；
- DeepSeek key、Telegram token 和 Authorization 不出现在日志；
- `cealana-remote` 无权调用 `myuna-ops` 高权限工具；
- 网络断开后的状态恢复；
- Myuna/OpenClaw 重启后不重复执行；
- 长任务状态和取消；
- 部分成功；
- 熔断与降级；
- 配置回滚成功与失败回滚；
- 日志行数、字符数、时间窗和服务范围限制。

## 18. 文档交付物

Phase 7 实施至少产生：

- architecture document；
- configuration guide；
- permission model；
- Operation Catalog；
- Recovery Playbook；
- deployment guide；
- daily operations；
- troubleshooting；
- rollback guide；
- security notes；
- example config；
- version compatibility record；
- threat model；
- test/acceptance report。

文件位置应遵循届时仓库规范；若没有规范，可考虑：

```text
docs/architecture/openclaw-control-plane.md
docs/runbooks/openclaw-recovery.md
config/openclaw.example.*
```

## 19. 示例流程

### 19.1 Telegram 查询状态

```text
Owner → cealana-remote: “查看 Myuna 状态”
cealana-remote authenticates Telegram principal
→ operation: myuna.status (L0)
→ Policy allow
→ structured status query
→ redacted summary + audit ID
→ Owner
```

### 19.2 Myuna 重启 Worker

```text
Myuna
→ OpenClawAdapter.run_operation(worker.restart, target=allowlisted-worker)
→ myuna-ops validates Myuna principal and request digest
→ Policy decides L1/L2
→ approval if required
→ fixed worker restart playbook
→ post-health verification
→ structured result + audit ID
→ Myuna Task Store
```

OpenClaw 不得把该请求再次提交给 Myuna。

### 19.3 Myuna 故障恢复

```text
Owner → cealana-remote
→ recovery.check_myuna
→ detects Myuna unavailable
→ enters bounded recovery mode
→ Owner selects recovery.restart_myuna
→ explicit approval bound to operation ID
→ fixed allowlisted restart playbook
→ recovery.verify_myuna
→ summary + audit ID → Owner
```

如果重启失败，可提出 `recovery.collect_diagnostics`；不得自动升级为任意 Shell。

## 20. 需要在 Phase 7 再决定的问题

- OpenClaw 的实际版本、许可证和稳定 API；
- 独立 WSL distro、轻量 VM 或第二节点的最终选择；
- Windows host bridge 的实现和最小权限；
- Telegram 与 Control UI 是否同时首发；
- DeepSeek 在 `cealana-remote` 中的模型、预算和降级；
- Myuna/OpenClaw 双方认证协议；
- 审批签名、nonce 和过期实现；
- operation ledger 使用 Myuna DB、OpenClaw 独立 DB 或双方引用；
- 审计日志长期保留和备份；
- L1 的自动批准范围；
- recovery mode 的触发、退出和最长时间；
- Minecraft 是否进入首批写操作；
- Discord 何时作为独立备用渠道评审；
- 真正带外管理或第二节点的长期计划。

## 21. 当前明确禁止的动作

在新的 Phase 7 Owner 批准前，不得：

- 安装 OpenClaw；
- 创建 `cealana-remote` 或 `myuna-ops` 真实账号/Agent；
- 创建 Telegram Bot 或写入 Bot Token；
- 写入 DeepSeek/OpenClaw Secret；
- 创建系统用户、sudoers、systemd 服务或 Windows 计划任务；
- 开放端口或配置公网转发；
- 修改 Myuna/Codex 现有调用链；
- 接入 QQ、Discord、Telegram 或 Control UI；
- 授予 Docker socket、SSH key、数据库或记忆访问；
- 启用任意 Shell；
- 实施恢复 Playbook；
- 以本文件为由自动执行任何系统变更。

## 22. Phase 7 MVP 验收条件

- Myuna 仍是任务与策略唯一事实来源；
- Myuna 继续直接控制 Codex；
- 两个 OpenClaw Agent 身份、凭证、工具和审计隔离；
- 无任意 Shell；
- 所有真实操作来自 Catalog 和固定 Playbook；
- Policy 为确定性执行层，而非 Prompt；
- L2/L3 审批可验证、一次性、过期、不可复用；
- 危险操作幂等；
- 回环与 hop limit 生效；
- 敏感值不进入日志、Prompt、审计或诊断包；
- Gateway 不直接暴露公网；
- Myuna 故障时基础恢复不依赖 Myuna；
- OpenClaw 故障不阻止 Myuna 正常使用 Codex；
- 回滚和禁用 OpenClaw 不需要重写 Myuna 核心；
- 单元、集成、安全和恢复演练全部通过；
- 真实启用前有独立 Owner plan digest。

## 23. 变更与升级规则

- 本文档后续修改通过新版本或 Git commit 记录；
- 架构边界变化需要 ADR；
- Phase 7 开始时从 `v0` 形成经仓库审查的 `v1 candidate`；
- 任何实现不得直接覆盖本文件表达的 Owner intent；
- 若实际 OpenClaw 能力与设想不同，记录差异和替代方案，由 Owner 选择；
- “未来计划”永远不等于“当前授权”。
