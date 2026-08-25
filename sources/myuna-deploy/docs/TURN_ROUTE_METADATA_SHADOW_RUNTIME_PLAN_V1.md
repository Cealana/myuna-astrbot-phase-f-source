# Turn/Route metadata-only Shadow v1 真实运行方案

状态：候选运行方案；未安装、未激活、无生产影响  
日期：2026-07-20  
适用范围：已验证 Owner QQ 私聊运行链

## 1. 结论

下一步只建议把已经通过离线验收的 `Hybrid Turn/Route Classifier v1`
接成一个**回复完成后的纯元数据观察器**。它可以记录“如果以后启用 Turn
Manager/Model Router，它会怎样建议”，但当前 QQ 回复仍完整走原有链路。

本方案明确不包含：

- 静默、延迟、合并或取消真实 QQ 回复；
- 30 秒至数分钟的 Temporal Buffer；
- 切换 DeepSeek Flash、DeepSeek Pro、OpenAI 或本地模型；
- 将本地模型输出送回 Core；
- 读取或写入 Owner Memory、History Archive 或 Prompt；
- 调用工具、审批操作或产生外部副作用；
- 自动登录 QQ、刷新二维码或恢复 NapCat；
- 让 Owner 为了观测而刻意维持 QQ 在线。

QQ 在线时可以积累有效样本；掉线时间不计入有效观测时间，也不视为
Classifier 失败。没有专项测试时，Owner 无需为掉线额外介入。

## 2. 已核对的现有链路

当前链路不是重新设计，而是在已有接缝上增加第二个独立观察器：

```text
NapCat / OneBot
  -> AstrBot myuna_gateway（抢占并禁止 AstrBot 自带 LLM）
  -> /run/myuna-gateway/qq-owner.sock
  -> qq_owner_runtime_gateway.py
  -> Myuna Core 127.0.0.1:18081
  -> DeepSeek 当前策略
  -> QQ 回复先返回并关闭连接
  -> 现有 Owner Memory Shadow best-effort enqueue
```

核对结果：

1. AstrBot 边界只转发已验证的纯文字私聊，并在进入 Gateway 前阻止 AstrBot
   自己调用模型。
2. QQ Runtime Gateway 会在 Core 成功回复后才形成 `ShadowJob`。
3. `serve_accepted_connection` 会先关闭回复连接，再尝试向现有 Memory Shadow
   投递；投递异常被吞掉，不会破坏回复。
4. Core 的响应已经包含 `provider`、`model` 和 `route_reason`，但 QQ Gateway
   目前只保留 `reply`。Route Shadow 如需比较真实路由，只应在 Gateway 内将
   这些字段映射成受限枚举，不应保存原始字段。
5. Qwen3.5-4B Q4_K_M 的 Windows llama.cpp Vulkan 隔离基准已经通过 Hybrid
   门槛，但目前没有常驻服务、开机启动项或生产接入。

## 3. 建议拓扑

```text
                         production reply path
QQ event -> Gateway -> Core ----------------------> QQ reply
                    |                                |
                    | reply connection closed       |
                    +--------------------------------+
                    |
                    +-> Memory Shadow（现有，互不依赖）
                    |
                    +-> Turn/Route Shadow datagram（新增，best effort）
                          -> deterministic rules
                          -> optional 4B advice on Windows loopback
                          -> metadata-only trace
```

两个 Shadow 必须各自在独立 `try` 块中投递。任意一个 Socket 不存在、队列已满、
Worker 崩溃或本地模型不可用时，只允许丢弃该次观察，不允许等待、重试或影响
另一个 Shadow。

## 4. 生产接缝

建议把现有单一 `ShadowJob` 扩展为内部 `PostReplyObservationJob`，仅在 Core
回复已经被 Gateway 接受时生成。它可以在进程内短暂包含：

```json
{
  "request_uuid": "random UUID",
  "query": "owner plaintext, transient only",
  "input_character_count": 42,
  "event_count": 1,
  "actual_route": "deepseek_default"
}
```

边界规则：

- `query` 只允许存在于 Gateway 内存、Unix datagram 和 Worker 内存；不得写入
  trace、journald、错误信息或模型服务日志。
- 不传递 QQ 号、account/principal/namespace、conversation ID、event ID、
  Prompt、回复文字、Memory 内容或任何 Credential。
- `request_uuid` 是本次观察新生成的随机 UUID，不复用渠道消息 ID。
- 当前每个已回复 QQ 事件的 `event_count` 固定为 `1`。消息合并属于未来的
  Temporal Buffer，不在本阶段伪装实现。

### 4.1 实际路由映射

Gateway 只把 Core 返回值映射为以下枚举：

```text
deepseek-v4-flash -> deepseek_default
deepseek-v4-pro   -> deepseek_pro
其他或缺失       -> unknown
```

映射后不得把原始 provider/model/route_reason 写入 Shadow trace。映射失败不能
拒绝一个已经生成的真实回复，必须降级为 `unknown`。

## 5. Shadow Worker

建议新增独立系统用户 `myuna_shadow_classifier`，没有 shell、没有 sudo、没有
数据库权限，也不属于 `myuna`、`myuna-gateway`、`docker` 或 Memory 相关组。

建议路径：

```text
/opt/myuna/turn-route-shadow-v1/                  root:root 0755
/etc/myuna-shadow/turn-route-shadow-v1.json       root:root 0640
/run/myuna-turn-route-shadow-dev/shadow.sock      Unix datagram
/var/log/myuna/turn-route-shadow/trace.jsonl      service-owned 0600
/etc/myuna-gateway/qq-owner-turn-route-shadow-v1-enabled
```

建议 systemd 防护：

- `NoNewPrivileges=yes`
- `ProtectSystem=strict`
- `ProtectHome=yes`
- `PrivateTmp=yes`
- `PrivateDevices=yes`
- `ProtectKernel*` / `ProtectControlGroups=yes`
- `CapabilityBoundingSet=`
- `RestrictAddressFamilies=AF_UNIX AF_INET`
- `IPAddressDeny=any`
- `IPAddressAllow=127.0.0.1/32`
- 仅允许写入 `/var/log/myuna/turn-route-shadow`
- 不提供任何 systemd Credential

Worker 行为：

1. 严格验证 datagram Schema 和最大 16 KiB 大小。
2. 先运行冻结的确定性规则。
3. 只有规则返回“需要模型判断”时，才尝试访问固定的本地 4B Endpoint。
4. Endpoint 不可用、超时、返回非法标签时使用既有保守 fallback：
   Turn=`B`，Route=`D`。
5. 生成两条互相独立的纯元数据记录：Turn 一条、Route 一条。
6. 清除本次明文引用；不建立聊天历史，不保留跨事件文本缓存。

## 6. Windows 本地 4B 服务边界

候选模型继续使用已固定并校验的：

```text
Qwen3.5-4B-Q4_K_M
SHA-256: 13c16f426047e2de38cd075bdade4a7bcbc8c774384876f677740cda65f8a983
llama.cpp: C:\Server-Tools\llama.cpp\b10068
model: D:\Playground\models\routing\Qwen3.5-4B\Qwen3.5-4B-Q4_K_M.gguf
endpoint: 127.0.0.1:18093
```

首轮真实 Shadow 建议仍不创建开机自启。模型服务可在明确测试窗口内单独启动；
未启动时 Worker 记录 `model_unavailable` 并采用 fallback，不影响 QQ。

启动参数至少要求：

- `--host 127.0.0.1`
- `--port 18093`
- `--no-webui`
- `--log-disable`
- 固定上下文、批大小、GPU layer 和并发上限
- 禁用代理继承，健康检查使用 `--noproxy`/直连 loopback

Worker 不能启动、停止或重启 llama.cpp。是否常驻、是否随 Windows 启动，以及
Minecraft 共存资源上限必须在后续单独审批。

## 7. Trace 合同

允许的持久化字段必须是固定 allowlist：

```text
schema_version
request_id
observed_at
group
classifier_version
decision_label
decision_source
reason_code
model_valid
latency_bucket
input_size_bucket
event_count_bucket
suggested_turn_action OR suggested_route
actual_reply_path OR actual_route
reply_suppressed
reply_delayed
provider_switched
would_differ
shadow_only
production_effect
```

禁止：

- 消息、回复、Prompt 或动作内容；
- 输入 Hash（短消息可能被字典反推）；
- QQ/账号/Principal/Namespace/Conversation 标识；
- Memory ID 或内容；
- Token、Key、Cookie、二维码或环境变量；
- 原始 provider/model/route_reason；
- llama.cpp 请求或响应文本。

保留期建议 7 天，按天轮换。聚合报告只保留计数、比例、延迟桶、fallback 原因和
关键错误数；原始逐条 metadata trace 在保留期后删除。

## 8. 失败隔离和性能门槛

硬门槛：

- 投递发生在 QQ 回复连接关闭之后；
- Gateway 投递使用 non-blocking AF_UNIX datagram；
- 不等待 Worker 返回；
- 不重试；
- Socket 缺失或队列满时直接丢弃；
- Shadow 异常不得进入 QQ 用户可见错误路径；
- Gateway journald 只允许固定 stage code；
- Worker journald 不允许输入、输出或动态异常文本。

计划验证值：

```text
post-reply enqueue p95 <= 5 ms
production reply latency delta = 0 by construction
reply suppressed/delayed/provider switched = 0
trace content/identity/secret leakage = 0
critical downward route error = 0
invalid model label reaching effect path = 0
```

注意：现有 Owner Memory Shadow 的 enqueue p95 曾为 6.780 ms，因此两个 Shadow
不能串行等待，也不能共享阻塞发送。Turn/Route Shadow 应使用单次 non-blocking
投递，并单独统计 drop，不借此修改现有 Memory Shadow。

## 9. 观测期和门禁

本阶段只有“观察”，没有 Canary 效果。建议分两次评审：

### 最低早期检查

- 至少 3 个不同的 QQ 在线自然使用日；
- 至少 50 条有效 Owner 纯文字私聊；
- 关键边界错误、内容泄漏和生产影响均为 0。

### 正式 Canary 候选门槛

- 建议达到 7 个在线自然使用日和 100 条有效消息；
- 至少 20 个真正调用 4B 的模糊样本，或明确记录样本不足；
- 对抽样结果做人工语义复核；
- Turn 关键错误为 0；
- Route 高风险向下误路由为 0；
- fallback、模型不可用、延迟和资源影响均有统计；
- Minecraft 同时运行时无可归因的稳定性退化。

QQ 离线区间不累计在线日/在线时长，也不算失败；不得为了满足样本数机械发送
消息或要求 Owner 维持登录。

即使门槛通过，也只能提出新的有限 Canary 方案；真正静默、等待、合并、路由
切换和 Temporal Buffer 都必须分别形成新 digest 并由 Owner 明确批准。

## 10. 分阶段实施（本文件未执行）

### R0：当前完成范围

- 审查现有 Gateway/Core/Shadow 接缝；
- 形成此运行方案和不可变 `PLAN.json`；
- 做静态边界验证；
- 不修改运行服务。

### R1：源代码候选（需新批准）

- 在 deploy 仓库增加 Worker、Socket、配置模板和测试；
- 修改 post-reply fanout 的仓库源代码；
- 使用 Fake Core/Fake Socket 做离线故障测试；
- 不复制到 `/opt`、`/usr/local/libexec` 或 `/etc`。

### R2：安装但保持禁用（需新批准）

- 建立独立用户、安装 root-owned 代码和 systemd unit；
- 不创建启用 Marker；
- 不启动 Socket/Worker/模型服务；
- 验证权限、回滚和日志清理。

### R3：metadata-only Shadow 激活（需新 digest 和明确批准）

- 创建 root-owned Marker；
- 启动独立 Socket/Worker；
- 更新已审核的 post-reply fanout；
- 首先 rules/fallback-only 探针，再决定是否启动 4B 测试窗口；
- 运行真实 QQ 通道验收，但回复内容和时序保持原样。

## 11. 回滚

即时回滚顺序：

1. 删除/移走 Turn/Route Shadow Marker；
2. 停止并禁用其 Socket 和 Worker；
3. 如正在运行，停止独立 Windows llama.cpp Shadow 进程；
4. 保留 trace 供审计，按 7 天策略清理；
5. 验证 QQ Gateway、Core 和现有 Memory Shadow 状态未改变。

由于投递是 Marker-gated、post-reply、best-effort，移除 Marker 后不需要改变
Definition、Memory、DeepSeek 路由或 QQ 身份绑定。

## 12. 审批边界

本方案本身不授权任何安装或激活。后续每一步都必须生成新的不可变 plan digest。
尤其是“把真实 QQ 文字发给本地 4B 做 Shadow 判断”属于新的真实数据处理范围，
必须在实施前由 Owner 明确批准。

