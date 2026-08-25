# Turn/Route metadata-only Shadow v1 R1 候选报告

生成时间：2026-07-20 15:10 +08:00
状态：**仓库源码候选通过；未安装、未激活**

## 1. 批准范围

本轮严格绑定：

```text
plan_digest aa63fb418623bc7780fc8dadd70c12651a07640488ae10e4fe5a9e7dcf22676f
```

允许修改 deploy 仓库源码、配置模板、systemd 模板、测试和文档，并使用合成
内容、Fake Socket、Fake Core 与 Fake Model 做离线测试。没有权限安装文件、
创建用户、启动模型、重启服务、连接真实 QQ、读取真实聊天、接入记忆或改变路由。

## 2. 实现结果

候选增加了以下源码边界：

1. 冻结的 `Hybrid Turn/Route Classifier v1`，文件 Hash 与离线验收版本完全一致。
2. 严格 datagram Schema；只允许随机观察 UUID、临时 query、字符数、固定事件数、
   bounded actual-route enum 和单调时钟。
3. metadata-only Trace Schema；禁止消息、回复、Prompt、输入 Hash、身份、Memory、
   Credential、原始 Provider/Model/Route Reason。
4. 独立 Shadow Worker 候选；规则优先，模型不可用或非法标签时 Turn 回退 `B`、
   Route 回退 `D`。
5. Windows 4B 客户端候选固定为 `127.0.0.1:18093`，显式绕过代理；提交配置中
   `model_enabled=false`。
6. QQ Gateway 仓库源码中的 post-reply fanout：先关闭回复连接，再分别尝试
   Memory Shadow 和 Turn/Route Shadow；两个投递互不依赖、均不重试。
7. 独立系统用户、Unix datagram Socket 和 systemd hardening 模板，但没有安装。

## 3. 测试结果

### R1 定向合成测试

```text
24 / 24 passed
```

覆盖：

- 回复连接关闭后才允许投递；
- 两个 Shadow 相互隔离；
- Marker 异常、Socket 缺失、队列满、Sink 失败；
- 严格事件 Schema、大小、UUID、计数和 actual-route allowlist；
- Rule / Model / Fallback 全路径；
- 模型超时、不可用和非法标签；
- Trace allowlist 和内容/身份/Secret 泄漏拒绝；
- reply suppression/delay/merge/provider switch 永远为 false；
- systemd 最小权限、无 Credential、仅 loopback 网络；
- root-owned 且不可组写/全局写的配置要求。

### Deploy 仓库全量回归

```text
82 / 82 passed
```

### Core 仓库全量回归

第一次运行继承宿主代理，两个 loopback HTTP 测试发生传输超时；该次标记为
`excluded_proxy_transport_environment`，没有源码断言失败。显式清除代理并设置
`NO_PROXY=127.0.0.1,localhost` 后，唯一有效结果为：

```text
107 / 107 passed
```

### 其他静态验证

- `python3 -m compileall`: passed
- `systemd-analyze verify`: passed
- `git diff --check`: passed
- 候选范围敏感字段扫描：0 hits

## 4. 固定源码 Hash

| Artifact | SHA-256 |
|---|---|
| `hybrid_classifier.py` | `3a961875e11e0deb1aa48c5068a84e1fbdacd8b467e1a07e171078d47d8abc2b` |
| `metadata_shadow.py` | `b7262104bed28fdeaebb2fdcd9ebb519cbdb8634b21b4ea8a3e1a266c34713f8` |
| `worker.py` | `be4b68fd50e032b8321596515aa41837e1e33afa1cbd809e65e8e4eab6746f42` |
| `turn_route_enqueue.py` | `fdb8ca7b2380e674e5cda22e44b8edcac132a5ef05539f3ac039eaf422ebc441` |
| `gateway_post_reply.py` | `6e4f04561e78f56663875d5323d2eacb5cc7c028abe94e6bf66ab2a2fb0950bd` |
| `qq_owner_runtime_gateway.py` | `6f2c43b58335a9f068a9e69c27d1c0088e0afb56a847b84d951dec867ef86fc2` |
| `turn-route-shadow-v1.json` | `c10d08aee4cdf308eb36daabc0d31385b63319ca104d005c61d7f737e6c57677` |
| service template | `7bb27301694a784de407f9588d099ab75c21e809630c052d7db218a9d18172bc` |
| socket template | `cca3d0b2fa770e326ffc573d6d384e68a95ff594a8c4de9c2406d1d85f473072` |

## 5. 运行态未改变的证据

R1 前后，已安装 Gateway 文件 Hash 保持不变：

```text
fdeda31b3961fc2f71f72457490ee1c553a41d9a91b891f501e2201271ff1328
  /usr/local/libexec/myuna-gateway/qq_owner_runtime_gateway.py
e91c6287425816f01b9c3d7c9eb72be9d6762851ce0110b2194c8113a44e0cf3
  /usr/local/libexec/myuna-gateway/gateway_post_reply.py
```

以下服务前后均为 active/running，`NRestarts=0`，启动时间未改变：

- `myuna-core@qq.service`
- `myuna-qq-owner-runtime-dev.service`
- `myuna-owner-memory-shadow-dev.service`

以下真实运行对象均不存在：

- Turn/Route activation Marker；
- `/etc/myuna-shadow/turn-route-shadow-v1.json`；
- `/opt/myuna/turn-route-shadow-v1`；
- `/run/myuna-turn-route-shadow-dev`；
- `/var/log/myuna/turn-route-shadow`；
- `myuna_shadow_classifier` 系统用户；
- 已加载的 Turn/Route service/socket；
- Windows `llama-server` 进程。

## 6. 当前能力边界

本轮通过只表示源码候选可进入以后单独审批的“安装但禁用”阶段。当前：

- 真实 QQ 文本没有被候选处理；
- QQ 回复没有被静默、延迟、合并或改变；
- DeepSeek 路由没有变化；
- 4B 模型没有启动；
- Turn Manager、Temporal Buffer 和 Model Router 没有激活；
- Memory、History Archive、Prompt 和工具没有接入；
- NapCat 登录与恢复逻辑没有变化。

## 7. 后续建议

如要进入 R2，应另行生成 plan digest，只安装 root-owned 源码、独立用户与 unit，
但仍不创建 Marker、不启动 Socket/Worker/模型。安装后必须再次核对：

1. 文件 Hash 与本报告一致；
2. systemd 权限与网络沙箱有效；
3. 已安装 QQ Gateway 仍未切换到候选源码；
4. 真实 QQ、Memory、Provider 与工具仍无任何新连接；
5. 回滚仅删除未激活的候选安装物。

本报告不构成 R2 安装或 R3 Shadow 激活授权。
