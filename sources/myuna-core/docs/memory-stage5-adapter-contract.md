# Memory Stage 5 Core-to-worker adapter contract

Stage 5 只验证 Myuna Core 能否通过受限 Unix Socket 使用 Stage 4 synthetic worker，
并把访问元数据写入 Core 审计日志。它不激活正式 Myuna、不导入真实记忆，也不调用
DeepSeek、OpenAI 或本地聊天模型。

## 固定边界

- 只允许 `synthetic=true`。
- 只允许 owner-only Unix Socket，不使用 TCP/UDP。
- Core 不接收数据库账户或数据库连接串。
- Core 只接收命中 ID、分数、理由、有限 trace 和模型状态，不接收记忆正文。
- worker 响应必须回显 request ID 和 synthetic boundary。
- lexical 请求不能意外升级为 hybrid。
- hybrid 请求不能静默降级。
- auto 降级必须提供 `degraded_reason`。
- limit 最大为 10，external operational records 固定关闭。
- 所有数值、模式、命中结构和响应大小必须在信任前校验。

## 审计内容

允许记录：

- request ID、UTC 时间和环境。
- synthetic 标记、caller、route reason。
- query SHA-256 指纹和字符数。
- scope 数量、memory kinds、proactive、limit 和是否包含时间条件。
- requested/used mode、degraded reason。
- 命中 ID、命中数量、耗时和最小模型身份。
- typed error code 与 retryable 标记。

禁止记录：

- 查询正文。
- 记忆正文、原话或 worker query terms。
- API 密钥、Authorization、Cookie、token 或凭据。
- 完整 trace、图片、附件或模型 reasoning content。

## 激活边界

Stage 5 适配器不接入 Core HTTP POST 路径。Core dev/staging/prod 和 retrieval worker
在验证结束后均保持 disabled/inactive。真实记忆、Definition、Provider 和正式回答链路
仍需要独立批准。
