# Owner Memory Retrieval v2 R2 Candidate

状态：`isolated_deployment_candidate_not_installed_not_active`

此目录为 R2 平行安装候选。它在 R1 检索包之外新增两层独立职责：

- `postgres_source.py`：只负责以固定 OS/DB 身份读取现有非 restricted 安全视图；
- `socket_worker.py`：只负责 systemd Unix Socket 生命周期和 v2 协议调用。

部署层也分开保存：Socket、Service、tmpfiles、安装、验证和回滚互不混合。

当前没有向 `/opt/myuna`、`/etc/systemd/system`、`/etc/tmpfiles.d` 或 `/run`
写入任何内容，没有执行 `daemon-reload`，没有创建或启动 v2 服务。

R2 最终安装只复用现有 `myuna_memory_runtime` OS 用户、同名 PostgreSQL 角色和
`memory.owner_memory_runtime_nonrestricted_v1` 安全视图，不新增数据库权限。
