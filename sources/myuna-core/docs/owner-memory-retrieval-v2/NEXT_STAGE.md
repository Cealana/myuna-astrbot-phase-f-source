# 下一阶段（尚未批准）

建议分三次独立审批，避免候选构建、系统安装和 QQ 激活混在一起。

## R1：正式仓库应用

- 将 v2 模块和测试应用到正式 Core/部署仓库；
- 保持现有 v1 运行文件不变；
- 运行完整 Core 测试；
- 创建本地提交；
- 不安装、不重启、不接入 QQ。

## R2：平行安装但禁用

- 安装固定 digest 的 v2 Worker；
- 使用独立 `myuna-owner-memory-read-v2.socket`；
- 复用现有最小权限只读 DB 角色，不增加数据权限；
- Socket/Service 保持 disabled/inactive；
- 以实际 `myuna` 用户执行无正文探针；
- 不修改正式 Core 绑定。

## R3：Owner QQ 原子切换

- 备份当前 Core release、capability 与环境绑定；
- 只切换 Owner Memory Socket/策略到 v2；
- 重启 `myuna-core@qq.service`；
- 执行健康检查和两条真实问句；
- 审计必须显示 M001 被实际使用；
- 失败时恢复 v1 绑定并只重启 Core。

每一步都需要独立 plan digest 和明确审批。
