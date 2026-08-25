# Selected Core release upgrade executor v1 — R2A

R2A 只定义确定性的激活/回滚状态机、后端协议、内存 Journal 和有状态 Fake 后端。
它不具备访问真实文件系统、systemd、Secret、网络、QQ、Telegram、模型或记忆的能力。

Fake 测试覆盖：

- 正常激活顺序与成功回执；
- Gateway quiesce 失败；
- 文件应用失败；
- daemon-reload 失败；
- Core 启动失败；
- 目标状态验证失败；
- Gateway 恢复失败；
- 非空 Journal 的 fail-closed；
- 未批准 plan digest 的拒绝。

当前阶段故意拒绝非空 Journal。持久化 Journal、崩溃恢复、真实 systemd/文件后端和 live 激活必须在后续独立合同中实现、测试并另行审批。
