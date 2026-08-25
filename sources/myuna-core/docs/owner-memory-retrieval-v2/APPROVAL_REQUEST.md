# Owner Memory Retrieval v2 R1：下一阶段审批

## 当前结论

v2 已完成独立候选构建，但尚未应用到正式 Core 仓库，也没有安装或激活。

- 合成、协议与 Core Adapter 测试：`26/26`。
- 当前真实非 restricted 安全视图：`21/21`。
- 两条已知真实失败问句均正确选中 M001。
- 五类防误检用例均返回空结果。
- 正式 Core 仓库基线：`9f84ae1039496cc060e21d01766e6cdf5bc47151`，当前干净。
- 在线 v1、QQ Core、数据库、systemd、网络、模型和记忆数据均未修改。

## R1 的唯一范围

R1 只把已封存的 v2 源码、测试和文档应用到 `/srv/myuna/repos/core`，运行完整测试，
并创建一个仅含 v2 文件的本地 Git 提交。R1 不安装运行文件、不创建服务、不切换 QQ，
也不更改真实记忆。

## 计划摘要

`16833641c6d0ed2768edacec942c70b0e967ec684d926cbc3d6d38aa8398c3aa`

## 批准文本

如批准 R1，请回复：

> 我批准 plan_digest 16833641c6d0ed2768edacec942c70b0e967ec684d926cbc3d6d38aa8398c3aa 对应的 Owner Memory Retrieval v2 R1 正式仓库应用；仅应用已封存的 v2 源码、测试与文档，运行完整 Core 测试并创建本地提交，不安装、不激活、不连接 QQ、不重启服务、不修改数据库、记忆、模型、网络、密钥、OpenClaw、Turn Manager、工具或 Minecraft。
