# ADR-017：Gateway 独立运行底座与真实 owner 预览门禁

状态：用户已批准底座；服务保持 disabled/inactive；真实 owner 写入仍需预览后确认

记录日期：2026-07-16（Asia/Shanghai）

## 决策

AstrBot/QQ Gateway 使用独立 Linux 用户 `myuna-gateway` 和独立 PostgreSQL 角色
`myuna_gateway_app`。它不能继承 `myuna`、`myuna_dev_app`、数据库 owner 或
PostgreSQL 管理权限。

Gateway 数据库角色没有任何表的直接 SELECT/INSERT/UPDATE/DELETE 权限，只能执行
六个经过审核的 `SECURITY DEFINER` 函数：

- claim inbound event；
- record inbound outcome；
- enqueue outbound；
- claim outbound；
- mark outbound delivered；
- mark outbound retry/dead-letter。

它不能访问 `myuna_identity`、`memory` 或 `myuna_admin`。

## Operational records

`gateway_runtime` 只存储：

- channel/instance/event 的不透明 ID；
- nonce 的 SHA-256 指纹；
- payload SHA-256；
- 时间、处理状态、失败代码；
- 已由适配器加密的目的地和出站 payload。

表结构禁止原始 QQ ID、原始 nonce、签名、消息正文和明文出站内容。Operational
records 与 Myuna 的个人记忆保持分离；Myuna 查询它们时只能表达为“我查看了记录”。

## 系统服务门禁

`myuna-channel-gateway-dev.service` 安装后必须保持 disabled/inactive。Unit 要求
`/etc/myuna-gateway/activation-approved`，而本阶段不创建该文件。即使错误创建标记，
当前 fail-closed runner 也会退出，不能连接 QQ 或 Core。

独立秘密包括 identity pepper、channel signing key 和 payload encryption key。
它们只保存在 `/etc/myuna-gateway/secrets`，`root:root 0600`，不进入 Git、报告、
环境变量或普通备份。

## Owner 真实身份预览

真实 QQ ID 只能由用户在服务器本地交互式终端中隐藏输入两次。工具：

```bash
sudo /srv/myuna/repos/deploy/scripts/preview_owner_binding.py
```

工具在内存中计算 HMAC 指纹，原始 ID 不进入 argv、SQL、日志或输出。它在一个数据库
事务中创建 `pending` principal、namespace 和 binding，显示脱敏结果后执行 ROLLBACK。
本工具不提供 `--apply` 或 COMMIT 路径。

预览通过后，用户还需要单独批准真实 pending 行写入。Binding 只有完成 QQ 私聊挑战后
才能从 pending 变为 verified；不能因为手动输入账号就直接获得 active owner 权限。

## 当前未激活

- 未安装 AstrBot，未登录 QQ。
- 未创建真实 principal、namespace 或 account binding。
- 未创建 activation marker，未启动或 enable Gateway。
- 未连接 Core，未开放端口。
- 未导入真实记忆，未给 Gateway 任何记忆权限。
