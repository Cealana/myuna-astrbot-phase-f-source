# Core Release Selector v1 R4B transaction bundle

Status: repository candidate / not installed / not active

## 目的

R4B 把 R4A 的纯迁移结果封装为一份完整、内容寻址、可回滚但尚未生效的事务包。
它不会把任何文件写入活动 binding 或 systemd drop-in 路径。

事务包同时包含：

1. 未来 R4C 的精确激活计划；
2. 从该计划摘要派生的 runtime binding；
3. 迁移后的十份完整 Core drop-in；
4. 当前十三份 Core drop-in 的逐字节回滚快照；
5. 当前 Core unit fragment 的证据副本；
6. 删除清单与迁移摘要；
7. 全部非 manifest 文件的 SHA-256 清单。

## 两层摘要

R4B 使用两个不同的摘要，避免 binding 与事务包形成自引用：

- `R4C_ACTIVATION_PLAN` 摘要：
  激活计划不包含事务目录摘要或 binding 摘要。先对规范 JSON 计划求 SHA-256，
  再把该摘要写入 runtime binding。未来 R4C 必须由 Owner 单独批准这个摘要。
- `R4B_INSTALL_PLAN` 摘要：
  绑定完整事务目录摘要、安装脚本和唯一安装位置，只授权 inactive 安装。

R4B 获批不代表 R4C 获批。事务包即使已经安装，也没有活动 binding、guard 或
selector，不能改变 Core。

## 事务目录

未来获批的 inactive installer 只允许写入：

```text
/opt/myuna/core-release-selector/transactions/<transaction_tree_sha256>/
/opt/myuna/core-release-selector/transaction-installations/<r4b_plan_digest>.json
```

目录为 `root:myuna 0550`，文件为 `root:myuna 0440`，受管父目录为
`root:myuna 0750`。相同内容允许幂等复核；任何额外文件、内容、owner、mode、
symlink 或 special entry 漂移都 fail closed。

## 事务内容

```text
TRANSACTION_MANIFEST.json
activation/R4C_ACTIVATION_PLAN.json
runtime/qq.binding.json
final/dropins/<10 files>
rollback/myuna-core@.service
rollback/dropins/<13 files>
evidence/MIGRATION_SUMMARY.json
evidence/DELETE_LIST.json
```

`TRANSACTION_MANIFEST.json` 列出除自身外每一个文件的 SHA-256。事务目录名使用
与 Core release 相同的 path-content tree 算法计算，因此路径和内容都会进入摘要。

## R4B 分段

- R4B-A：把纯 transaction contract、inactive installer、测试和本文提交到 Deploy。
  不构建或安装真实事务包。
- R4B-B：在 `work` 中从当前 live 只读证据构建真实事务包，封存内层 R4C 计划。
- R4B-C：另行批准，把该事务包安装到 `/opt` inactive 目录并生成非敏感回执。

每一段都需要独立摘要。R4B-C 仍不得执行 daemon reload、修改 active drop-in、
创建活动 binding，或启动、停止、重启任何服务。

## R4C 激活边界

R4C 必须使用单独的 Owner 批准，并验证：

1. Owner 批准摘要等于事务内 `R4C_ACTIVATION_PLAN.json` 的 SHA-256；
2. runtime binding 的 `approval_plan_digest` 等于同一摘要；
3. 事务目录摘要、manifest、forward set 与 rollback set 全部匹配；
4. 当前 live prestate 与事务快照完全一致；
5. Gateway 先显式停止，Core 验证成功后才显式启动；
6. 任一失败点都恢复完整旧 drop-in 集、移除新 binding、daemon reload 并恢复服务。

R4B 不包含 R4C 执行器，也不授权任何激活动作。

## v6 边界

Myuna v6 和两份同步说明继续排在 R4 完成之后。事务包不修改 Definition，也不会
把 v6 内容带入 Core release 迁移。
