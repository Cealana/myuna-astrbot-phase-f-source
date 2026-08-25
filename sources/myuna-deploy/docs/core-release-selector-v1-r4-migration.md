# Core Release Selector v1 R4 migration

Status: R4A repository candidate / pure planner / not installed / not active

## 当前事实

活动 Core 目录仍为历史地址：

```text
/srv/myuna/releases/core/3bc0fb63...
```

但该目录的 149 文件真实树摘要已经是：

```text
430be06ece061b16b3bc2d67e9e2d17764c81073ffc8593403470063935f68a8
```

因此 R4 是同一内容的规范地址迁移，不是业务代码升级。

## 为什么不能只写入新的 `10-...` drop-in

当前还有十份按字典序位于 `10-...` 之后的历史 drop-in，同时声明
`WorkingDirectory` 与 `PYTHONPATH`。若直接加入 Selector，它们会继续覆盖
Selector，形成看似接线、实际仍由历史文件控制的假激活。

R4 必须：

1. 删除五份只包含历史 release ownership 的 drop-in；
2. 对另外五份混合 drop-in 仅移除 `WorkingDirectory/PYTHONPATH`，逐字保留
   Reply Contract、Definition、Owner Memory 等其它指令；
3. 原样保留代理、DeepSeek 实验与 credentials 三份非 release-owner drop-in；
4. 加入固定 guard 与 selector；
5. 从 R3B binding-intent 和未来 R4 激活计划摘要派生正式 runtime binding。

迁移后，base template 仍保留开发仓库默认值作为静态后备，但全部 drop-in 中
只有 `10-core-release-selector-v1.conf` 可以拥有 release。

## R4 分段

- R4A：把纯 Migration Planner、精确迁移合同、测试和本文提交到 Deploy。
  不含文件写入、subprocess、systemd 或服务控制能力。
- R4B：另行实现并批准 inactive transaction bundle staging；只准备 binding、
  新 drop-in、删除清单与完整回滚快照，不修改 live drop-in。
- R4C：另行批准受控激活。先停 Gateway，再应用完整集合、daemon-reload、
  重启并验证 Core，最后显式启动 Gateway；任一步失败都恢复完整旧集合。

R4A 不授权 R4B 或 R4C。

## v6 边界

Myuna v6 与两份同步说明排在 R4 后单独交接。R4 不修改当前 Definition，也不会
把 v6 静默带入 Core release 迁移。

