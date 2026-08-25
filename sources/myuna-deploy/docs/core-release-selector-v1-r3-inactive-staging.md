# Core Release Selector v1 R3 inactive staging

状态：R3A repository candidate / inactive / not installed / not selected

## 目标

R3 为未来的 Core release ownership 迁移准备四个彼此绑定、但当前完全不生效的组件：

1. `Selector`：只拥有同一 release 的 `WorkingDirectory` 与 `PYTHONPATH`；
2. `Verifier`：内容寻址、只读的 `ExecStartPre` 校验器；
3. `binding-intent`：记录候选证据，但不能被 runtime binding parser 接受；
4. `guard`：未来调用固定 Verifier，并要求活动 runtime binding 存在。

R3 不改变当前 Core。活动进程仍使用 legacy `3bc0fb63…`；规范
`430be06e…` release 继续保持已安装但未选择状态。

## 为什么 staging 不能直接包含 runtime binding

正式 runtime binding 必须记录未来 R4 的 `approval_plan_digest`。R3 尚未获得该摘要，
如果预先写入一个占位摘要，就可能把未获授权的文件误认为可激活配置，也会形成计划文件
包含自身摘要的循环。

因此 R3 使用：

```text
schema=myuna.core-release-selection-binding-intent.v1
status=inactive_staging
```

它没有 `approval_plan_digest`，且 exact-fields schema 与
`myuna.core-release-selection-binding.v1` 不同。把 intent 误放到活动 binding 路径时，
Verifier 必须 fail closed。R4 获批后才通过确定性 renderer 加入 R4 摘要并生成正式 binding。

## 固定证据

```text
selected Core tree       430be06ece061b16b3bc2d67e9e2d17764c81073ffc8593403470063935f68a8
selected Core files      149
source Core commit       1d968d9bf361cc50a4a9b709a566c698424f3287
candidate canonical SHA  b55d45bca0e0f9361de4db5cfe943c357c1267145d0ad37394901631d273f699
selector drop-in SHA     a8a733ade0992c3d94f919afc945fb052dbd1580cd777efccf6b0365bfb32ef0
Verifier script SHA      3fab13b7b533c3e93bf5759256ff5153d7bb17aea0fc8307f560e82985a7fcaf
guard drop-in SHA        30c69f98d8a27c5d3cd04c6ae9b9ad7513e00685e0003ee71399a3d2fae180c4
binding-intent SHA       0ee3c54dbcb3575d6b471595341df076658ca5b6cdf676bf30ec4b5a53ce3068
```

若 `scripts/core_release_selector.py` 再发生任何修改，Verifier 路径、guard SHA、intent
与本节证据都必须整体重新生成，不能局部手改。

## R3A：正式仓库候选

R3A 只把合同、installer、intent、测试和本文档提交到 Deploy。它不运行 installer，
不写 `/opt` 或 `/etc`，也不接触 systemd 与服务。

`scripts/core_release_selector.py` 仍然是只读合同/Verifier 模块；写入 staging 的职责只存在于
`scripts/install_core_release_selector_staging.py`，避免把只读校验和系统写入混在一个模块。

## R3B：另行批准的 inactive install

R3B 未来只允许写入：

```text
/opt/myuna/core-release-selector/releases/<verifier_sha256>/
/etc/myuna/core-release-selector/candidates/<r3b_plan_digest>/
```

Verifier release 只包含：

```text
core_release_selector.py
```

候选目录只包含：

```text
selection-candidate.json
qq.binding-intent.json
05-core-release-selector-guard-v1.conf
10-core-release-selector-v1.conf
STAGING_MANIFEST.json
```

目录为 `root:myuna 0550`，文件为 `root:myuna 0440`；上级受管目录为
`root:myuna 0750`。已存在的相同内容允许幂等复核，任何额外文件、摘要、owner、mode、
symlink 或 special entry 漂移都 fail closed。

## 明确不允许的路径和行为

R3A/R3B 均不得写入：

```text
/etc/myuna/core-release-selector/qq.binding.json
/etc/systemd/system/myuna-core@qq.service.d/05-core-release-selector-guard-v1.conf
/etc/systemd/system/myuna-core@qq.service.d/10-core-release-selector-v1.conf
```

也不得：

- 执行 `systemctl` 或 `daemon-reload`；
- 启动、停止、重启、reload、enable 或 disable 服务；
- 修改历史 drop-in；
- 选择或激活 release；
- 连接 QQ、调用模型、读取或写入记忆；
- 读取 Secret 或活动 EnvironmentFile 的值。

## R4 前置条件

R4 必须另行完成并获批：

- 固定全部 live drop-in 的名称与 SHA；
- 只检查活动 EnvironmentFile 的变量名，确认无 `PYTHONPATH`；
- 在 staging 中先构造迁移后的完整 drop-in 集；
- 从 intent 与 R4 摘要派生正式 runtime binding；
- 为历史纯 release drop-in 和混合 drop-in 分别定义字节级迁移/回滚；
- 允许 Core 以及 Requires 所致 Gateway 各发生一次受控重启；
- 验证 Definition、Capability、Owner Memory v2、Reply 与 Natural Degradation R3D 不漂移。

R3 的存在不构成 R4 授权。
