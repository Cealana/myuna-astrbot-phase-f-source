# ADR-031: Core Release Selector v1

状态：R3A candidate / repository-only / inactive

## 决策

为 `myuna-core@qq.service` 建立一个显式、内容寻址、fail-closed 的 Core Release Selector。

Selector 只原子拥有：

- `WorkingDirectory`；
- `PYTHONPATH`。

两项必须指向同一个 `/srv/myuna/releases/core/<tree_sha256>`。Definition、Capability、Memory、Reply flags、provider、proxy、credentials、Gateway、AstrBot、QQ 与服务生命周期继续由各自模块管理。

R1 只加入严格合同、确定性 renderer、只读 verifier、inventory analyzer、inactive candidate config 与测试。R2A 证明旧 149 文件树只是受 Windows `Path` 排序影响而使用了非规范地址；R2B 已把完全相同的文件平行安装到规范地址。R2C 只更新 repository-only candidate 的证据身份。R3A 加入不可激活的 binding-intent、内容寻址 Verifier 身份绑定、guard/selector 摘要绑定和独立 inactive staging installer；它仍不安装、不读取 live Secret、不执行 `systemctl`、不写活动 systemd 路径，也不改变当前运行服务。

## 背景

调查时，`myuna-core@qq.service` 有 13 个 drop-in，其中 10 个重复设置 Core `WorkingDirectory/PYTHONPATH`；主模板还提供 `/srv/myuna/repos/core` 基线。最终 release 取决于 drop-in 文件名字典序。

当前运行中的 legacy 地址仍固定为：

```text
tree_sha256   3bc0fb63d8b4bad4a8e691e9091bb1aae57becbf9f46da5f71508a14327adb21
source_commit 1d968d9bf361cc50a4a9b709a566c698424f3287
file_count    149
```

R2A 逐文件证明它与规范候选内容完全相同；R2B 已安装但尚未选择的规范地址为：

```text
tree_sha256   430be06ece061b16b3bc2d67e9e2d17764c81073ffc8593403470063935f68a8
source_commit 1d968d9bf361cc50a4a9b709a566c698424f3287
file_count    149
```

R2C 仅让 repository candidate 指向规范地址。当前服务继续运行 legacy 地址，直到后续独立批准的 R4 事务原子迁移 ownership 并重启。

## Candidate schema

`config/core-release-selector-v1.json` 使用 exact-fields schema：

```text
myuna.core-release-selection-candidate.v1
```

固定：

- `document_kind=candidate`；
- `status=repository_only_inactive`；
- `unit=myuna-core@qq.service`；
- `instance=qq`；
- `release_root=/srv/myuna/releases/core`；
- `stable_selector_dropin=10-core-release-selector-v1.conf`；
- `canonical_json_algorithm=myuna-canonical-json-v1`；
- `tree_digest_algorithm=myuna-path-content-tree-sha256-v1`。

Release path 只能从固定 root 与 64 位小写 tree digest 派生，不接受任意 path、symlink、`latest` 或 `current/previous` 指针。

`source_commit` 必须同时绑定构建 artifact manifest SHA-256 与安装回执 SHA-256。R2C 的规范证据固定为：artifact manifest `7909359616a3b089f9b6fe5c6b90e6900c7edd9c849e33b012c4b909bc5ac938`，R2B 安装回执 `b296bcc04909a459e39d3f60724e7987f431187d05958bc74df99eaf60069777`；安装证据已保存为 Linux/C/D 三份逐文件相同的非敏感副本。

## Tree digest

`myuna-path-content-tree-sha256-v1`：

1. 递归收集 regular files，拒绝 symlink 和 special entry；
2. 使用相对 POSIX path 排序；
3. 对每个文件向 SHA-256 流写入：4-byte big-endian path UTF-8 长度、path bytes、8-byte big-endian payload 长度、payload bytes；
4. `file_count` 只计算 regular files。

Golden：

```text
a.txt=41, dir/b.bin=00ff
sha256=3c9e00eee57c43dbb603eed3a4a36f62f759db7f6e288fd24db05dd68333cb63
file_count=2
```

## Canonical JSON

`myuna-canonical-json-v1` 只接受 JSON object/array/string/integer/boolean/null，拒绝 float、NaN、Infinity、duplicate key 与非字符串 object key。

等价 Python 编码：

```python
json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
```

无 BOM、无末尾换行、无额外 Unicode normalization。

## Renderer 与 runtime guard

Selector renderer 只能产生：

```ini
[Service]
WorkingDirectory=/srv/myuna/releases/core/<tree_sha256>
Environment=PYTHONPATH=/srv/myuna/releases/core/<tree_sha256>/src
```

不得产生 `EnvironmentFile`、`LoadCredential`、proxy、Capability、Memory dependency 或 feature flag。

R3 staging 先使用独立、不可被 runtime parser 接受的 intent schema：

```text
myuna.core-release-selection-binding-intent.v1
status=inactive_staging
```

Intent 绑定 candidate canonical SHA、selector/guard SHA、内容寻址 Verifier 路径与 SHA，以及 selected release 证据；它故意不包含 `approval_plan_digest`，因此不能伪装成已经获得激活授权。未来 R4 只有在取得独立摘要批准后，才从 intent 和该 R4 摘要派生 runtime binding：

```text
myuna.core-release-selection-binding.v1
```

QQ 的内容寻址 `ExecStartPre` verifier 在每次启动时核对：

- binding 与 selector 内容/SHA；
- binding 与 guard 内容/SHA；
- binding 中的 candidate canonical SHA 与 selected release 可重建结果；
- Verifier 文件路径、目录摘要、文件摘要、owner/group 与只读 mode；
- cwd 与 `PYTHONPATH`；
- release tree digest 与 file count；
- root:myuna、目录 0550、文件 0440；
- no symlink/special/write drift。

主模板的 repo baseline 可继续供明确开发实例使用；QQ selector 或 binding 缺失/不一致时，guard 必须拒绝启动，不能静默回到正式仓库。

所有活动 `EnvironmentFile` 都必须经过只针对变量名的检查；任何 `PYTHONPATH=` 定义均 fail closed。R1 不读取 live EnvironmentFile。

## Inventory 边界

Analyzer 只分析调用者提供的 bytes，不访问 systemd 或 `/etc`。它可以：

- 列出 base/drop-in release owners；
- 报告 systemd 字典序下的 effective owner，但不把字典序视为授权；
- 固定 prestate 文件名与 SHA；
- 拒绝 partial/split ownership；
- 拒绝 EnvironmentFile `PYTHONPATH` 旁路。

R1 正式 Deploy 仓库仅临时允许一个已知 legacy owner：

```text
systemd/myuna-core-qq-voice-hotfix-1.conf
sha256=bf86829a4362fe3dc395e799d554b254434b4de7a20646ac5ff45dbaeee15a8d
```

任何第二个或内容漂移的 repository owner 都被拒绝；完成 live ownership 迁移后，该例外降为零。

## 后续阶段

1. R2A：完成旧树与规范树的 149 文件逐字节重寻址证明；
2. R2B：把规范 `430be06e…` 树平行安装为 inactive release，并生成 Linux/C/D 回执；
3. R2C：把 repository-only candidate 更新为规范 release 证据，不接触 runtime；
4. R3A：将 binding-intent、staging installer、Verifier/guard 强绑定合同与测试提交到 Deploy；
5. R3B：把固定 Selector/Verifier、binding-intent、guard 和 selector 候选安装到 `/opt/.../releases/<tool_sha256>/` 与 `/etc/myuna/core-release-selector/candidates/<r3b_plan_digest>/`，但不写活动 binding/drop-in、不执行 `daemon-reload`；
6. R4：一个独立 digest 的原子事务清理历史 release owners、从 intent 派生正式 binding、安装 binding/guard/稳定 selector，切换到 `430be06e…`，重启 Core 并明确允许 Gateway 的一次依赖重启；
7. R5：健康、能力身份、Memory、R3D 与 Linux/C/D 回执验收。

R4 失败时恢复完整 drop-in/binding prestate并继续运行 legacy `3bc0…`，不把迁移失败误作功能栈降级。

历史 `b6eb…` 与 `22ce…` 是已知稳定证据，不是可由 Selector 单独直接切换的 previous。它们需要各自的 Natural Degradation/Capability 组合回滚计划。
