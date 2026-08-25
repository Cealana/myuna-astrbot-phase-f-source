# Core Release Selector v1 R2C canonical evidence

状态：repository-only candidate / inactive / not selected / not activated

## 目的

R2C 将 Selector 的仓库候选证据从 legacy 地址 `3bc0fb63…` 更新为规范
POSIX 路径排序地址 `430be06e…`。两者包含完全相同的 149 个文件；变化只在
树摘要的排序实现，不是代码升级或降级。

## 固定证据

```text
source_commit               1d968d9bf361cc50a4a9b709a566c698424f3287
tree_sha256                 430be06ece061b16b3bc2d67e9e2d17764c81073ffc8593403470063935f68a8
file_count                  149
artifact_manifest_sha256    7909359616a3b089f9b6fe5c6b90e6900c7edd9c849e33b012c4b909bc5ac938
installation_receipt_sha256 b296bcc04909a459e39d3f60724e7987f431187d05958bc74df99eaf60069777
candidate_canonical_sha256  b55d45bca0e0f9361de4db5cfe943c357c1267145d0ad37394901631d273f699
selector_dropin_sha256      a8a733ade0992c3d94f919afc945fb052dbd1580cd777efccf6b0365bfb32ef0
```

R2B 安装回执保存在 Linux、C、D 三个位置，三份文件 SHA-256 相同。

## 边界

本候选只改变仓库中的 Selection Evidence。它不会：

- 修改或重载 systemd；
- 创建 runtime binding 或 guard；
- 改变 `WorkingDirectory` 或 `PYTHONPATH`；
- 选择或激活 `430be06e…`；
- 重启 Core 或 Gateway；
- 接触 QQ、模型、记忆、Definition、Capability、密钥或其他服务。

在 R4 获得独立摘要批准并成功执行前，活动 Core 仍是 legacy `3bc0fb63…`。
