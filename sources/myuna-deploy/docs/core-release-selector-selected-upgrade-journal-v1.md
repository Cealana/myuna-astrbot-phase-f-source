# Selected Core Upgrade Durable Journal v1

该合同为 selected-to-selected Core 切换提供持久、追加式 JSONL 哈希链 Journal，以及只能创建一次的成功回执。每条记录都绑定顺序号、前一条记录哈希、载荷哈希与本条记录哈希；写入内容和父目录条目均执行 `fsync`。

本阶段只提供调用方指定目录中的文件系统 Journal，不包含 systemd、网络、数据库、Secret、QQ、Telegram、模型、记忆或 live release 后端。发现损坏记录、截断记录、错误顺序、哈希漂移、符号链接或重复成功回执时必须 fail-closed。

非空但有效的 Journal 只作为后续恢复合同的证据。本合同不得自行判断恢复、重试或继续执行，也不得覆盖旧 Journal 或成功回执。
