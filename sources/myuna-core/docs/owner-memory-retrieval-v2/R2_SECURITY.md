# R2 安全边界

- v2 使用独立 `/opt` release、Unix Socket、systemd unit 和运行目录。
- v2 不导入或调用 v1 的检索/Worker Python 模块。
- 数据源固定为现有非 restricted 只读视图；OS 用户和 DB 角色固定且相同。
- 不读取 restricted、History Archive、Shadow Memory 或其他 namespace。
- 无网络、无模型、无记忆写入、无密钥、无 TCP/UDP 监听。
- 错误响应只包含类型码，不包含查询或记忆正文。
- 安装完成后的目标状态必须为 disabled/inactive。
- QQ Core 继续绑定 v1；R2 不修改 `/etc/myuna/qq.env` 或 capability manifest。
- R3 原子切换必须使用新的 plan digest 与 Owner 明确批准。
