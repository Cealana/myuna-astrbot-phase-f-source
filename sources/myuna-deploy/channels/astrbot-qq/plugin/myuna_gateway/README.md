# Myuna AstrBot QQ boundary

This local-only plugin intercepts every AIOCQHTTP/OneBot event before normal
AstrBot processing. Group events are stopped without a reply. Private events
must contain only text and are forwarded as a signed `myuna.channel.v1`
envelope to a local Unix socket.

The plugin has no model-provider configuration, database socket, Core endpoint,
memory permission, or tool permission. Its mounted signing credential only
authorizes channel ingestion and cannot authorize an owner binding.
