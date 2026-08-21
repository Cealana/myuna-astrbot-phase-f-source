# Modification Notice

Modification date: 2026-08-21.

Myuna modified the reviewed AstrBot response pipeline to produce one immutable, content-free send outcome after the existing response-send operation. The Telegram gateway binds that outcome to an opaque signed trace and permits delivery/factual close only after an exact success outcome. The marker deliberately excludes message text, user/chat/channel identity, reply chains, URLs, provider bodies, credentials, exceptions, and other free text.

The image overlay changes only:

- `sources/astrbot/astrbot/core/pipeline/respond/stage.py`

The reviewed AstrBot Dockerfile pins the official base image and overlays that exact file. Related Myuna Core and Deploy boundary source and generated-synthetic tests are included under their respective source directories.

The reviewed Myuna Deploy Telegram gateway additionally appends one fixed, content-free no-charge corresponding-source offer to every plugin-owned emitted plain response through its existing result-construction seam. It introduces no additional Telegram send, provider call, endpoint, callback, database, store, or service route. Duplicate and no-result paths remain no-send.

These modifications and the included corresponding source are offered under AGPL-3.0-or-later. Existing upstream notices remain intact.
