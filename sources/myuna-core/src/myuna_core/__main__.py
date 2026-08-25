from __future__ import annotations

import os
from pathlib import Path

from .audit import AuditLogger
from .config import load_settings
from .conversation import DevConversationEngine
from .external_context.live import LiveHybridConversationEngine, hybrid_live_enabled
from .external_context.policy_overlay import (
    load_selected_policy_overlay,
    release_digest_from_path,
)
from .external_context.release_binding import load_release_set_snapshot_from_environ
from .http_api import build_server


def _optional_digest_binding(environ: dict[str, str], name: str) -> str | None:
    value = environ.get(name)
    if value is None:
        return None
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError(f"{name} is not an exact digest")
    return value


def main() -> None:
    settings = load_settings()
    audit = AuditLogger(settings.log_dir, settings.environment)
    audit.emit(
        "service_start",
        details={
            "bind_host": settings.bind_host,
            "port": settings.port,
            "definition_release": settings.definition_release,
            "enabled_providers": list(settings.enabled_providers),
        },
    )
    engine = DevConversationEngine(settings, audit) if settings.ready else None
    hybrid_engine = None
    if hybrid_live_enabled(os.environ):
        if engine is None:
            raise RuntimeError("hybrid generation requires an active conversation engine")
        release_snapshot = load_release_set_snapshot_from_environ(os.environ)
        release_set = (
            None if release_snapshot is None else release_snapshot.release_set
        )
        policy_overlay = None
        if release_snapshot is not None:
            policy_overlay = load_selected_policy_overlay(
                parent_release_set=release_snapshot.release_set,
                parent_manifest_file_digest=release_snapshot.file_digest,
                component_kind="core",
                current_component_release_digest=release_digest_from_path(
                    Path(__file__), component="core"
                ),
                expected_uid=0,
                expected_gid=int(
                    release_snapshot.release_set.runtime_config["gid"]
                ),
            )
        hybrid_engine = LiveHybridConversationEngine(
            settings,
            audit,
            engine,
            release_set=release_set,
            policy_overlay=policy_overlay,
            episodic_overlay_id=_optional_digest_binding(
                os.environ,
                "MYUNA_P07_EPISODIC_OVERLAY_ID",
            ),
            episodic_memory_release_set_id=_optional_digest_binding(
                os.environ,
                "MYUNA_P07_EPISODIC_MEMORY_RELEASE_SET_ID",
            ),
            reflective_diary_egress_binding_digest=_optional_digest_binding(
                os.environ,
                "MYUNA_P07_REFLECTIVE_DIARY_EGRESS_BINDING_DIGEST",
            ),
            owner_day_diary_closed_egress_binding_digest=_optional_digest_binding(
                os.environ,
                "MYUNA_P07_OWNER_DAY_DIARY_CLOSED_EGRESS_BINDING_DIGEST",
            ),
            owner_day_diary_preview_egress_binding_digest=_optional_digest_binding(
                os.environ,
                "MYUNA_P07_OWNER_DAY_DIARY_PREVIEW_EGRESS_BINDING_DIGEST",
            ),
        )
    server = build_server(
        settings,
        audit,
        engine=engine,
        hybrid_engine=hybrid_engine,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        audit.emit("service_stop")
        server.server_close()


if __name__ == "__main__":
    main()
