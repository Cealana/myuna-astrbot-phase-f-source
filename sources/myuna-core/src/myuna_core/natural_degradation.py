from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import re
from typing import Protocol

from .runtime_capability_honesty import capability_honesty_violations


class CapabilityManifestLike(Protocol):
    def capability_enabled(self, name: str) -> bool:
        ...


class DegradationCategory(str, Enum):
    MEMORY_NO_EVIDENCE = "memory_no_evidence"
    REPLY_CONTRACT_REJECTED = "reply_contract_rejected"
    PROVIDER_TRANSIENT_FAILURE = "provider_transient_failure"
    PROVIDER_BUDGET_OR_AUTH_FAILURE = "provider_budget_or_auth_failure"
    CORE_OR_GATEWAY_FAILURE = "core_or_gateway_failure"
    MEMORY_SERVICE_FAILURE = "memory_service_failure"
    ONEBOT_OR_NAPCAT_OFFLINE = "onebot_or_napcat_offline"
    HOST_OR_NETWORK_UNREACHABLE = "host_or_network_unreachable"
    SCHEDULED_NOTIFICATION_UNAVAILABLE = "scheduled_notification_unavailable"
    MEMORY_WRITE_UNAVAILABLE = "memory_write_unavailable"
    EXTERNAL_DATA_UNAVAILABLE = "external_data_unavailable"
    VISION_UNAVAILABLE = "vision_unavailable"
    EXTERNAL_ACTION_UNAVAILABLE = "external_action_unavailable"


class RecoveryState(str, Enum):
    ACTIVE = "active"
    RECOVERING = "recovering"
    RECOVERED = "recovered"


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _require_safe_identifier(value: str, label: str) -> None:
    if _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} must be a safe identifier")


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class FailureEnvelope:
    event_id: str
    correlation_id: str
    category: DegradationCategory
    component: str
    retryable: bool
    owner_action_required: bool
    confirmed_facts: tuple[str, ...]
    unknown_facts: tuple[str, ...]
    safe_detail_code: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    recovery_state: RecoveryState

    def __post_init__(self) -> None:
        for label, value in (
            ("event_id", self.event_id),
            ("correlation_id", self.correlation_id),
            ("component", self.component),
            ("safe_detail_code", self.safe_detail_code),
        ):
            _require_safe_identifier(value, label)
        for label, values in (
            ("confirmed_facts", self.confirmed_facts),
            ("unknown_facts", self.unknown_facts),
        ):
            if len(values) > 16:
                raise ValueError(f"{label} contains too many entries")
            for value in values:
                _require_safe_identifier(value, label)
        _require_aware(self.first_seen_at, "first_seen_at")
        _require_aware(self.last_seen_at, "last_seen_at")
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at cannot precede first_seen_at")
        if self.occurrence_count < 1:
            raise ValueError("occurrence_count must be positive")

    @property
    def fingerprint(self) -> str:
        return f"{self.category.value}:{self.component}:{self.safe_detail_code}"


_NATURAL_TEMPLATES = {
    DegradationCategory.MEMORY_NO_EVIDENCE: (
        "我现在没有找到能确认这件事的记录，所以不能装作记得"
    ),
    DegradationCategory.REPLY_CONTRACT_REJECTED: (
        "刚才那句话没有通过回复检查，我没有把不可靠的内容继续发出来。"
        "你可以换个说法再问我一次"
    ),
    DegradationCategory.PROVIDER_TRANSIENT_FAILURE: (
        "我刚才没能正常完成这次回复。稍后再试一次就好"
    ),
    DegradationCategory.PROVIDER_BUDGET_OR_AUTH_FAILURE: (
        "我现在没能使用对话模型，这不是你说错了什么，需要先检查服务额度或配置"
    ),
    DegradationCategory.CORE_OR_GATEWAY_FAILURE: (
        "我这边的对话服务现在不太正常，这次没能继续处理，需要先恢复服务"
    ),
    DegradationCategory.MEMORY_SERVICE_FAILURE: (
        "我刚才没能读取记忆服务，所以不能把这次情况说成‘没有相关记忆’。"
        "我只能先根据眼前的对话回答"
    ),
    DegradationCategory.ONEBOT_OR_NAPCAT_OFFLINE: (
        "QQ 连接现在不在线，没法从同一个 QQ 会话继续发送，需要先恢复登录"
    ),
    DegradationCategory.HOST_OR_NETWORK_UNREACHABLE: (
        "服务器或网络现在不可达，同一台机器里的服务没法自行恢复通信"
    ),
    DegradationCategory.SCHEDULED_NOTIFICATION_UNAVAILABLE: (
        "我现在还不能设置定时任务，也不能在你不发消息时主动从 QQ 提醒你。"
        "你可以先设一个手机闹钟，到时再来找我就好"
    ),
    DegradationCategory.MEMORY_WRITE_UNAVAILABLE: (
        "我现在只能读取已经接入的记忆，还不能把新内容写进去。"
        "你可以先记在备忘录里，下次把记录发给我，我可以帮你整理"
    ),
    DegradationCategory.EXTERNAL_DATA_UNAVAILABLE: (
        "我现在不能查询实时外部数据，所以不能替你确认最新结果"
    ),
    DegradationCategory.VISION_UNAVAILABLE: "我现在还不能读取图片里的内容",
    DegradationCategory.EXTERNAL_ACTION_UNAVAILABLE: (
        "我现在没有外部操作权限，不能直接替你执行这件事。你完成后再告诉我就好"
    ),
}


def natural_degradation_text(category: DegradationCategory) -> str:
    """Return the canonical deterministic text for one degradation category."""

    if not isinstance(category, DegradationCategory):
        raise TypeError("category must be a DegradationCategory")
    return _NATURAL_TEMPLATES[category]


def render_natural_degradation(envelope: FailureEnvelope) -> str:
    return natural_degradation_text(envelope.category)


_ADVISORY_ONLY = re.compile(
    r"(?:如何|怎么|怎样).{0,20}(?:实现|设计|开发|部署|接入|编写|配置).{0,16}"
    r"(?:提醒|记忆|视觉|图片|联网|工具|重启|操作)|"
    r"(?:架构|接口|代码|合同|测试样本).{0,20}(?:怎么|如何|方案|设计)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class UnavailableCapabilityRequest:
    category: DegradationCategory
    required_capabilities: tuple[str, ...]


_REQUEST_RULES = (
    (
        DegradationCategory.SCHEDULED_NOTIFICATION_UNAVAILABLE,
        ("external_actions",),
        re.compile(
            r"(?:提醒我|叫我|通知我|主动.{0,8}(?:给我)?发消息)|"
            r"(?:设置|创建|安排).{0,12}(?:提醒|闹钟|定时任务)|"
            r"(?:明天|今晚|明晚|到时候|届时).{0,24}(?:提醒|叫|通知)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        DegradationCategory.MEMORY_WRITE_UNAVAILABLE,
        ("long_term_memory_write",),
        re.compile(
            r"(?:帮我|替我|请|给我)?.{0,8}(?:记住|记下|记下来|保存|存进|写进|写入).{0,20}"
            r"(?:长期记忆|记忆|以后|规则|这件事)?",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        DegradationCategory.VISION_UNAVAILABLE,
        ("vision",),
        re.compile(
            r"(?:图片|照片|截图|表情包|图像).{0,24}(?:看|看懂|识别|理解|读取)|"
            r"(?:看|看懂|识别|理解|读取).{0,24}(?:图片|照片|截图|表情包|图像)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        DegradationCategory.EXTERNAL_DATA_UNAVAILABLE,
        ("external_data",),
        re.compile(
            r"(?:查|查询|搜索|联网|上网).{0,24}(?:天气|新闻|价格|网页|实时|最新)|"
            r"(?:天气|新闻|价格).{0,24}(?:最新|实时|查|查询|告诉我)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        DegradationCategory.EXTERNAL_ACTION_UNAVAILABLE,
        ("tools", "external_actions", "system_administration"),
        re.compile(
            r"(?:帮我|替我|请你|现在).{0,16}(?:重启|启动|停止|关闭|修改|删除|安装|卸载|"
            r"设置|执行|运行|调节).{0,24}(?:Minecraft|MC|服务器|服务|容器|Windows|WSL|"
            r"防火墙|数据库|NapCat|QQ|电脑|音量|亮度|程序|文件)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)


def classify_unavailable_capability_request(
    user_text: str,
    manifest: CapabilityManifestLike,
) -> UnavailableCapabilityRequest | None:
    if _ADVISORY_ONLY.search(user_text) is not None:
        return None
    for category, required, pattern in _REQUEST_RULES:
        if pattern.search(user_text) is None:
            continue
        if all(manifest.capability_enabled(name) for name in required):
            return None
        return UnavailableCapabilityRequest(category, required)
    return None


_MECHANICAL_MENU = re.compile(r"(?m)^\s*#{1,6}\s+|(?:^|\n)\s*[-*]\s+.{1,80}(?:\n\s*[-*]\s+.{1,80}){1,}")
_UNVERIFIED_IMAGE_MECHANISM = re.compile(
    r"(?:只会|系统会|通道会).{0,20}(?:收到|变成|显示).{0,16}(?:占位符|空白|没有内容)|"
    r"(?:图片|照片).{0,16}(?:不会传过来|根本收不到)",
    re.IGNORECASE | re.DOTALL,
)
_UNSTORED_RECALL_PROMISE = re.compile(
    r"(?:需要|以后|下次).{0,16}(?:问我|找我).{0,20}(?:帮你想起来|提醒你|我会记得)|"
    r"我会.{0,12}(?:帮你想起来|一直记得)",
    re.IGNORECASE | re.DOTALL,
)


def reply_tail_violations(
    reply: str,
    category: DegradationCategory,
    manifest: CapabilityManifestLike,
) -> list[str]:
    violations = list(capability_honesty_violations(reply, manifest))
    if _MECHANICAL_MENU.search(reply) is not None:
        violations.append("mechanical_capability_menu")
    if (
        category is DegradationCategory.VISION_UNAVAILABLE
        and _UNVERIFIED_IMAGE_MECHANISM.search(reply) is not None
    ):
        violations.append("unverified_image_transport_mechanism")
    if (
        category is DegradationCategory.MEMORY_WRITE_UNAVAILABLE
        and _UNSTORED_RECALL_PROMISE.search(reply) is not None
    ):
        violations.append("unstored_future_recall_overpromise")
    if category is not DegradationCategory.VISION_UNAVAILABLE and "vision_claim" in violations:
        violations.append("cross_capability_visual_suggestion")
    if (
        category is not DegradationCategory.MEMORY_WRITE_UNAVAILABLE
        and "memory_write_claim" in violations
    ):
        violations.append("cross_capability_memory_suggestion")
    return list(dict.fromkeys(violations))


@dataclass(frozen=True, slots=True)
class NotificationCursor:
    fingerprint: str
    recovery_state: RecoveryState
    owner_action_required: bool
    emitted_at: datetime

    def __post_init__(self) -> None:
        _require_aware(self.emitted_at, "emitted_at")


@dataclass(frozen=True, slots=True)
class NotificationDecision:
    emit: bool
    reason: str


def decide_degradation_notification(
    envelope: FailureEnvelope,
    cursor: NotificationCursor | None,
    *,
    now: datetime,
    reminder_interval: timedelta,
) -> NotificationDecision:
    _require_aware(now, "now")
    if reminder_interval <= timedelta(0):
        raise ValueError("reminder_interval must be positive")
    if cursor is None:
        return NotificationDecision(True, "first_observation")
    if cursor.fingerprint != envelope.fingerprint:
        return NotificationDecision(True, "fingerprint_changed")
    if cursor.recovery_state is not envelope.recovery_state:
        return NotificationDecision(True, "recovery_state_changed")
    if envelope.owner_action_required and not cursor.owner_action_required:
        return NotificationDecision(True, "owner_action_became_required")
    if now - cursor.emitted_at >= reminder_interval:
        return NotificationDecision(True, "reminder_interval_elapsed")
    return NotificationDecision(False, "duplicate_suppressed")


def notification_cursor(envelope: FailureEnvelope, *, emitted_at: datetime) -> NotificationCursor:
    return NotificationCursor(
        fingerprint=envelope.fingerprint,
        recovery_state=envelope.recovery_state,
        owner_action_required=envelope.owner_action_required,
        emitted_at=emitted_at,
    )
