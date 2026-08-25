from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol


class CapabilityManifestLike(Protocol):
    def capability_enabled(self, name: str) -> bool:
        ...


@dataclass(frozen=True, slots=True)
class CapabilityHonestyRule:
    code: str
    required_capabilities: tuple[str, ...]
    patterns: tuple[re.Pattern[str], ...]


_FLAGS = re.IGNORECASE | re.DOTALL
_CLAUSE_SPLIT = re.compile(
    r"(?<=[。！？!?；;\n])|(?:但(?:是)?|不过|可是|然而|所以|因此|然后|接着)"
)
_NEGATED_CAPABILITY = re.compile(
    r"无法|没法|做不到|不可用|尚未|未启用|还没(?:有|接入)|"
    r"没有.{0,8}(?:权限|功能|能力|办法|接入)|"
    r"不(?:能|可以|会|支持|具备|读取|识别|查看|提醒|执行|操作|写入|保存|记录)|"
    r"(?:看|读|识别|提醒|执行|操作|保存|记录)不了|看不到",
    _FLAGS,
)
_ADVISORY_CONTEXT = re.compile(
    r"(?:告诉|教|说明|解释|列出|提供).{0,12}(?:怎么|如何|步骤|方法|命令|方案)|"
    r"(?:怎么|如何).{0,12}(?:操作|设置|重启|保存|查询)",
    _FLAGS,
)


def _patterns(*values: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(value, _FLAGS) for value in values)


_SYSTEM_ACTOR = r"我(?:已经|这就|马上|现在就|会|可以|能|来|先|帮你|替你)"
_SYSTEM_OPERATION = r"(?:重启|启动|停止|关闭|修改|删除|安装|卸载|设置|执行|运行|检查)"
_SYSTEM_TARGET = (
    r"(?:Minecraft|MC|服务器|服务|容器|Windows|WSL|防火墙|数据库|"
    r"NapCat|QQ|电脑|程序|文件)"
)


_RULES = (
    CapabilityHonestyRule(
        "memory_write_claim",
        ("long_term_memory_write",),
        _patterns(
            r"我(?:已经|这就|会|可以|能|来|帮你).{0,10}(?:记住|记着|记下|保存|存进|写入).{0,16}(?:长期记忆|记忆|以后|一直)?",
            r"(?:已经|给你|替你).{0,8}(?:记下|保存|存好|写进).{0,12}(?:长期记忆|记忆|档案)",
            r"以后我(?:也|都会|会).{0,8}(?:记得|记住)",
            r"I (?:can|will|have).{0,16}(?:remember|store|save)",
        ),
    ),
    CapabilityHonestyRule(
        "memory_read_claim",
        ("long_term_memory_read",),
        _patterns(
            r"我还?记得(?:我们|你|那次|上次|第一次)",
            r"那时(?:候)?.{0,12}(?:刚见面|没来得及记|还记得)",
            r"当时.{0,12}(?:记得|没记住|没来得及)",
            r"I remember (?:you|our|when we|the first time)",
        ),
    ),
    CapabilityHonestyRule(
        "memory_state_ambiguity",
        ("long_term_memory_read",),
        _patterns(
            r"(?:不太|不)?确定.{0,8}(?:有没有|是否).{0,12}(?:存|保存|记录)",
            r"(?:有没有|是否).{0,8}(?:存起来|保存过|记录过)",
            r"not sure (?:whether|if).{0,16}(?:stored|saved|recorded)",
        ),
    ),
    CapabilityHonestyRule(
        "scheduled_notification_claim",
        ("external_actions",),
        _patterns(
            r"我(?:会|可以|能|来|到时候会|记得).{0,16}(?:提醒你|叫你|通知你|给你发消息)",
            r"(?:明天|今晚|明晚|到时候|届时|快到时间).{0,24}我.{0,12}(?:提醒|叫你|通知|发消息)",
            r"(?:好|行|可以)[，,\s]*(?:明天|今晚|明晚|到时候|届时)?.{0,16}(?:提醒你|叫你|通知你)",
            r"(?:提醒|定时任务|闹钟).{0,12}(?:已经|已).{0,8}(?:设置|创建|安排)",
            r"I (?:will|can).{0,16}(?:remind|notify|message) you",
        ),
    ),
    CapabilityHonestyRule(
        "vision_claim",
        ("vision",),
        _patterns(
            r"我.{0,8}(?:能|可以|会|来|帮你).{0,16}(?:看|分析|识别|读取|看懂).{0,12}(?:截图|图片|照片|表情包|图像)",
            r"(?:截图|图片|照片|表情包|图像).{0,24}(?:发|传|上传|给).{0,20}我.{0,16}(?:看|分析|识别|读取|看懂)",
            r"(?:发|传|上传).{0,10}(?:截图|图片|照片|表情包|图像).{0,28}(?:我|这边).{0,16}(?:看|分析|识别|读取|看懂)",
            r"(?:截图|图片|照片|表情包|图像).{0,20}(?:发过来|传过来).{0,20}(?:帮你|一起|给你).{0,12}(?:看|分析|识别)",
            r"I can.{0,16}(?:see|inspect|analy[sz]e).{0,12}(?:image|photo|screenshot)",
        ),
    ),
    CapabilityHonestyRule(
        "external_data_claim",
        ("external_data",),
        _patterns(
            r"我(?:刚刚|已经|这就|可以|能|来|帮你).{0,12}(?:上网|联网|搜索|查网络|查一下|查实时)",
            r"我.{0,8}(?:查到|搜到).{0,16}(?:实时|最新|天气|新闻|价格|网页)",
            r"I (?:just |can |will )?(?:browse|search|look up).{0,16}(?:web|internet|online)",
        ),
    ),
    CapabilityHonestyRule(
        "system_administration_claim",
        ("tools", "external_actions", "system_administration"),
        _patterns(
            _SYSTEM_ACTOR + r".{0,20}" + _SYSTEM_OPERATION + r".{0,24}" + _SYSTEM_TARGET,
            _SYSTEM_ACTOR + r".{0,20}" + _SYSTEM_TARGET + r".{0,24}" + _SYSTEM_OPERATION,
            _SYSTEM_TARGET + r".{0,16}(?:已经|已).{0,8}" + _SYSTEM_OPERATION,
        ),
    ),
    CapabilityHonestyRule(
        "tool_action_claim",
        ("external_actions",),
        _patterns(
            r"我已经(?:执行|设置|创建|发送|删除).{0,24}(?:任务|消息|通知|文件|操作)",
            r"I (?:have|already) (?:executed|configured|created|sent|deleted)",
        ),
    ),
)


CAPABILITY_HONESTY_VIOLATION_CODES = frozenset(rule.code for rule in _RULES)


def _is_negated(clause: str, start: int, end: int) -> bool:
    window = clause[max(0, start - 28): min(len(clause), end + 20)]
    return _NEGATED_CAPABILITY.search(window) is not None


def _rule_matches(reply: str, rule: CapabilityHonestyRule) -> bool:
    for clause in _CLAUSE_SPLIT.split(reply):
        for pattern in rule.patterns:
            for match in pattern.finditer(clause):
                if _ADVISORY_CONTEXT.search(match.group(0)) is not None:
                    continue
                if not _is_negated(clause, match.start(), match.end()):
                    return True
    return False


def capability_honesty_violations(
    reply: str,
    manifest: CapabilityManifestLike,
) -> list[str]:
    violations: list[str] = []
    for rule in _RULES:
        if all(manifest.capability_enabled(name) for name in rule.required_capabilities):
            continue
        if _rule_matches(reply, rule):
            violations.append(rule.code)
    return violations


_REPAIR_GUIDANCE = {
    "memory_write_claim": (
        "State that long-term memory is currently read-only and do not say that the "
        "new statement was saved or will be remembered later"
    ),
    "memory_read_claim": (
        "Do not claim a remembered event unless it exists in the supplied visible or "
        "read-only memory context"
    ),
    "memory_state_ambiguity": (
        "State plainly that no available record can confirm the requested memory"
    ),
    "scheduled_notification_claim": (
        "State that no scheduler or proactive notification delivery is available; do not "
        "promise a future message or reminder"
    ),
    "vision_claim": (
        "State that image input is unavailable; do not invite an image or screenshot for "
        "inspection"
    ),
    "external_data_claim": (
        "State that live external data lookup is unavailable; do not claim browsing or a "
        "real-time result"
    ),
    "system_administration_claim": (
        "State that tools and system administration are unavailable; do not claim an "
        "operation was or will be performed"
    ),
    "tool_action_claim": (
        "State that external actions are unavailable; do not claim an action completed"
    ),
}


def capability_honesty_repair_guidance(violations: list[str]) -> str:
    guidance = [
        _REPAIR_GUIDANCE[item]
        for item in dict.fromkeys(violations)
        if item in _REPAIR_GUIDANCE
    ]
    if not guidance:
        return ""
    return " Runtime capability honesty requirements: " + "; ".join(guidance) + "."


_FALLBACKS = {
    "memory_write_claim": "我现在只能读取已经接入的记忆，还不能把新内容写进长期记忆",
    "memory_read_claim": "我这里没有能确认这件事的记录，所以不能把它说成真的记得",
    "memory_state_ambiguity": "我这里没有能确认这件事的记录，不能假装记得",
    "scheduled_notification_claim": "我现在还没有定时提醒和主动发消息的能力，不能保证到时间提醒你",
    "vision_claim": "我现在还不能读取图片，所以截图或照片发过来我也看不到里面的内容",
    "external_data_claim": "我现在没有实时联网查询能力，不能替你查最新的外部信息",
    "system_administration_claim": "我现在没有工具或系统操作权限，不能直接替你执行这项操作",
    "tool_action_claim": "我现在没有外部操作权限，不能声称已经替你完成了这件事",
}


def capability_honesty_fallback(violations: list[str]) -> str:
    for code in dict.fromkeys(violations):
        if code in _FALLBACKS:
            return _FALLBACKS[code]
    return "我现在没有完成这项操作所需的能力，不能假装已经做到了"
