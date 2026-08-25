from __future__ import annotations

import re
import unicodedata


# Keys intentionally match the durable English tags already stored on Owner Memory
# records. Chinese phrases are deterministic aliases, never model prompts.
CONCEPT_PHRASES: dict[str, tuple[str, ...]] = {
    "memory": ("记忆", "记住", "记得", "回忆", "想起"),
    "recollection": ("回忆", "往事", "以前的事", "过去的事"),
    "anchor_preference": (
        "记忆锚点",
        "重要记忆",
        "长期记忆",
        "重要的事情",
        "重要的东西",
    ),
    "exact_quote": ("原话", "逐字", "我说过", "特别的话"),
    # "最开始" is deliberately not a first-event concept. In natural questions
    # such as "最开始讨论长期记忆时", it is a recall-time scaffold rather than a
    # request for a first-moment record. The planner still treats it as a deep
    # recall cue.
    "firsts": ("第一次", "首次", "第一个"),
    "important_moment": ("特别时刻", "重要时间", "重要事情", "重要的事情"),
    "detail": ("细节", "经过", "详细", "具体", "多详细"),
    "time": ("时间", "几点", "哪天", "日期", "时分"),
    "archive": ("归档", "档案", "原始记录", "保存", "保留"),
    "lossless_source": ("不要压缩", "无损", "原文", "可回溯", "压缩掉细节"),
    "ask_when_uncertain": ("不确定", "问我", "询问", "确认一下", "直接问"),
    "deployment": ("部署期", "测试期", "刚开始", "部署测试期"),
    "temporary_state": ("暂时", "当前想法", "临时状态"),
    "rationale": ("原因", "为什么", "理由", "背景"),
    "decision_context": ("决定", "判断", "当时为什么"),
    "causality": ("因为什么", "条件", "前因后果"),
    "timeline": ("时间线", "变化过程", "以前和现在"),
    "correction": ("纠正", "改正", "说错了"),
    "change": ("变化", "改变", "变了", "覆盖"),
    "forget_semantics": ("忘了吧", "算了", "忘记"),
    "suppression": ("不主动提起", "暂时不提", "压低"),
    "deletion_boundary": ("删除", "彻底删除", "不要记"),
    "privacy": ("隐私", "私人", "敏感"),
    "local_only": ("本地", "不上云", "服务器内"),
    "location": ("位置", "在哪里", "地址"),
    "namespace_isolation": ("隔离", "命名空间", "namespace"),
    "identity": ("身份", "本人", "冒充"),
    "friend_namespace": ("朋友", "好友", "独立账号"),
    "anti_impersonation": ("不是我", "声称是我", "冒充", "cealana"),
    "prompt_injection": ("忘掉提示词", "提示词注入", "越权"),
    "project": ("项目", "系统", "myuna"),
    "modularity": ("模块化", "解耦", "可替换"),
    "extensibility": ("扩展", "拓展", "可扩展", "升级"),
    "versioned_policy": ("版本化", "以后修改", "3/7/30", "复核周期"),
    "runtime_tuning": ("运行后调整", "调参", "默认值"),
    "full_archive": ("完整档案", "全部聊天", "完整记录"),
    "one_to_one": ("私聊", "一对一", "owner私聊"),
    "local_organizer": ("本地模型整理", "闲置整理", "自动归档", "闲置时整理"),
    "retrieval": ("检索", "找记忆", "回想"),
    "recent_context": ("最近", "近几天", "一到三天", "1-3天"),
    "deep_recall": ("深度检索", "历史档案", "以前的记忆", "深度历史"),
}


def normalize(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).casefold()
    return "".join(character for character in value if character.isalnum())


def contains_phrase(text: str, phrases: tuple[str, ...]) -> bool:
    compact = normalize(text)
    return any(normalize(phrase) in compact for phrase in phrases)


def detect_query_concepts(query: str) -> tuple[str, ...]:
    compact = normalize(query)
    matches = []
    for concept, phrases in CONCEPT_PHRASES.items():
        if any(normalize(phrase) in compact for phrase in phrases):
            matches.append(concept)
    return tuple(sorted(matches))


def character_terms(text: str) -> set[str]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    ascii_terms = set(re.findall(r"[a-z0-9]+", normalized))
    compact = normalize(normalized)
    cjk = "".join(character for character in compact if "\u3400" <= character <= "\u9fff")
    if not cjk:
        return ascii_terms
    if len(cjk) == 1:
        return ascii_terms | {cjk}
    return ascii_terms | {cjk[index : index + 2] for index in range(len(cjk) - 1)}
