from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Mapping, Sequence


class PersonaGroundingClass(str, Enum):
    UNSCOPED = "unscoped"
    SOFT_PERSONA_DAILY_LIFE = "soft_persona_daily_life"
    REAL_WORLD_OBSERVATION = "real_world_observation"
    EXTERNAL_OPERATION = "external_operation"


INFRASTRUCTURE_REALITY_PLAUSIBILITY_REJECTION_ENABLED = False
REALITY_PLAUSIBILITY_GUIDANCE_AUTHORITY = "model_definition"


@dataclass(frozen=True, slots=True)
class PersonaGroundingDecision:
    category: PersonaGroundingClass
    reason: str

    @property
    def allows_recent_event_soft_fiction(self) -> bool:
        return self.category is PersonaGroundingClass.SOFT_PERSONA_DAILY_LIFE


_QUESTION_MARKER = re.compile(r"[？?]|(?:吗|嘛|呢|么|什么|怎样|怎么样|如何|有没有|是不是)\s*$", re.I)
_RECENT_OR_PRESENT_TIME = re.compile(
    r"今天|今日|昨天|昨晚|今早|早上|上午|中午|下午|傍晚|晚上|夜里|半夜|"
    r"刚才|刚刚|方才|现在|这会儿|这阵子|最近|前几天",
    re.I,
)
_PERSONA_DAILY_LIFE = re.compile(
    r"在家|出门|出去|回来|回家|做(?:了)?什么|干(?:了)?什么|干嘛|忙什么|"
    r"有什么打算|打算做什么|准备做什么|过得|怎么样|还好吗|累不累|困不困|"
    r"睡(?:得|了|觉)|起床|吃(?:了|饭)|喝(?:了|水)|休息|散步|逛|看书|看电影|"
    r"听歌|玩|拍照|摄影|整理(?:自己)?的?照片|心情|开心|难过|无聊|在想什么",
    re.I,
)
_DIRECT_PERSONA_REFERENCE = re.compile(r"你|Myuna|缪娜|米尤娜", re.I)
_ANAPHORIC_FOLLOW_UP = re.compile(
    r"^(?:那|然后|后来|再后来|结果|接着|之后)?(?:呢|怎么样|然后呢|后来呢|结果呢)[？?]?$",
    re.I,
)
_REAL_WORLD_OBSERVATION = re.compile(
    r"天气|气温|温度|下雨|下雪|刮风|空气质量|日出|日落|实时|定位|位置|"
    r"窗外|外面.{0,12}(?:云|雨|雪|风|太阳|月亮|天色)|"
    r"(?:云|雨|雪|风|太阳|月亮|天色).{0,12}(?:窗外|外面)",
    re.I | re.S,
)
_EXTERNAL_OPERATION_OR_ASSET = re.compile(
    r"(?:帮我|替我|给我|我的|我发的|你收到的).{0,24}"
    r"(?:照片|相册|图片|截图|文件|文档|服务器|电脑|设备|手机|账号|账户|QQ|Telegram|消息|提醒)|"
    r"(?:重启|修改|删除|整理|上传|下载|发送|读取|查看|打开|关闭).{0,24}"
    r"(?:照片|相册|图片|截图|文件|文档|服务器|电脑|设备|手机|账号|账户|QQ|Telegram|消息|提醒)|"
    r"(?:服务器|电脑|设备|手机|账号|账户|QQ|Telegram|文件|文档).{0,24}"
    r"(?:重启|修改|删除|上传|下载|发送|读取|打开|关闭|启动|停止|恢复|在线|掉线)|"
    r"(?:看见|看到|识别|读到).{0,16}(?:我发的)?(?:照片|图片|截图)",
    re.I | re.S,
)
def _looks_like_direct_daily_life_question(text: str) -> bool:
    has_question_shape = _QUESTION_MARKER.search(text.strip()) is not None
    if not has_question_shape:
        return False
    if _PERSONA_DAILY_LIFE.search(text) is not None:
        return True
    return (
        _RECENT_OR_PRESENT_TIME.search(text) is not None
        and (
            _DIRECT_PERSONA_REFERENCE.search(text) is not None
            or len(text.strip()) <= 18
        )
    )


def classify_persona_grounding(
    messages: Sequence[Mapping[str, str]],
    *,
    mode: str,
) -> PersonaGroundingDecision:
    if mode != "myuna" or not messages:
        return PersonaGroundingDecision(PersonaGroundingClass.UNSCOPED, "mode_not_myuna")

    final_text = messages[-1]["content"].strip()
    if _EXTERNAL_OPERATION_OR_ASSET.search(final_text) is not None:
        return PersonaGroundingDecision(
            PersonaGroundingClass.EXTERNAL_OPERATION,
            "external_operation_or_asset",
        )
    if _REAL_WORLD_OBSERVATION.search(final_text) is not None:
        return PersonaGroundingDecision(
            PersonaGroundingClass.REAL_WORLD_OBSERVATION,
            "real_world_observation",
        )
    if _looks_like_direct_daily_life_question(final_text):
        return PersonaGroundingDecision(
            PersonaGroundingClass.SOFT_PERSONA_DAILY_LIFE,
            "direct_daily_life_question",
        )

    if _ANAPHORIC_FOLLOW_UP.fullmatch(final_text) is not None:
        prior_user_messages = [
            message["content"]
            for message in messages[:-1]
            if message["role"] == "user"
        ][-3:]
        if any(
            _EXTERNAL_OPERATION_OR_ASSET.search(text) is None
            and _REAL_WORLD_OBSERVATION.search(text) is None
            and _looks_like_direct_daily_life_question(text)
            for text in prior_user_messages
        ):
            return PersonaGroundingDecision(
                PersonaGroundingClass.SOFT_PERSONA_DAILY_LIFE,
                "anaphoric_daily_life_follow_up",
            )

    return PersonaGroundingDecision(PersonaGroundingClass.UNSCOPED, "no_soft_fiction_invitation")


def runtime_prompt_boundary(decision: PersonaGroundingDecision) -> str:
    if not decision.allows_recent_event_soft_fiction:
        return ""
    return (
        "The Owner's final message directly invites a low-stakes in-character answer about "
        "Myuna's own ordinary daily life, present state, or near-term plans. Myuna may answer "
        "naturally with modest provisional soft fiction consistent with the approved Definition "
        "and current conversation. Do not label it as fiction in the public reply. Treat new detail "
        "as volatile conversation context only, never verified external reality, stable canon, shared "
        "history, or long-term memory. Never use this allowance to claim real weather or sensory data, "
        "access to the Owner's photos or files, system or account operations, or an actual physical "
        "meeting with the Owner. Prefer a small bounded answer over a detailed invented itinerary."
    )


def repair_prompt_boundary(decision: PersonaGroundingDecision) -> str:
    if decision.allows_recent_event_soft_fiction:
        return (
            "The final user message directly invites a low-stakes answer about Myuna's own daily "
            "life or present state. A modest provisional soft-fiction answer is allowed. Keep it "
            "consistent and bounded; do not turn it into verified reality, stable canon, memory, "
            "external sensing, Owner asset access, system work, or a real meeting."
        )
    return (
        "Do not invent current or recent weather, unseen scenes outside the window, outings, "
        "encounters, or personal events as factual filler; stay with the present exchange or "
        "explicitly frame an imagined scene."
    )
