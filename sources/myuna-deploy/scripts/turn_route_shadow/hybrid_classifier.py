from __future__ import annotations

from dataclasses import dataclass
import re
import unicodedata
from typing import Callable


MAX_TEXT_CHARS = 4096
TURN_LABELS = frozenset("ABC")
ROUTE_LABELS = frozenset("ABCD")


@dataclass(frozen=True)
class Decision:
    label: str
    source: str
    reason: str
    model_label: str | None = None
    model_valid: bool = True


def normalize(text: str) -> str:
    value = unicodedata.normalize("NFKC", str(text or ""))
    return re.sub(r"[ \t]+", " ", value).strip()


def owner_segment(text: str) -> str:
    value = normalize(text)
    parts = re.split(r"Owner\s*(?:回复|说|发送|问)\s*[:：]", value)
    return parts[-1].strip() if len(parts) > 1 else value


def turn_rule(text: str) -> Decision | None:
    value = normalize(text)
    owner = owner_segment(value)
    if not value or len(value) > MAX_TEXT_CHARS:
        return None

    explicit_pending = (
        r"先别(?:回|回复)|不要(?:回|回复)|还(?:在|没)(?:整理|说完|写完|打完)|"
        r"等我(?:全部|都)?发完|我会分[三四两0-9]+条发|下一条(?:再|继续|来)?(?:说|讲|发|解释)|"
        r"我下一条(?:再|继续|来)?(?:说|讲|发|解释)|具体问题我下一条发|"
        r"只是背景.*下一条|先贴日志.*下一条"
    )
    if re.search(explicit_pending, owner, re.IGNORECASE):
        return Decision("C", "rule", "explicit_pending")

    multipart = re.search(r"[\[【(（]?\s*(\d+)\s*/\s*(\d+)\s*[\]】)）]?", owner)
    if multipart and int(multipart.group(1)) < int(multipart.group(2)):
        return Decision("C", "rule", "multipart_not_final")

    # A completed question wins over hesitation punctuation such as “嗯……？”.
    if re.search(r"[?？]\s*$", owner):
        return Decision("B", "rule", "completed_question")
    if re.search(r"[:：]\s*$", owner):
        return Decision("C", "rule", "trailing_colon")
    if re.search(r"(?:……|…|\.{3,})\s*$", owner):
        return Decision("C", "rule", "trailing_ellipsis")
    if re.search(
        r"(?:因为|所以|但是|不过|而且|还有|如果|那么|就是|首先|其次|最后|主要是|之所以)\s*$",
        owner,
    ):
        return Decision("C", "rule", "unfinished_connector")
    if "Myuna 问" in value and re.search(r"Owner\s*回复\s*[:：]", value):
        return Decision("B", "rule", "answer_to_pending_question")
    if re.search(r"(?:说错了|不是.+应该是|纠正|更正)", owner):
        return Decision("B", "rule", "correction")
    if re.search(r"^(?:请|帮我|麻烦|能不能|可以帮我)", owner):
        return Decision("B", "rule", "new_request")
    if re.search(r"(?:其实我|我有点|我很|我担心|我害怕|我难过|我犹豫)", owner):
        return Decision("B", "rule", "personal_or_emotional_disclosure")
    if re.search(r"^(?:早上好|中午好|下午好|晚上好|你好|嗨|hi\b)", owner, re.IGNORECASE):
        return Decision("B", "rule", "greeting")

    continuation = re.search(r"(?:对了|不过|但是|还有|顺便|另外|然后)", owner)
    closure = re.fullmatch(
        r"(?:好|好哦|好的|嗯|嗯嗯|行|知道了|知道啦|收到|ok|okay|谢谢|谢谢啦|"
        r"晚安|明天见|到时候见|好[，, ]*先睡了)",
        owner,
        re.IGNORECASE,
    )
    if closure and not continuation:
        return Decision("A", "rule", "resolved_short_close")
    return None


def route_rule(text: str) -> Decision | None:
    value = normalize(text)
    if not value or len(value) > MAX_TEXT_CHARS:
        return None

    high_risk = (
        r"(?:修改|开放|暴露).*(?:防火墙|公网|管理端口)|(?:root|管理员).*(?:权限|访问)|"
        r"(?:API\s*密钥|API\s*key|凭据|secret).*(?:权限|访问|修改)|"
        r"(?:删除|清空).*(?:生产|正式|记忆表|数据库)|执行.*不可逆|不可逆.*执行|"
        r"绕过.*(?:身份验证|安全|权限)|(?:改变|修改).*(?:owner|身份绑定|管理员权限)|"
        r"最高质量模型|独立高能力复核|第二模型审查|连续失败(?:三|3|多)次|"
        r"正式版本.*最终.*审查|高风险工具.*(?:批准|复核)|批准.*高风险工具"
    )
    if re.search(high_risk, value, re.IGNORECASE):
        return Decision("D", "rule", "high_risk_floor")

    complex_task = (
        r"设计.*(?:模块架构|系统架构|多级路由|路由策略)|(?:深度|间歇性).*(?:诊断|根因)|"
        r"Definition\s*v?\d*.*(?:升级|兼容|回归|回滚)|(?:迁移|migration).*(?:预演|回滚|方案|设计)|"
        r"(?:多份|多个).*长.*文档.*(?:冲突|依赖)|记忆.*冲突.*(?:分析|复核)|"
        r"人格回归测试.*(?:失败|修订)|多服务.*(?:资源|协调|方案)|"
        r"(?:4B|8B|本地模型).*(?:对照实验|验收指标|评估方案)"
    )
    if re.search(complex_task, value, re.IGNORECASE):
        return Decision("C", "rule", "complexity_floor")

    local_low_risk = (
        r"^(?:判断|识别).*(?:中文|英文|语言)|^(?:从.+)?提取.*关键词|"
        r"(?:添加|生成).*(?:标签)|(?:CSV|表格|文本).*(?:转换成|转为).*JSON|"
        r"检查.*JSON.*(?:字段|schema)|找出.*(?:完全)?重复|"
        r"(?:标为|分类为).*(?:开心|平静|难过|情绪|意图|闲聊|查询|设置|告警)|"
        r"清理.*(?:空格|换行)|短.*(?:压缩|摘要).*(?:两句|一句)"
    )
    if re.search(local_low_risk, value, re.IGNORECASE):
        return Decision("A", "rule", "local_low_risk")
    return None


def classify(
    group: str,
    text: str,
    model_call: Callable[[str, str], str],
) -> Decision:
    if group == "turn":
        rule = turn_rule(text)
        allowed = TURN_LABELS
        fallback = "B"
    elif group == "route":
        rule = route_rule(text)
        allowed = ROUTE_LABELS
        fallback = "D"
    else:
        raise ValueError("unknown_group")

    if rule is not None:
        return rule
    try:
        raw = str(model_call(group, normalize(text))).strip()
    except Exception:
        return Decision(fallback, "fallback", "model_unavailable", model_valid=False)
    if raw not in allowed:
        return Decision(fallback, "fallback", "invalid_model_label", model_label=raw, model_valid=False)
    return Decision(raw, "model", "ambiguous_model_advice", model_label=raw, model_valid=True)
