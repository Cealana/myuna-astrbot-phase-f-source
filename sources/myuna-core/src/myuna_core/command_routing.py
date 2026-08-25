from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re


class CommandParseError(ValueError):
    def __init__(self, code: str, command_text: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.command_text = command_text


class CommandName(str, Enum):
    TESTFLIGHT = "testflight"
    CHECKLIST = "checklist"
    INFO = "info"
    WORKBENCH = "workbench"
    EXIT_WORKBENCH = "exitworkbench"
    CHECK = "check"
    BLUEOUT = "blueout"
    DIARY = "diary"
    BENCHMARK = "benchmark"


@dataclass(frozen=True, slots=True)
class ParsedCommand:
    name: CommandName
    parameter: str | None
    source: str

    @property
    def is_immediate_stop(self) -> bool:
        return self.name is CommandName.BLUEOUT


_SLASH_COMMAND = re.compile(r"^/([A-Za-z][A-Za-z0-9_-]*)(?:[ \t]+([^\r\n]+))?$")


class CommandParser:
    """Whole-message deterministic parser that runs before persona routing."""

    def parse(self, text: str) -> ParsedCommand | None:
        if not isinstance(text, str):
            raise CommandParseError("invalid_command_input")
        candidate = text.strip()
        if candidate.casefold() == "blueout":
            return ParsedCommand(CommandName.BLUEOUT, None, "plain-alias")
        if not candidate.startswith("/"):
            return None
        match = _SLASH_COMMAND.fullmatch(candidate)
        if match is None:
            raise CommandParseError("malformed_command", candidate[:64])
        raw_name = match.group(1).casefold()
        try:
            name = CommandName(raw_name)
        except ValueError:
            raise CommandParseError("unknown_command", "/" + match.group(1)) from None
        parameter = match.group(2)
        if parameter is not None:
            parameter = parameter.strip()
        if name is CommandName.BLUEOUT and parameter:
            raise CommandParseError("blueout_rejects_parameters", "/Blueout")
        return ParsedCommand(name, parameter or None, "slash-command")


def render_command_error(error: CommandParseError) -> str:
    if error.code == "unknown_command":
        return f"[COMMAND ERROR]\n未知指令：{error.command_text}"
    return "[COMMAND ERROR]\n指令格式无效"
