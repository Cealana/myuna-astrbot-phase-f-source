from __future__ import annotations

from dataclasses import dataclass


SCHEMA_VERSION = 1
DOCUMENT_TYPE = "owner_profile_baseline"
RECEIPT_TYPE = "owner_profile_approval_v1"
AUDIT_NAMESPACE = "owner_profile_read_v1"

PROFILE_CATEGORIES = (
    "self_introduction",
    "long_term_preference",
    "long_term_goal",
    "ongoing_project",
)

PROFILE_FILENAME = "profile.toml"
RECEIPT_FILENAME = "receipt.json"
MAX_PROFILE_BYTES = 65_536
MAX_RECEIPT_BYTES = 16_384
MAX_SECTIONS = 32
MAX_TITLE_CHARACTERS = 120
MAX_BODY_CHARACTERS = 4_000
MAX_TOTAL_BODY_CHARACTERS = 32_000
MAX_KEYWORDS = 12
MAX_KEYWORD_CHARACTERS = 64
MAX_QUERY_CHARACTERS = 256
MAX_RESULTS = 3
MAX_CONTEXT_CHARACTERS = 6_000


class OwnerProfileError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class OwnerProfileSection:
    section_id: str
    topic_key: str
    category: str
    title: str
    body: str
    keywords: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OwnerProfile:
    profile_id: str
    profile_revision: int
    sections: tuple[OwnerProfileSection, ...]
    sha256: str
    byte_count: int

    @property
    def category_counts(self) -> tuple[tuple[str, int], ...]:
        return tuple(
            (category, sum(item.category == category for item in self.sections))
            for category in PROFILE_CATEGORIES
            if any(item.category == category for item in self.sections)
        )


@dataclass(frozen=True, slots=True)
class ProfileReceipt:
    profile_sha256: str
    profile_bytes: int
    profile_schema_version: int
    profile_id: str
    profile_revision: int
    section_count: int
    category_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class RetrievedProfileSection:
    rank: int
    category: str
    title: str
    body: str
    source_ref: str


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    state: str
    profile_revision: int
    profile_sha256: str
    query_characters: int
    sections: tuple[RetrievedProfileSection, ...]
    context: str | None

    @property
    def selected_categories(self) -> tuple[str, ...]:
        return tuple(item.category for item in self.sections)
