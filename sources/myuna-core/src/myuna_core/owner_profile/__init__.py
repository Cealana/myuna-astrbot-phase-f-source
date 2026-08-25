"""Owner-authored, read-only Profile Baseline source foundation."""

from .approval import (
    APPROVAL_FILENAME,
    APPROVAL_TYPE,
    ProfileReleaseApproval,
    parse_profile_approval_bytes,
    verify_profile_approval,
)
from .contracts import (
    DOCUMENT_TYPE,
    PROFILE_CATEGORIES,
    SCHEMA_VERSION,
    OwnerProfile,
    OwnerProfileError,
    OwnerProfileSection,
    ProfileReceipt,
    RetrievalResult,
    RetrievedProfileSection,
)
from .loader import build_receipt, load_approved_profile
from .projection import error_audit_projection, success_audit_projection
from .retrieval import OwnerProfileIndex, render_profile_context, retrieve_from_loader

__all__ = [
    "APPROVAL_FILENAME",
    "APPROVAL_TYPE",
    "DOCUMENT_TYPE",
    "PROFILE_CATEGORIES",
    "SCHEMA_VERSION",
    "OwnerProfile",
    "OwnerProfileError",
    "OwnerProfileIndex",
    "OwnerProfileSection",
    "ProfileReleaseApproval",
    "ProfileReceipt",
    "RetrievalResult",
    "RetrievedProfileSection",
    "build_receipt",
    "error_audit_projection",
    "load_approved_profile",
    "parse_profile_approval_bytes",
    "render_profile_context",
    "retrieve_from_loader",
    "success_audit_projection",
    "verify_profile_approval",
]
