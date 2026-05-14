"""
Normalize REGISTER_KEY the same way on client and server (Unicode + invisible chars).

HMAC signing keys are not passed through this module — only the register shared secret.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import unicodedata
from typing import Any

from capability_issuer import canonical_json


def normalize_register_key(s: str) -> str:
    """Strip BOM/ZWSP, whitespace ends, then NFKC so client/server agree on look-alike characters."""
    t = (s or "").strip().strip("\ufeff\u200b")
    return unicodedata.normalize("NFKC", t)


def x_register_key_from_headers(headers: Any) -> str:
    """Read X-Register-Key case-insensitively (some stacks vary header field casing)."""
    raw = ""
    try:
        for k, v in headers.items():
            if str(k).lower() == "x-register-key" and v is not None:
                raw = str(v)
                break
    except (AttributeError, TypeError):
        pass
    if not raw:
        raw = headers.get("X-Register-Key") or headers.get("x-register-key") or ""
    return normalize_register_key(str(raw))


def load_register_key_from_environ() -> str:
    """REGISTER_KEY from the environment, normalized (must match tool_server)."""
    return normalize_register_key(os.environ.get("REGISTER_KEY", ""))


def fingerprint12(s: str) -> str:
    """First 12 hex chars of SHA-256 (for REGISTER_KEY_FINGERPRINT_DEBUG only)."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def register_body_hmac_hex(capability_id: str, delegation_token: str, register_key: str) -> str:
    """
    HMAC-SHA256(REGISTER_KEY, canonical_json({capability_id, delegation_token})) as lowercase hex.

    Proves possession of REGISTER_KEY for this exact registration payload without sending the
    secret in an HTTP header (avoids Latin-1 / folding issues on some stacks).
    """
    payload = {"capability_id": capability_id, "delegation_token": delegation_token}
    msg = canonical_json(payload)
    return hmac.new(
        register_key.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
