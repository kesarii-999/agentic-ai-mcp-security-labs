"""
Stub Identity Provider: issues pseudo delegation tokens (server-side only in SAFE flows).

These tokens represent broad delegated authority and must never be placed in LLM context
(OWASP MCP-01). The SAFE orchestrator uses them only for vault registration and tool
execution after action-scoped verification.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time


def issue_delegation_token(user_id: str) -> str:
    """
    Return a pseudo delegation token (opaque, base64url-like).
    Not a real JWT; sufficient for lab demonstration of vault lookup.
    """
    rnd = secrets.token_bytes(24)
    ts = str(int(time.time())).encode()
    raw = user_id.encode("utf-8") + b"|" + ts + b"|" + rnd
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest() + rnd[:8]).decode(
        "ascii"
    )
