"""
HMAC-SHA256 signed capabilities: scope authorization (tool + constraints + lifetime).

Canonical JSON: sort_keys=True, separators=(",", ":") for signing and verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sign(signing_key: bytes, message: str) -> str:
    return hmac.new(signing_key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def mint_capability(
    capability_id: str,
    allowed_tool: str,
    constraints: dict[str, Any],
    ttl_secs: int,
    signing_key: bytes,
) -> dict[str, Any]:
    """
    Build a signed capability dict. `sig` covers all other fields (canonical JSON).
    """
    now = int(time.time())
    payload = {
        "capability_id": capability_id,
        "allowed_tool": allowed_tool,
        "constraints": constraints,
        "exp": now + int(ttl_secs),
        "iat": now,
    }
    msg = canonical_json(payload)
    sig = _sign(signing_key, msg)
    out = dict(payload)
    out["sig"] = sig
    return out


def verify_capability(capability: dict[str, Any], signing_key: bytes) -> tuple[bool, str]:
    """
    Verify HMAC and expiry. Returns (ok, reason).
    """
    if not isinstance(capability, dict):
        return False, "invalid_capability_shape"
    sig = capability.get("sig")
    if not isinstance(sig, str):
        return False, "missing_signature"
    payload = {k: v for k, v in capability.items() if k != "sig"}
    expected = _sign(signing_key, canonical_json(payload))
    if not hmac.compare_digest(expected, sig):
        return False, "bad_signature"
    exp = payload.get("exp")
    if not isinstance(exp, int):
        return False, "invalid_exp"
    if int(time.time()) > exp:
        return False, "expired"
    return True, "ok"
