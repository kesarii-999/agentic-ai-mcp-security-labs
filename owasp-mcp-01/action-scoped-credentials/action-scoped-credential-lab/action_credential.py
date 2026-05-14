"""
Action-scoped credentials: bind one execution to tool name, input hash, capability, TTL, nonce.

Signing uses HMAC-SHA256 over canonical JSON of signed fields. Replay prevention via
in-memory nonce set (process lifetime).
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from typing import Any

from capability_issuer import canonical_json


def tool_input_hash(tool_input: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(tool_input).encode("utf-8")).hexdigest()


_replay_lock = threading.Lock()
_used_nonces: set[str] = set()


def _sign(signing_key: bytes, message: str) -> str:
    return hmac.new(signing_key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_action_scoped_credential(
    capability: dict[str, Any],
    tool_name: str,
    tool_input: dict[str, Any],
    ttl_secs: int,
    signing_key: bytes,
    nonce: str,
) -> dict[str, Any]:
    """
    Mint an action-scoped credential bound to capability_id, tool_name, tool_input hash,
    exp/iat, and one-time nonce. `capability` must be the verified dict (includes sig).
    """
    cap_id = capability["capability_id"]
    now = int(time.time())
    t_hash = tool_input_hash(tool_input)
    payload = {
        "capability_id": cap_id,
        "tool_name": tool_name,
        "tool_input_hash": t_hash,
        "exp": now + int(ttl_secs),
        "iat": now,
        "nonce": nonce,
    }
    sig = _sign(signing_key, canonical_json(payload))
    out = dict(payload)
    out["sig"] = sig
    return out


def verify_action_scoped_credential(
    credential: dict[str, Any],
    signing_key: bytes,
    tool_input: dict[str, Any],
    tool_name: str,
) -> tuple[bool, str]:
    """
    Verify signature, expiry, tool_name binding, tool_input hash binding, and one-time nonce.

    On full success, records nonce to prevent replay. Signature/expiry/hash failures
    do not consume the nonce.
    """
    if not isinstance(credential, dict):
        return False, "invalid_credential_shape"
    sig = credential.get("sig")
    if not isinstance(sig, str):
        return False, "missing_signature"

    nonce = credential.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return False, "missing_nonce"

    payload = {k: v for k, v in credential.items() if k != "sig"}
    expected = _sign(signing_key, canonical_json(payload))
    if not hmac.compare_digest(expected, sig):
        return False, "bad_signature"

    now = int(time.time())
    exp = payload.get("exp")
    if not isinstance(exp, int) or now > exp:
        return False, "expired_or_invalid_exp"

    if payload.get("tool_name") != tool_name:
        return False, "tool_name_mismatch"

    if payload.get("tool_input_hash") != tool_input_hash(tool_input):
        return False, "tool_input_hash_mismatch"

    cap_id = payload.get("capability_id")
    if not isinstance(cap_id, str) or not cap_id:
        return False, "invalid_capability_id"

    # Atomic one-time consume after all cryptographic checks succeed
    with _replay_lock:
        if nonce in _used_nonces:
            return False, "replay_detected"
        _used_nonces.add(nonce)

    return True, "ok"
