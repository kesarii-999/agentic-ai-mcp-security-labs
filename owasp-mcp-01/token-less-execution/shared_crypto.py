# shared_crypto.py
# In enterprise, this would be mTLS / workload identity.
# For the lab, we use a shared HMAC key between agent and tool server.
import hmac
import hashlib
import json
from typing import Dict, Any

def canonical_json(data: Dict[str, Any]) -> bytes:
    """
    Stable JSON encoding so both client and server sign the exact same bytes.
    """
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sign_payload(payload: Dict[str, Any], shared_key: str) -> str:
    msg = canonical_json(payload)
    mac = hmac.new(shared_key.encode("utf-8"), msg, hashlib.sha256)
    return mac.hexdigest()

def verify_signature(payload: Dict[str, Any], shared_key: str, signature_hex: str) -> bool:
    expected = sign_payload(payload, shared_key)
    return hmac.compare_digest(expected, signature_hex)