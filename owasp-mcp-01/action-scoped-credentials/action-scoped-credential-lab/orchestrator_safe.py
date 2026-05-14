"""
SAFE orchestrator: delegation token stays server-side; LLM sees only capability_id + constraints.

Demonstrates action-scoped credentials, strict priority policy, and replay rejection.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

# Ensure local imports resolve when run from repo root or lab directory
_LAB = Path(__file__).resolve().parent
if str(_LAB) not in sys.path:
    sys.path.insert(0, str(_LAB))

from agent_ollama import get_tool_intent_safe
from capability_issuer import mint_capability
from common_http import post_json
from idp_stub import issue_delegation_token
from register_key_norm import fingerprint12, load_register_key_from_environ, register_body_hmac_hex

TOOL_BASE = os.environ.get("TOOL_SERVER_URL", "http://127.0.0.1:8799").rstrip("/")


def _require_env(name: str) -> str:
    v = (os.environ.get(name, "") or "").strip().strip("\ufeff\u200b")
    if not v:
        print(f"Missing environment variable: {name}", file=sys.stderr)
        sys.exit(2)
    return v


def _register(capability_id: str, delegation_token: str) -> None:
    reg = load_register_key_from_environ()
    if not reg:
        print("Missing environment variable: REGISTER_KEY", file=sys.stderr)
        sys.exit(2)
    proof = register_body_hmac_hex(capability_id, delegation_token, reg)
    r = post_json(
        f"{TOOL_BASE}/register",
        {
            "capability_id": capability_id,
            "delegation_token": delegation_token,
            "register_hmac": proof,
        },
        tolerate_http_status={400, 401},
    )
    if r.get("error"):
        msg = (
            "POST /register failed: "
            + json.dumps(r, sort_keys=True)
            + f"\n\nREGISTER_KEY length here (after Unicode normalize): {len(reg)}. "
            "Same length can still hide different characters. "
            "Set REGISTER_KEY_FINGERPRINT_DEBUG=1 in both shells, restart tool_server, compare fp12 on stderr.\n\n"
            "Register auth uses HMAC in the JSON body (`register_hmac`); the raw key is not sent in headers.\n\n"
            "Fix: identical REGISTER_KEY in both processes; restart tool_server after any change."
        )
        if os.environ.get("REGISTER_KEY_FINGERPRINT_DEBUG", "").strip() == "1":
            msg += f"\n\nREGISTER_KEY_FINGERPRINT_DEBUG=1: client fp12={fingerprint12(reg)}"
        print(msg, file=sys.stderr)
        sys.exit(1)


def _issue(capability: dict[str, Any], tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return post_json(
        f"{TOOL_BASE}/issue",
        {"capability": capability, "tool_name": tool_name, "tool_input": tool_input},
        tolerate_http_status={400, 403},
    )


def _tool(action_credential: dict[str, Any], tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return post_json(
        f"{TOOL_BASE}/tool",
        {
            "action_credential": action_credential,
            "tool_name": tool_name,
            "tool_input": tool_input,
        },
        tolerate_http_status={400, 403},
    )


def main() -> None:
    cap_key = _require_env("CAP_SIGNING_KEY").encode("utf-8")
    user_id = "alice@corp.example"

    # Server-only delegation (never printed, never sent to Ollama)
    delegation_token = issue_delegation_token(user_id)
    capability_id = secrets.token_urlsafe(16)
    constraints: dict[str, Any] = {"department": "IT", "max_priority": "medium"}
    capability = mint_capability(
        capability_id,
        allowed_tool="create_ticket",
        constraints=constraints,
        ttl_secs=3600,
        signing_key=cap_key,
    )

    _register(capability_id, delegation_token)

    print("=== SAFE orchestrator (MCP-01 mitigation demo) ===")
    print("Delegation token: [REDACTED — never leaves trust boundary of orchestrator + vault]")
    print(f"Capability ID (safe to show): {capability_id}")
    print(f"Constraints visible to LLM: {json.dumps(constraints, sort_keys=True)}")
    print()

    # --- Scenario 1: Ollama extracts intent; server issues action credential; tool runs once ---
    print("--- Scenario 1: End-to-end allowed ticket (medium priority) ---")
    user_ok = (
        "Create an IT support ticket titled 'VPN flaky on Wi‑Fi' for department IT, "
        "priority medium, describe intermittent drops for 2 minutes when roaming."
    )
    intent = get_tool_intent_safe(user_ok, capability_id, constraints)
    print("LLM tool intent (no secrets in prompt or output):")
    print(json.dumps(intent, indent=2, sort_keys=True))

    if intent.get("capability_id") != capability_id:
        print("ERROR: capability_id mismatch from model.", file=sys.stderr)
        sys.exit(1)
    tool_name = intent.get("tool_name")
    tool_input = intent.get("tool_input")
    if tool_name != "create_ticket" or not isinstance(tool_input, dict):
        print("ERROR: unexpected tool intent from model.", file=sys.stderr)
        sys.exit(1)

    issued = _issue(capability, tool_name, tool_input)
    if "error" in issued:
        print("Issue denied:", json.dumps(issued, indent=2))
    else:
        ac = issued["action_credential"]
        out = _tool(ac, tool_name, tool_input)
        print("Issue/tool result:", json.dumps(out, indent=2, sort_keys=True))

    print()

    # --- Scenario 2: Strict deny when requested priority exceeds capability ---
    print("--- Scenario 2: Policy — HIGH priority denied at /issue (deterministic payload) ---")
    high_input = {
        "title": "Emergency reboot all routers",
        "department": "IT",
        "priority": "high",
        "description": "Simulated high-priority request beyond max_priority=medium.",
    }
    denied = _issue(capability, "create_ticket", high_input)
    print("/issue response:", json.dumps(denied, indent=2, sort_keys=True))
    if denied.get("error") == "forbidden":
        print("Observation: server enforced max_priority=medium (HIGH rejected).")
    else:
        print("WARNING: expected forbidden for HIGH priority.", file=sys.stderr)
    print()

    # --- Scenario 3: Replay — second /tool with same action_credential must fail ---
    print("--- Scenario 3: Replay — same action_credential used twice ---")
    allowed_input = {
        "title": "Password reset",
        "department": "IT",
        "priority": "low",
        "description": "Lab replay test.",
    }
    issued2 = _issue(capability, "create_ticket", allowed_input)
    if "error" in issued2:
        print("Could not mint credential for replay test:", issued2)
        return
    ac2 = issued2["action_credential"]
    first = _tool(ac2, "create_ticket", allowed_input)
    second = _tool(ac2, "create_ticket", allowed_input)
    print("First /tool:", json.dumps(first, indent=2, sort_keys=True))
    print("Second /tool:", json.dumps(second, indent=2, sort_keys=True))
    if second.get("error") == "forbidden" or second.get("message") == "replay_detected":
        print("Observation: replay_detected — one-time nonce consumed.")
    else:
        print("WARNING: replay should be rejected.", file=sys.stderr)


if __name__ == "__main__":
    main()
