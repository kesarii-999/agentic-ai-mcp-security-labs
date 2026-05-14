"""
Local tool server: capability registration (vault), action-credential issuance, gated tool execution.

Listens on **127.0.0.1:8799** by default (IPv4 loopback; avoids Windows localhost IPv4/IPv6 mismatch).

Environment:
  CAP_SIGNING_KEY          — HMAC key for capabilities (UTF-8 string)
  ACTION_CRED_SIGNING_KEY  — HMAC key for action-scoped credentials
  REGISTER_KEY             — shared secret for POST /register (HMAC body proof; optional legacy header)
  REGISTER_KEY_FINGERPRINT_DEBUG — set to 1 to log SHA-256 fp12 of REGISTER_KEY (lab debugging only)
  TOOL_SERVER_BIND         — optional bind address (default 127.0.0.1; use 0.0.0.0 only if you need LAN)
  TOOL_SERVER_PORT         — optional port (default 8799)
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import action_credential
import capability_issuer
from register_key_norm import (
    fingerprint12,
    load_register_key_from_environ,
    register_body_hmac_hex,
    x_register_key_from_headers,
)

# In-memory vault: capability_id -> delegation_token (never logged or returned to clients)
_VAULT: dict[str, str] = {}

_CAP_KEY: bytes
_ACTION_KEY: bytes
_REGISTER_KEY: str


def _audit(msg: str) -> None:
    print(f"[AUDIT] {msg}", file=sys.stderr, flush=True)


def _load_keys() -> None:
    global _CAP_KEY, _ACTION_KEY, _REGISTER_KEY
    # Strip BOM / zero-width space (common when copying from editors or chat)
    def _clean(s: str) -> str:
        return (s or "").strip().strip("\ufeff\u200b")

    cap = _clean(os.environ.get("CAP_SIGNING_KEY", ""))
    act = _clean(os.environ.get("ACTION_CRED_SIGNING_KEY", ""))
    reg = load_register_key_from_environ()
    if not cap or not act or not reg:
        print(
            "Missing env: CAP_SIGNING_KEY, ACTION_CRED_SIGNING_KEY, REGISTER_KEY",
            file=sys.stderr,
        )
        sys.exit(2)
    _CAP_KEY = cap.encode("utf-8")
    _ACTION_KEY = act.encode("utf-8")
    _REGISTER_KEY = reg
    _audit(f"keys_loaded register_key_char_len={len(_REGISTER_KEY)}")
    if os.environ.get("REGISTER_KEY_FINGERPRINT_DEBUG", "").strip() == "1":
        _audit(f"register_key_fp12_server={fingerprint12(_REGISTER_KEY)} (REGISTER_KEY_FINGERPRINT_DEBUG=1)")


def _json_response(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
    try:
        n = int(handler.headers.get("Content-Length", "0") or "0")
    except ValueError:
        n = 0
    raw = handler.rfile.read(n) if n > 0 else b""
    if not raw.strip():
        return {}
    try:
        val = json.loads(raw.decode("utf-8"))
        return val if isinstance(val, dict) else None
    except json.JSONDecodeError:
        return None


def _priority_rank(p: str) -> int | None:
    m = {"low": 0, "medium": 1, "high": 2}
    return m.get(p.strip().lower())


def _validate_tool_input(obj: Any) -> tuple[bool, str, dict[str, Any]]:
    if not isinstance(obj, dict):
        return False, "tool_input_not_object", {}
    required = ("title", "department", "priority", "description")
    for k in required:
        if k not in obj:
            return False, "missing_field", {}
        if not isinstance(obj[k], str):
            return False, "field_not_string", {}
    title = obj["title"].strip()
    if not title:
        return False, "empty_title", {}
    pr = _priority_rank(obj["priority"])
    if pr is None:
        return False, "invalid_priority", {}
    normalized = {
        "title": title,
        "department": obj["department"].strip(),
        "priority": obj["priority"].strip().lower(),
        "description": obj["description"],
    }
    return True, "ok", normalized


def _enforce_constraints(
    constraints: dict[str, Any], tool_input: dict[str, Any]
) -> tuple[bool, str]:
    want_dept = str(constraints.get("department", "")).strip().lower()
    got_dept = tool_input["department"].strip().lower()
    if got_dept != want_dept:
        return False, "department_not_allowed"
    max_p = constraints.get("max_priority")
    max_r = _priority_rank(str(max_p)) if max_p is not None else None
    req_r = _priority_rank(tool_input["priority"])
    if max_r is None or req_r is None:
        return False, "invalid_priority_constraint"
    # Strict: requested priority must not exceed max (deny HIGH when max is medium)
    if req_r > max_r:
        return False, "priority_exceeds_capability"
    return True, "ok"


def _handle_register(handler: BaseHTTPRequestHandler, body: dict[str, Any]) -> None:
    cid = body.get("capability_id")
    dtok = body.get("delegation_token")
    rh = body.get("register_hmac")
    if isinstance(rh, str):
        rh = rh.strip()

    hmac_ok = False
    if (
        isinstance(cid, str)
        and cid
        and isinstance(dtok, str)
        and dtok
        and isinstance(rh, str)
        and rh
    ):
        expected_hex = register_body_hmac_hex(cid, dtok, _REGISTER_KEY)
        if len(rh) == len(expected_hex) and secrets.compare_digest(
            rh.lower().encode("ascii"), expected_hex.lower().encode("ascii")
        ):
            hmac_ok = True

    key = x_register_key_from_headers(handler.headers)
    if not key:
        header_ok = False
    else:
        kb = key.encode("utf-8")
        rb = _REGISTER_KEY.encode("utf-8")
        header_ok = len(kb) == len(rb) and secrets.compare_digest(kb, rb)

    if not hmac_ok and not header_ok:
        _audit(
            "register_denied "
            f"hmac_ok={hmac_ok} header_ok={header_ok} "
            f"header_present={bool(key)} header_char_len={len(key)} "
            f"expected_char_len={len(_REGISTER_KEY)} "
            f"rh_type={type(body.get('register_hmac')).__name__}"
        )
        if os.environ.get("REGISTER_KEY_FINGERPRINT_DEBUG", "").strip() == "1":
            hk = fingerprint12(key) if key else "empty"
            sk = fingerprint12(_REGISTER_KEY)
            _audit(f"register_key_fp12_header={hk} register_key_fp12_expected={sk}")
        _json_response(handler, 401, {"error": "unauthorized", "message": "invalid_register_key"})
        return

    if not isinstance(cid, str) or not cid:
        _json_response(handler, 400, {"error": "bad_request", "message": "invalid_capability_id"})
        return
    if not isinstance(dtok, str) or not dtok:
        _json_response(handler, 400, {"error": "bad_request", "message": "invalid_delegation_token"})
        return
    _VAULT[cid] = dtok
    _audit(f"delegation_registered capability_id={cid}")
    _json_response(handler, 200, {"status": "registered", "capability_id": cid})


def _handle_issue(handler: BaseHTTPRequestHandler, body: dict[str, Any]) -> None:
    cap = body.get("capability")
    tool_name = body.get("tool_name")
    tool_input = body.get("tool_input")
    if not isinstance(cap, dict) or not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        _json_response(handler, 400, {"error": "bad_request", "message": "invalid_issue_payload"})
        return

    ok, reason = capability_issuer.verify_capability(cap, _CAP_KEY)
    if not ok:
        _audit(f"issue_denied reason={reason} tool_name={tool_name!r}")
        _json_response(handler, 403, {"error": "forbidden", "message": "capability_invalid"})
        return

    if cap.get("allowed_tool") != tool_name:
        _audit(f"issue_denied reason=tool_not_allowed capability_id={cap.get('capability_id')}")
        _json_response(handler, 403, {"error": "forbidden", "message": "tool_not_allowed"})
        return

    if tool_name != "create_ticket":
        _json_response(handler, 400, {"error": "bad_request", "message": "unknown_tool"})
        return

    ok_schema, sreason, normalized = _validate_tool_input(tool_input)
    if not ok_schema:
        _audit(f"issue_denied reason={sreason}")
        _json_response(handler, 400, {"error": "validation_failed", "message": sreason})
        return

    constraints = cap.get("constraints")
    if not isinstance(constraints, dict):
        _json_response(handler, 403, {"error": "forbidden", "message": "invalid_constraints"})
        return

    ok_c, creason = _enforce_constraints(constraints, normalized)
    if not ok_c:
        _audit(f"issue_denied reason={creason} capability_id={cap.get('capability_id')}")
        _json_response(handler, 403, {"error": "forbidden", "message": creason})
        return

    nonce = secrets.token_urlsafe(24)
    cred = action_credential.issue_action_scoped_credential(
        cap,
        tool_name,
        normalized,
        ttl_secs=120,
        signing_key=_ACTION_KEY,
        nonce=nonce,
    )
    _audit(
        f"action_credential_issued capability_id={cap.get('capability_id')} tool={tool_name}"
    )
    _json_response(handler, 200, {"action_credential": cred})


def _simulate_create_ticket(delegation_token: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    # delegation_token used only server-side to simulate upstream ITSM auth
    _ = delegation_token
    ticket_id = f"TCK-{secrets.token_hex(6).upper()}"
    return {"ticket_id": ticket_id, "status": "created", "title": tool_input["title"]}


def _handle_tool(handler: BaseHTTPRequestHandler, body: dict[str, Any]) -> None:
    cred = body.get("action_credential")
    tool_name = body.get("tool_name")
    tool_input = body.get("tool_input")
    if not isinstance(cred, dict) or not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        _json_response(handler, 400, {"error": "bad_request", "message": "invalid_tool_payload"})
        return

    ok_schema, sreason, normalized = _validate_tool_input(tool_input)
    if not ok_schema:
        _json_response(handler, 400, {"error": "validation_failed", "message": sreason})
        return

    ok, vreason = action_credential.verify_action_scoped_credential(
        cred, _ACTION_KEY, normalized, tool_name
    )
    if not ok:
        _audit(f"tool_denied reason={vreason}")
        _json_response(handler, 403, {"error": "forbidden", "message": vreason})
        return

    cap_id = cred.get("capability_id")
    if not isinstance(cap_id, str):
        _json_response(handler, 403, {"error": "forbidden", "message": "invalid_credential"})
        return

    dtok = _VAULT.get(cap_id)
    if not dtok:
        _audit(f"tool_denied reason=vault_miss capability_id={cap_id}")
        _json_response(handler, 403, {"error": "forbidden", "message": "capability_not_registered"})
        return

    if tool_name != "create_ticket":
        _json_response(handler, 400, {"error": "bad_request", "message": "unknown_tool"})
        return

    result = _simulate_create_ticket(dtok, normalized)
    _audit(f"ticket_created ticket_id={result['ticket_id']} capability_id={cap_id}")
    _json_response(handler, 200, {"status": "ok", "result": result})


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        # Quiet default access log; use _audit for security-relevant events
        return

    def do_POST(self) -> None:
        try:
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            body = _read_json_body(self)
            if body is None:
                _json_response(self, 400, {"error": "bad_request", "message": "invalid_json"})
                return
            if path == "/register":
                _handle_register(self, body)
            elif path == "/issue":
                _handle_issue(self, body)
            elif path == "/tool":
                _handle_tool(self, body)
            else:
                _json_response(self, 404, {"error": "not_found", "message": "no_route"})
        except Exception:
            traceback.print_exc(file=sys.stderr)
            _json_response(self, 500, {"error": "internal_error", "message": "server_error"})


def main() -> None:
    # Print to stderr so Cursor/VS Code "Run Python File" and threaded workers show the same stream
    # as [AUDIT] lines. Includes __file__ so you can confirm you are running *this* copy of the lab.
    print(f"[tool_server] starting — loaded from:\n  {__file__}", file=sys.stderr, flush=True)
    _load_keys()
    # 127.0.0.1: client using http://127.0.0.1:8799 reaches the server. Binding to "localhost"
    # alone can listen only on ::1 on some Windows/Python stacks while urllib uses IPv4.
    host = (os.environ.get("TOOL_SERVER_BIND") or "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int(os.environ.get("TOOL_SERVER_PORT", "8799"))
    except ValueError:
        port = 8799
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"[tool_server] listening on http://{host}:{port}", file=sys.stderr, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("shutting down", file=sys.stderr)


if __name__ == "__main__":
    main()
