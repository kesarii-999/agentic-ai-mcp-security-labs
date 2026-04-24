# tool_server.py
import os
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any

from shared_crypto import verify_signature

HOST = "127.0.0.1"
PORT = 8787

# --- Enterprise secret: only tool server has this ---
ITSM_API_TOKEN = os.environ.get("ITSM_API_TOKEN", None)

# --- Agent-to-toolserver auth (HMAC shared key for lab) ---
MCP_CLIENT_KEY = os.environ.get("MCP_CLIENT_KEY", None)

ALLOWED_TOOLS = {"create_ticket"}

def safe_json_response(handler: BaseHTTPRequestHandler, status: int, data: Dict[str, Any]):
    body = json.dumps(data).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

def validate_ticket_input(tool_input: Dict[str, Any]) -> str | None:
    """
    Returns None if valid, else returns error string.
    """
    required = {"title", "description", "priority"}
    if set(tool_input.keys()) != required:
        return "Invalid fields. Required exactly: title, description, priority."

    if not isinstance(tool_input["title"], str) or len(tool_input["title"]) < 5:
        return "title must be a string of length >= 5"

    if not isinstance(tool_input["description"], str) or len(tool_input["description"]) < 10:
        return "description must be a string of length >= 10"

    if tool_input["priority"] not in ("low", "medium", "high"):
        return "priority must be one of: low, medium, high"

    return None

def simulate_downstream_itsm_create_ticket(tool_input: Dict[str, Any], token: str) -> Dict[str, Any]:
    """
    Simulates calling an enterprise ITSM API that requires a token.
    In real world: requests.post(..., headers={"Authorization": f"Bearer {token}"})
    """
    # IMPORTANT: Do not print token, do not return token, do not leak token in errors.
    # Create a fake ticket id
    ticket_id = f"INC{int(time.time())}"
    return {
        "ticket_id": ticket_id,
        "status": "created",
        "priority": tool_input["priority"],
        "title": tool_input["title"],
        "message": "Ticket created successfully in ITSM."
    }

class ToolServerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Basic routing
        if self.path != "/tool":
            safe_json_response(self, 404, {"error": "Not found"})
            return

        if ITSM_API_TOKEN is None:
            safe_json_response(self, 500, {"error": "Server misconfigured: missing ITSM_API_TOKEN"})
            return

        if MCP_CLIENT_KEY is None:
            safe_json_response(self, 500, {"error": "Server misconfigured: missing MCP_CLIENT_KEY"})
            return

        # Read body
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length)

        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            safe_json_response(self, 400, {"error": "Invalid JSON"})
            return

        # Expected shape:
        # {
        #   "tool_name": "create_ticket",
        #   "tool_input": {...},
        #   "timestamp": 1234567890,
        #   "signature": "hex..."
        # }
        for key in ("tool_name", "tool_input", "timestamp", "signature"):
            if key not in payload:
                safe_json_response(self, 400, {"error": f"Missing field: {key}"})
                return

        tool_name = payload["tool_name"]
        tool_input = payload["tool_input"]
        timestamp = payload["timestamp"]
        signature = payload["signature"]

        # Allow-list tool
        if tool_name not in ALLOWED_TOOLS:
            safe_json_response(self, 403, {"error": "Tool not allowed"})
            return

        # Prevent replay: require timestamp within 60 seconds
        now = int(time.time())
        if not isinstance(timestamp, int) or abs(now - timestamp) > 60:
            safe_json_response(self, 401, {"error": "Request expired"})
            return

        # Verify signature over payload minus signature
        unsigned = {
            "tool_name": tool_name,
            "tool_input": tool_input,
            "timestamp": timestamp
        }
        if not verify_signature(unsigned, MCP_CLIENT_KEY, signature):
            safe_json_response(self, 401, {"error": "Invalid signature"})
            return

        # Validate schema
        if not isinstance(tool_input, dict):
            safe_json_response(self, 400, {"error": "tool_input must be an object"})
            return

        err = validate_ticket_input(tool_input)
        if err:
            safe_json_response(self, 400, {"error": err})
            return

        # Execute tool (token never leaves this process)
        try:
            result = simulate_downstream_itsm_create_ticket(tool_input, ITSM_API_TOKEN)
            # Sanitized response only
            safe_json_response(self, 200, {"ok": True, "result": result})
        except Exception:
            # Sanitized error: do not include headers, tokens, stack traces
            safe_json_response(self, 500, {"ok": False, "error": "Tool execution failed"})

    def log_message(self, format, *args):
        # Optional: reduce noisy logs in corporate environment
        return

def main():
    print(f"[ToolServer] Starting on http://{HOST}:{PORT}")
    server = HTTPServer((HOST, PORT), ToolServerHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()