# capability_server.py
from typing import Dict

PRIORITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3
}

def enforce_capability(capability: Dict, tool_name: str, tool_input: Dict) -> Dict:
    if not capability.get("valid"):
        return {"allowed": False, "reason": "Invalid capability"}

    if tool_name != capability["allowed_tool"]:
        return {"allowed": False, "reason": "Tool not permitted"}

    constraints = capability["constraints"]

    if tool_input.get("department") != constraints["department"]:
        return {"allowed": False, "reason": "Department not allowed"}

    requested = tool_input.get("priority")
    max_allowed = constraints["max_priority"]

    if PRIORITY_ORDER[requested] > PRIORITY_ORDER[max_allowed]:
        return {
            "allowed": False,
            "reason": f"Priority '{requested}' exceeds allowed '{max_allowed}'"
        }

    return {"allowed": True}