# capabilities.py
from typing import Dict

def get_it_helpdesk_capability() -> Dict:
    """
    Capability issued to IT Helpdesk Agent
    """
    return {
        "capability_id": "cap-it-helpdesk-001",
        "allowed_tool": "create_ticket",
        "constraints": {
            "department": "IT",
            "max_priority": "low"
        },
        "valid": True
    }
    
#Explicit authority
#No identity lookup
#No roles
#No tokens