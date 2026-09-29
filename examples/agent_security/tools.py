"""Mock tools with capability mappings for demonstration."""

from typing import Dict, Any

TOOLS: Dict[str, Dict[str, Any]] = {
    "read_document": {
        "capabilities": ["filesystem.read"],
        "description": "Reads local research documents.",
    },
    "web_search": {
        "capabilities": ["network.request"],
        "description": "Performs web search for external sources.",
    },
    "send_email": {
        "capabilities": ["email.send"],
        "description": "Sends outbound email notifications.",
    },
    "delete_db_record": {
        "capabilities": ["database.delete"],
        "description": "Deletes records from the operational database.",
    },
}
