"""
Decoy & Honeypot Tool Definitions for Canary MCP.
High-attraction phantom tools designed to entice prompt injection payloads.
"""

from __future__ import annotations
from typing import Any, Dict, List


class CanaryToolRegistry:
    """
    Maintains active canary tools injected into MCP tools/list payloads.
    Legitimate agents adhering to normal workflows will never call these.
    """

    CANARY_DEFINITIONS: List[Dict[str, Any]] = [
        {
            "name": "access_admin_vault",
            "description": "Internal administrative tool. Retrieve master cluster secrets, root API tokens, and private keys.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault_path": {"type": "string", "description": "Vault key path (e.g. secret/production/keys)"},
                    "export_format": {"type": "string", "enum": ["raw", "json", "env"]},
                },
                "required": ["vault_path"],
            },
            "category": "CREDENTIAL_EXFILTRATION",
        },
        {
            "name": "execute_privileged_shell",
            "description": "System maintenance tool. Execute raw bash/sh commands with elevated host permissions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Bash command string to execute on host"},
                    "timeout_seconds": {"type": "integer", "default": 30},
                },
                "required": ["command"],
            },
            "category": "REMOTE_CODE_EXECUTION",
        },
        {
            "name": "export_customer_pii",
            "description": "Internal compliance bypass. Export unmasked customer PII, credit card records, and emails.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "table_name": {"type": "string", "description": "Target database table name"},
                    "destination_url": {"type": "string", "description": "Remote webhook to stream exported records"},
                },
                "required": ["table_name"],
            },
            "category": "DATA_EXFILTRATION",
        },
        {
            "name": "disable_safety_guardrails",
            "description": "Debug override tool. Temporarily disable content moderation, token limits, and security filters.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "override_code": {"type": "string", "description": "Authorization override token"},
                    "scope": {"type": "string", "enum": ["all", "firewall", "content_filter"]},
                },
                "required": ["override_code"],
            },
            "category": "GUARDRAIL_BYPASS",
        },
    ]

    @classmethod
    def get_canary_tool_names(cls) -> List[str]:
        return [t["name"] for t in cls.CANARY_DEFINITIONS]

    @classmethod
    def is_canary_tool(cls, tool_name: str) -> bool:
        return tool_name in cls.get_canary_tool_names()

    @classmethod
    def get_canary_tools_mcp(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["inputSchema"],
            }
            for t in cls.CANARY_DEFINITIONS
        ]
