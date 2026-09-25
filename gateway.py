"""
Canary MCP Deception Gateway.
Transparent reverse-proxy injecting canary tripwire tools into standard MCP pipelines.
"""

from __future__ import annotations
import json
from typing import Any, Callable, Dict, List, Optional
from canary_mcp.canary_tools import CanaryToolRegistry
from canary_mcp.tripwire import CanaryIncident, TripwireInterlock


class CanaryMcpGateway:
    """
    Transparent inline reverse-proxy for the Model Context Protocol (MCP).
    Blends honeypot tools into legitimate server manifests and traps adversarial invocations.
    """

    def __init__(
        self,
        downstream_handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        incidents_dir: Optional[str] = None,
    ):
        self.downstream_handler = downstream_handler or self._default_mock_downstream
        self.tripwire = TripwireInterlock(incidents_dir=incidents_dir)

    def _default_mock_downstream(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Mock legitimate downstream tool handler for testing and standalone demo."""
        method = req.get("method")
        rpc_id = req.get("id")

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "tools": [
                        {
                            "name": "search_documentation",
                            "description": "Legitimate tool. Search internal engineering documentation.",
                            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                        },
                        {
                            "name": "query_public_api",
                            "description": "Legitimate tool. Fetch public REST API metrics.",
                            "inputSchema": {"type": "object", "properties": {"endpoint": {"type": "string"}}},
                        },
                    ]
                },
            }

        elif method == "tools/call":
            params = req.get("params", {})
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [
                        {"type": "text", "text": f"Executed legitimate tool: {params.get('name')}"}
                    ]
                },
            }

        return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": "Method not found"}}

    def process_rpc(
        self,
        req: Dict[str, Any],
        session_id: str = "default-session",
        agent_id: str = "agent-runner",
    ) -> Dict[str, Any]:
        """
        Intercepts and processes incoming MCP JSON-RPC requests.
        """
        rpc_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        # If session is already compromised and locked, fail-closed
        if self.tripwire.is_session_locked(session_id):
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32098,
                    "message": "SESSION TERMINATED: Hostile intrusion attempt previously detected. Access revoked.",
                },
            }

        # 1. tools/list: Blend legitimate tools with canary tripwires
        if method == "tools/list":
            downstream_resp = self.downstream_handler(req)
            if "result" in downstream_resp and "tools" in downstream_resp["result"]:
                legit_tools = downstream_resp["result"]["tools"]
                canary_tools = CanaryToolRegistry.get_canary_tools_mcp()
                # Seamlessly inject canaries into the tool catalog
                merged_tools = legit_tools + canary_tools
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"tools": merged_tools},
                }
            return downstream_resp

        # 2. tools/call: Intercept and trip on canary tool invocations
        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            # Check if attacker triggered a canary honeypot
            if CanaryToolRegistry.is_canary_tool(tool_name):
                incident = self.tripwire.trip_tool_wire(
                    session_id=session_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    agent_id=agent_id,
                )
                return {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32099,
                        "message": (
                            f"🛑 INTRUSION TRIPWIRE TRIGGERED: Honeypot tool '{tool_name}' invoked. "
                            f"Execution terminated. Incident sealed: {incident.incident_id}"
                        ),
                        "data": {
                            "incident_id": incident.incident_id,
                            "category": incident.category,
                            "incident_hash": incident.incident_hash,
                        },
                    },
                }

            # Forward clean legitimate call to downstream server
            return self.downstream_handler(req)

        # Forward other methods (e.g. ping, initialize)
        return self.downstream_handler(req)
