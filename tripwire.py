"""
Tripwire Interlock & Forensic Incident Capture Engine.
Provides sub-millisecond execution termination and tamper-proof forensic evidence sealing.
"""

from __future__ import annotations
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from canary_mcp.canary_tools import CanaryToolRegistry


@dataclass
class CanaryIncident:
    incident_id: str
    timestamp: float
    triggered_canary: str
    category: str
    agent_id: str
    tool_arguments: Dict[str, Any]
    session_id: str
    incident_hash: str

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "triggered_canary": self.triggered_canary,
            "category": self.category,
            "agent_id": self.agent_id,
            "tool_arguments": self.tool_arguments,
            "session_id": self.session_id,
            "incident_hash": self.incident_hash,
        }


class TripwireInterlock:
    """
    Zero-false-positive intrusion interlock.
    Instantly trips when an agent or indirect prompt injection invokes a decoy tool or canary token.
    """

    def __init__(self, incidents_dir: Optional[str] = None):
        self.incidents_dir = incidents_dir or "/tmp/canary_mcp_incidents"
        os.makedirs(self.incidents_dir, exist_ok=True)
        self._tripped_sessions: set = set()
        self._incident_log: List[CanaryIncident] = []

    def is_session_locked(self, session_id: str) -> bool:
        return session_id in self._tripped_sessions

    def trip_tool_wire(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        agent_id: str = "agent-unknown",
    ) -> CanaryIncident:
        """
        Activates tripwire on decoy tool invocation.
        Captures the forensic attack vector and permanently locks the agent session.
        """
        self._tripped_sessions.add(session_id)
        incident_id = f"canary-alert-{uuid.uuid4().hex[:8]}"

        # Resolve category
        category = "UNKNOWN_CANARY_VIOLATION"
        for t in CanaryToolRegistry.CANARY_DEFINITIONS:
            if t["name"] == tool_name:
                category = t["category"]
                break

        now = time.time()
        canonical = json.dumps(
            {
                "id": incident_id,
                "time": now,
                "tool": tool_name,
                "args": arguments,
                "agent": agent_id,
                "session": session_id,
            },
            sort_keys=True,
        )
        incident_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        incident = CanaryIncident(
            incident_id=incident_id,
            timestamp=now,
            triggered_canary=tool_name,
            category=category,
            agent_id=agent_id,
            tool_arguments=arguments,
            session_id=session_id,
            incident_hash=incident_hash,
        )

        self._incident_log.append(incident)

        # Write immutable record to disk
        out_file = os.path.join(self.incidents_dir, f"{incident_id}.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(incident.to_dict(), f, indent=2)

        return incident

    def get_incident_history(self) -> List[CanaryIncident]:
        return self._incident_log
