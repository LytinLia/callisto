"""Core data models for CALLISTO."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(Enum):
    TOOL_CALL = "toolCall"
    TOOL_RESULT = "toolResult"
    MESSAGE = "message"
    MODEL_CHANGE = "model_change"
    CUSTOM = "custom"


class RiskLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AttackType(Enum):
    A1_RATE_FLOOD = "rate_flood"
    A2_PRIV_ESCALATION = "priv_escalation"
    A3_DATA_EXFIL = "data_exfil"
    A4_BEHAVIOR_DRIFT = "behavior_drift"
    A5_TEMPORAL_VIOLATION = "temporal_violation"
    A6_STATE_POISON = "state_poison"
    BENIGN = "benign"


@dataclass
class CallEvent:
    """A single API/tool invocation event."""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    session_id: str = ""
    agent_id: str = ""
    timestamp: float = 0.0
    event_type: EventType = EventType.TOOL_CALL
    tool_name: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    duration_ms: float = 0.0
    # ground-truth label (for evaluation only)
    label: AttackType = AttackType.BENIGN


@dataclass
class Session:
    """A sequence of CallEvents from one agent session."""

    session_id: str = ""
    agent_id: str = ""
    events: list[CallEvent] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_event(self, event: CallEvent) -> None:
        event.session_id = self.session_id
        event.agent_id = self.agent_id
        self.events.append(event)
        if not self.start_time or event.timestamp < self.start_time:
            self.start_time = event.timestamp
        if event.timestamp > self.end_time:
            self.end_time = event.timestamp

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def tool_calls(self) -> list[CallEvent]:
        """Return all tool-related events (both TOOL_CALL and TOOL_RESULT)."""
        return [e for e in self.events if e.event_type in (EventType.TOOL_CALL, EventType.TOOL_RESULT)]


@dataclass
class Alert:
    """Detection alert produced by the detection engine."""

    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = 0.0
    session_id: str = ""
    risk_level: RiskLevel = RiskLevel.NONE
    attack_type: AttackType = AttackType.BENIGN
    source_module: str = ""  # "CRS" | "MA-BOCPD" | "CSBF"
    trigger_events: list[str] = field(default_factory=list)  # event_ids
    score: float = 0.0
    explanation: str = ""
