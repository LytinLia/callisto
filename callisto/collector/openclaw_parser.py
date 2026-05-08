"""OpenClaw JSONL session log parser.

Parses OpenClaw's JSONL log format into CALLISTO CallEvent streams.
Supports both file-based batch parsing and real-time watching.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Generator

from callisto.collector.models import CallEvent, EventType, Session


def parse_event(raw: dict) -> CallEvent | None:
    """Parse a single JSONL record into a CallEvent."""
    etype_str = raw.get("type", "")
    try:
        etype = EventType(etype_str)
    except ValueError:
        etype = EventType.CUSTOM

    if etype not in (EventType.TOOL_CALL, EventType.TOOL_RESULT):
        return None

    return CallEvent(
        event_id=raw.get("id", ""),
        session_id=raw.get("sessionId", ""),
        agent_id=raw.get("agentId", ""),
        timestamp=raw.get("timestamp", time.time()),
        event_type=etype,
        tool_name=raw.get("toolName", raw.get("tool", "")),
        parameters=raw.get("parameters", raw.get("params", {})),
        result=raw.get("result"),
        duration_ms=raw.get("durationMs", 0.0),
    )


def parse_session_file(path: Path) -> Session:
    """Parse an entire JSONL session file into a Session object."""
    session = Session(session_id=path.stem)
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = parse_event(raw)
            if event:
                session.add_event(event)
    return session
