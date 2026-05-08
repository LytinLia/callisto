"""Circuit breaker — halts agent execution when threat level is critical."""

from __future__ import annotations

import json
import time
from pathlib import Path
from callisto.collector.models import Alert, RiskLevel


class CircuitBreaker:
    """Trips when consecutive high-severity alerts exceed a threshold.

    States:
    - CLOSED: normal operation, monitoring alerts
    - OPEN: execution blocked, waiting for cooldown or manual reset
    - HALF_OPEN: allowing limited execution to test recovery
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, threshold: int = 3, reset_timeout: float = 60.0):
        self.threshold = threshold
        self.reset_timeout = reset_timeout
        self.state = self.CLOSED
        self._consecutive_alerts = 0
        self._opened_at: float = 0.0

    def record_alert(self, alert: Alert) -> str:
        """Record an alert and return the new circuit state."""
        if alert.risk_level.value >= RiskLevel.HIGH.value:
            self._consecutive_alerts += 1
        else:
            self._consecutive_alerts = max(0, self._consecutive_alerts - 1)

        if self.state == self.CLOSED and self._consecutive_alerts >= self.threshold:
            self.state = self.OPEN
            self._opened_at = time.time()

        if self.state == self.OPEN and time.time() - self._opened_at > self.reset_timeout:
            self.state = self.HALF_OPEN

        return self.state

    def record_success(self) -> str:
        """Record a successful (safe) operation."""
        if self.state == self.HALF_OPEN:
            self.state = self.CLOSED
            self._consecutive_alerts = 0
        return self.state

    def should_block(self) -> bool:
        return self.state == self.OPEN

    def reset(self) -> None:
        self.state = self.CLOSED
        self._consecutive_alerts = 0

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "_consecutive_alerts": self._consecutive_alerts,
            "_opened_at": self._opened_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CircuitBreaker":
        cb = cls()
        cb.state = data.get("state", cls.CLOSED)
        cb._consecutive_alerts = data.get("_consecutive_alerts", 0)
        cb._opened_at = data.get("_opened_at", 0.0)
        return cb

    @staticmethod
    def load_state_file(path: Path) -> dict:
        """Load breaker state dict from JSON file."""
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return {}

    @staticmethod
    def save_state_file(path: Path, states: dict) -> None:
        """Save breaker state dict to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(states, indent=2, ensure_ascii=False), encoding="utf-8")
