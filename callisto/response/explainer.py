"""Explainer — generates human-readable explanations for alerts."""

from __future__ import annotations

from callisto.collector.models import Alert, AttackType, RiskLevel


_ATTACK_DESCRIPTIONS = {
    AttackType.A1_RATE_FLOOD: "Rate anomaly: abnormally high API call frequency detected, potential resource exhaustion attack",
    AttackType.A2_PRIV_ESCALATION: "Privilege escalation: individually authorized tool calls form an unauthorized chain",
    AttackType.A3_DATA_EXFIL: "Data exfiltration: sensitive data may be leaking through tool parameters or outputs",
    AttackType.A4_BEHAVIOR_DRIFT: "Behavioral drift: agent behavior deviates significantly from established baseline",
    AttackType.A5_TEMPORAL_VIOLATION: "Temporal violation: tool calls violate expected ordering constraints",
    AttackType.A6_STATE_POISON: "State poisoning: suspicious writes to persistent state that may affect future sessions",
}


class AlertExplainer:
    """Generates structured, human-readable alert reports."""

    def explain(self, alert: Alert) -> str:
        """Generate a concise explanation for an alert."""
        attack_desc = _ATTACK_DESCRIPTIONS.get(alert.attack_type, "Unknown threat type")
        risk_label = alert.risk_level.name

        lines = [
            f"[{risk_label}] {alert.source_module} Alert",
            f"  Type: {attack_desc}",
            f"  Score: {alert.score:.3f}",
        ]
        if alert.trigger_events:
            lines.append(f"  Trigger events: {', '.join(alert.trigger_events[:5])}")
        if alert.explanation:
            lines.append(f"  Detail: {alert.explanation}")
        return "\n".join(lines)

    def explain_batch(self, alerts: list[Alert]) -> str:
        """Generate a summary report for multiple alerts."""
        if not alerts:
            return "No alerts."
        parts = [f"=== CALLISTO Alert Report ({len(alerts)} alerts) ===\n"]
        for i, a in enumerate(alerts, 1):
            parts.append(f"--- Alert {i} ---")
            parts.append(self.explain(a))
            parts.append("")
        return "\n".join(parts)
