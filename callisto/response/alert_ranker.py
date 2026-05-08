"""Alert ranker — prioritizes and deduplicates detection alerts."""

from __future__ import annotations

import time
from collections import defaultdict

from callisto.collector.models import Alert, RiskLevel


class AlertRanker:
    """Ranks, deduplicates, and throttles alerts.

    - Dedup: suppresses repeated alerts from the same module within cooldown
    - Priority: sorts by risk_level * score
    - Aggregation: merges related alerts into a single compound alert

    优化 (v2.1):
    - 去重 key 包含参数指纹，不同的敏感操作都会告警
    - 缩短 cooldown 时间，减少误杀
    """

    def __init__(self, cooldown: float = 1.0):
        self.cooldown = cooldown
        self._last_alert: dict[str, float] = {}  # dedup_key -> last alert timestamp

    def _get_dedup_key(self, alert: Alert) -> str:
        """生成去重 key - 包含参数指纹以区分不同的敏感操作"""
        # 从 trigger_events 提取参数指纹
        param_hash = ""
        if alert.trigger_events:
            # 使用事件 ID 作为指纹的一部分
            param_hash = ":".join(sorted(alert.trigger_events)[:3])

        return f"{alert.session_id}:{alert.source_module}:{alert.attack_type.value}:{param_hash}"

    def process(self, alerts: list[Alert]) -> list[Alert]:
        """Filter, rank, and return actionable alerts."""
        now = time.time()
        filtered = []
        for a in alerts:
            key = self._get_dedup_key(a)
            last = self._last_alert.get(key, 0.0)
            if now - last >= self.cooldown:
                filtered.append(a)
                self._last_alert[key] = now

        # Sort by priority: risk_level descending, then score descending
        filtered.sort(key=lambda a: (a.risk_level.value, a.score), reverse=True)
        return filtered
