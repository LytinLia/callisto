#!/usr/bin/env python3
"""
CALLISTO 实时监控器

功能：
1. 实时监控 OpenClaw 日志文件
2. 自动拦截风险操作
3. 生成检测报告
4. 支持熔断机制

使用方法：
    .venv/bin/python -m callisto.monitor <log_dir> [--block] [--report]
"""

import sys
import os
import time
import json
import signal
import logging
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

from callisto.config import CallistoConfig
from callisto.engine import CallistoEngine
from callisto.response.explainer import AlertExplainer
from callisto.collector.models import Session, CallEvent, EventType, RiskLevel

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)


@dataclass
class MonitorConfig:
    """监控器配置"""
    log_dir: str = "./logs"
    watch_interval: float = 1.0
    fingerprint_path: Optional[str] = None
    crs_threshold: float = 0.7
    bocpd_threshold: float = 0.5
    auto_block: bool = False
    generate_report: bool = True
    report_dir: str = "./reports"


class Monitor:
    """CALLISTO 实时监控器"""

    def __init__(self, config: MonitorConfig):
        self.config = config
        self.running = True
        self.sessions = {}
        self.alerts = []
        self.blocked_sessions = set()
        self.file_positions = {}

        self._init_engine()

        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _init_engine(self):
        """初始化检测引擎"""
        cfg = CallistoConfig(
            crs_threshold=self.config.crs_threshold,
            bocpd_threshold=self.config.bocpd_threshold,
        )

        if self.config.fingerprint_path:
            cfg.fingerprint_path = Path(self.config.fingerprint_path)

        self.engine = CallistoEngine(cfg)
        self.explainer = AlertExplainer()
        log.info("检测引擎初始化完成")

    def _handle_signal(self, signum, frame):
        """处理停止信号"""
        log.info("收到停止信号，正在关闭...")
        self.running = False

    def parse_event(self, raw: dict, session_id: str) -> Optional[CallEvent]:
        """解析 OpenClaw 日志事件"""
        try:
            event_type_str = raw.get("type", "")
            if event_type_str not in ("toolCall", "toolResult"):
                return None

            timestamp_raw = raw.get("timestamp", "")
            if isinstance(timestamp_raw, str):
                # ISO 格式：2026-04-20T03:59:20.381Z
                timestamp = self._parse_timestamp(timestamp_raw)
            else:
                timestamp = timestamp_raw / 1000 if timestamp_raw > 1e12 else timestamp_raw

            # toolName 可能在顶层或 message 内
            tool_name = raw.get("toolName") or raw.get("tool", "")
            if not tool_name:
                msg = raw.get("message", {})
                tool_name = msg.get("toolName") or msg.get("name", "")

            if not tool_name:
                return None

            details = raw.get("details", {})
            msg = raw.get("message", {})
            # Merge parameters from both message and details
            msg_params = msg.get("parameters", {})

            return CallEvent(
                event_id=raw.get("id", ""),
                session_id=session_id,
                agent_id=raw.get("agentId", "openclaw"),
                timestamp=timestamp,
                event_type=EventType.TOOL_CALL,
                tool_name=tool_name,
                parameters={"toolCallId": raw.get("toolCallId", ""), **details, **msg_params},
                result=msg.get("content", []),
                duration_ms=details.get("durationMs", 0),
            )
        except Exception as e:
            log.debug(f"解析失败：{e}")
            return None

    def _parse_timestamp(self, ts_str: str) -> float:
        """解析 ISO 时间戳"""
        from datetime import datetime
        try:
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except Exception:
            return time.time()

    def process_files(self):
        """处理所有日志文件"""
        log_dir = Path(self.config.log_dir)

        if not log_dir.exists():
            log.warning(f"日志目录不存在：{log_dir}")
            return

        for file_path in log_dir.glob("*.jsonl"):
            session_id = file_path.stem

            if session_id in self.blocked_sessions:
                continue

            if session_id not in self.sessions:
                self.sessions[session_id] = Session(
                    session_id=session_id,
                    agent_id="openclaw",
                )

            session = self.sessions[session_id]

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    pos = self.file_positions.get(str(file_path), 0)
                    f.seek(pos)
                    lines = f.readlines()
                    self.file_positions[str(file_path)] = f.tell()

                new_events = False
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    raw = json.loads(line)
                    event = self.parse_event(raw, session_id)
                    if event:
                        session.add_event(event)
                        new_events = True

                if new_events and len(session.tool_calls) > 0:
                    self._detect(session)

            except Exception as e:
                log.error(f"处理文件 {file_path} 失败：{e}")

    def _detect(self, session):
        """运行检测"""
        try:
            alerts = self.engine.analyze_session(session)

            for alert in alerts:
                alert.session_id = session.session_id
                self.alerts.append(alert)
                self._print_alert(alert)

            if self.engine.is_blocked():
                self._block(session)

        except Exception as e:
            log.error(f"检测失败：{e}")

    def _print_alert(self, alert):
        """打印告警"""
        colors = {
            "LOW": "\033[94m",
            "MEDIUM": "\033[93m",
            "HIGH": "\033[91m",
            "CRITICAL": "\033[95m",
        }
        reset = "\033[0m"
        color = colors.get(alert.risk_level.name, "")

        print(f"\n{color}{'='*60}{reset}")
        print(f"{color}[{alert.risk_level.name}] {alert.attack_type.value}{reset}")
        print(f"  会话：{alert.session_id}")
        print(f"  时间：{datetime.fromtimestamp(alert.timestamp).strftime('%H:%M:%S')}")
        print(f"  分数：{alert.score:.3f}")
        print(f"  说明：{alert.explanation}")
        print(f"{color}{'='*60}{reset}")

    def _block(self, session):
        """处理熔断"""
        if session.session_id in self.blocked_sessions:
            return

        self.blocked_sessions.add(session.session_id)
        print(f"\n🚨 熔断触发！会话 {session.session_id} 已被阻止")

        if self.config.generate_report:
            self._generate_emergency_report(session)

    def _generate_emergency_report(self, session):
        """生成紧急报告"""
        report_dir = Path(self.config.report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"emergency_{session.session_id}_{timestamp}.txt"

        session_alerts = [a for a in self.alerts if a.session_id == session.session_id]

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("CALLISTO 紧急安全报告\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"会话 ID: {session.session_id}\n")
            f.write(f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("告警详情:\n")
            f.write("-" * 40 + "\n")

            for i, alert in enumerate(session_alerts, 1):
                f.write(f"\n[告警 {i}]\n")
                f.write(f"  类型：{alert.attack_type.value}\n")
                f.write(f"  风险：{alert.risk_level.name}\n")
                f.write(f"  分数：{alert.score:.3f}\n")
                f.write(f"  说明：{alert.explanation}\n")

            f.write("\n建议操作:\n")
            f.write("  1. 审查该会话完整日志\n")
            f.write("  2. 检查数据泄露\n")
            f.write("  3. 撤销危险操作\n")

        log.info(f"紧急报告已生成：{report_path}")
        print(f"📄 报告：{report_path}")

    def run(self):
        """启动监控"""
        log.info(f"开始监控：{self.config.log_dir}")
        log.info(f"扫描间隔：{self.config.watch_interval}秒")
        log.info(f"自动阻断：{'开启' if self.config.auto_block else '关闭'}")

        print("\n" + "=" * 60)
        print("🔍 CALLISTO 实时监控器")
        print("=" * 60)
        print(f"日志目录：{os.path.abspath(self.config.log_dir)}")
        print(f"扫描间隔：{self.config.watch_interval}秒")
        print("按 Ctrl+C 停止监控\n")

        start_time = time.time()

        while self.running:
            try:
                self.process_files()
                time.sleep(self.config.watch_interval)
            except Exception as e:
                log.error(f"监控循环出错：{e}")
                time.sleep(self.config.watch_interval)

        elapsed = time.time() - start_time
        print(f"\n监控结束，运行时长：{elapsed:.1f}秒")
        print(f"处理会话：{len(self.sessions)}")
        print(f"总告警数：{len(self.alerts)}")
        print(f"熔断会话：{len(self.blocked_sessions)}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="CALLISTO 实时监控器")
    parser.add_argument("log_dir", nargs="?", default="./logs",
                       help="OpenClaw 日志目录")
    parser.add_argument("--fingerprint", type=str, default=None,
                       help="行为指纹文件路径")
    parser.add_argument("--block", action="store_true",
                       help="启用自动阻断")
    parser.add_argument("--interval", type=float, default=1.0,
                       help="扫描间隔秒数")

    args = parser.parse_args()

    config = MonitorConfig(
        log_dir=args.log_dir,
        watch_interval=args.interval,
        fingerprint_path=args.fingerprint,
        auto_block=args.block,
    )

    monitor = Monitor(config)
    monitor.run()


if __name__ == "__main__":
    main()
