#!/usr/bin/env python3
"""
CALLISTO OpenClaw Plugin - 实时检测后端

集成 CALLISTO 完整检测引擎，支持:
- A1: 速率洪水检测
- A2: 权限升级检测
- A3: 数据外泄检测
- A4: 行为漂移检测
- A5: 时序违例检测
- A6: 状态投毒检测
- P1/D1: 敏感文件读取检测
- L1/L2: 内网/服务访问检测
- L3: 凭证文件访问检测
- 敏感信息脱敏 (新增)
- 自动熔断 (新增)
- 人类监督模式 (新增)
"""

import json
import sys
import time
import re
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any

# 导入 CALLISTO 组件
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    from callisto.engine import CallistoEngine
    from callisto.config import CallistoConfig
    from callisto.collector.models import Session, CallEvent, EventType, RiskLevel, Alert, AttackType
    from callisto.sanitizer import Sanitizer
    from callisto.response.circuit_breaker import CircuitBreaker
    from callisto.content_safety import ContentSafetyDetector
    CALLISTO_AVAILABLE = True
except ImportError as e:
    CALLISTO_AVAILABLE = False
    print(f"CALLISTO import error: {e}", file=sys.stderr)
    # Fallback 类型定义
    class Session:
        def __init__(self, session_id="", agent_id=""):
            self.session_id = session_id
            self.events = []
        def add_event(self, event):
            self.events.append(event)
    class CallEvent: pass
    class EventType:
        TOOL_CALL = "tool_call"
    class RiskLevel:
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"
        name = "LOW"
    class Alert:
        def __init__(self, attack_type="", risk_level="LOW", score=0.0, explanation="", timestamp=0):
            self.attack_type = type('obj', (object,), {'value': attack_type})()
            self.risk_level = type('obj', (object,), {'name': risk_level})()
            self.score = score
            self.explanation = explanation
            self.timestamp = timestamp
    class CircuitBreaker:
        def __init__(self, threshold=3):
            self.threshold = threshold
            self.state = "CLOSED"
            self._consecutive_alerts = 0
        def record_alert(self, alert):
            if alert.risk_level.name == "HIGH":
                self._consecutive_alerts += 1
        def should_block(self):
            return self._consecutive_alerts >= self.threshold
    class CallistoEngine:
        def __init__(self, cfg): pass
        def analyze_session(self, session): return []
    class CallistoConfig:
        def __init__(self, circuit_breaker_threshold=3): pass
    class Sanitizer:
        def __init__(self): pass
        def sanitize(self, text): return text
    class ContentSafetyDetector:
        def analyze(self, tool_name, parameters): return []


# ========== 敏感文件路径模式 ==========
_SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/gshadow",
    "/etc/ssh/", "/etc/ssl/", "/etc/pki/",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    ".pem", ".key", ".p12", ".pfx", ".jks",
    "credentials", "credentials.json", "credentials.yaml",
    ".aws/credentials", ".aws/config",
    ".azure/", ".gcloud/", "application_default_credentials",
    ".kube/config", "serviceaccount/token", "ca.crt",
    "database.yml", "database.json", "db.conf",
    ".env", ".env.local", ".env.production",
    "api_key", "apikey", "api-key", "secret", "token",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    "/var/log/auth.log", "/var/log/secure", "/var/log/audit/",
    ".docker/config.json", "dockercloud-auth",
]

# ========== 内网访问模式 ==========
_INTERNAL_PATTERNS = [
    r"192\.168\.\d{1,3}\.\d{1,3}",
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}",
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"169\.254\.169\.254",  # 云元数据
    r"metadata\.google\.internal",
    r"\.internal", r"\.local", r"\.lan", r"\.intra",
    r"\.corp", r"\.private",
    r"mysql\.", r"redis\.", r"mongo\.", r"postgres\.",
    r"k8s-api", r"kubernetes\.", r"etcd-",
    r"consul\.", r"vault\.", r"elasticsearch\.",
]

# ========== 恶意命令模式 ==========
_MALICIOUS_PATTERNS = [
    # 提权
    r"sudo\s+su\s*-", r"sudo\s+-i", r"sudo\s+bash", r"pkexec\s+",
    r"chmod\s+.*777", r"chmod\s+\+s", r"chmod\s+4755",
    r"chown\s+root", r"useradd.*-u\s*0",
    # 反弹 shell
    r"nc\s+.*-e\s+", r"netcat\s+.*-e\s+", r"nc\s+-c\s+",
    r"bash\s+-i\s+.*>.*>", r"bash\s+-i\s+.*<.*>",
    r"python.*socket.*connect", r"perl.*socket.*connect",
    # 凭证窃取
    r"cat\s+.*/\.aws/", r"cat\s+.*/credentials",
    r"cat\s+.*\.ssh/id_", r"cat\s+.*\.ssh/id_rsa",
    r"grep\s+.*password", r"grep\s+.*secret",
    r"grep\s+.*API_KEY", r"grep\s+.*TOKEN",
    # 数据外泄 — curl/wget 上传数据
    r"curl\s+.*-d\s+@", r"curl\s+.*--data-binary\s+@",
    r"wget\s+.*--post-file\s+@",
    r"curl\s+-X\s+POST.*-d\s+",  # curl POST with data
    r"curl\s+-F\s+",  # curl form upload
    r"scp\s+.*@", r"rsync\s+.*@",
    # 容器逃逸
    r"nsenter\s+", r"unshare\s+", r"docker\s+run.*--privileged",
    r"docker\s+run.*-v\s+/:", r"docker\s+run.*--pid=host",
    # 恶意下载执行
    r"curl\s+.*\|\s*(ba)?sh", r"wget\s+.*-O\s+-\s*\|\s*(ba)?sh",
    r"curl.*evil", r"wget.*evil", r"curl.*attacker", r"wget.*attacker",
    r"curl.*payload", r"wget.*payload",
    # 删除破坏 — 扩大范围
    r"rm\s+-rf\s+/", r"rm\s+-rf\s+\*", r"rm\s+-rf\s+\.\*/",
    r"rm\s+-rf\s+\.\*\s+\.\./\*",  # rm -rf ./* ../*
    r"rm\s+-rf",  # broad rm -rf (catches rm -rf .git etc)
    r">\s+/dev/sd",
    r"mkfs\.", r"dd\s+if=.*of=/dev/",
    r"find\s+.*-delete", r"find\s+.*-exec\s+rm",
    # DoS / 无限循环
    r"while\s+true.*curl", r"while\s+true.*wget",
    r"while\s+:\s*;.*curl",
    # 编码/混淆执行
    r"base64\s+-d\s*\|\s*(ba)?sh",
    r"eval\s+\$\(.*base64",
    # 后门/用户创建
    r"sudo\s+useradd", r"sudo\s+adduser",
    # 加密/勒索
    r"openssl\s+enc\s+",
    r"find\s+.*-exec\s+openssl",
    # 测试规则
    r"\bcallisto-test-alert\b",  # 测试命令：触发告警
]

# ========== 良性命令白名单 ==========
_BENIGN_PATTERNS = [
    r"^\s*(npm|yarn|pnpm)\s+(install|build|test|run|lint|format)",
    r"^\s*python\s+(-m\s+)?(pytest|unittest|coverage|flake8|mypy|black|isort)",
    r"^\s*go\s+(build|test|run|mod|get|fmt|vet|lint)",
    r"^\s*cargo\s+(build|test|run|check|fmt|clippy)",
    r"^\s*mvn\s+", r"^\s*gradle\s+", r"^\s*make\s+",
    r"^\s*(ls|cat|head|tail|grep|find|wc|sort|uniq|diff|comm)\s+",
    r"^\s*echo\s+",
    r"^\s*git\s+(status|log|diff|show|branch|remote|fetch|pull|push|add|commit|checkout)",
    r"^\s*docker\s+(ps|images|logs|build|pull|push|inspect|network|volume)",
    r"^\s*(uname|hostname|pwd|whoami|env|printenv)\s*",
    r"^\s*(apt|yum|dnf|brew)\s+(list|search|info|show)",
]


@dataclass
class DetectResult:
    status: str
    session_id: str
    alerts: List[Dict[str, Any]]
    circuit_breaker: str = "CLOSED"
    consecutive_alerts: int = 0
    message: str = ""


class CallistoAgent:
    """CALLISTO Agent for OpenClaw plugin - 使用完整引擎"""

    BREAKER_STATE_FILE = Path.home() / ".openclaw" / "agents" / "main" / "breaker_state.json"

    def __init__(self, threshold: int = 3):
        self.threshold = threshold
        self.sessions: Dict[str, Session] = {}
        self.breakers: Dict[str, CircuitBreaker] = {}
        self.engine: Optional[CallistoEngine] = None
        self.sanitizer: Optional[Sanitizer] = None
        self.last_tool_times: Dict[str, List[float]] = {}  # 速率检测
        self.session_alert_counts: Dict[str, int] = {}  # 每会话告警计数

        if CALLISTO_AVAILABLE:
            # 创建完整引擎配置
            cfg = CallistoConfig(
                circuit_breaker_threshold=threshold,
                burst_window=5.0,
                burst_count_threshold=10,
            )
            self.engine = CallistoEngine(cfg)

            # ========== 新增：自动集成脱敏器 ==========
            self.sanitizer = Sanitizer(
                enabled=True,
                input_sanitization=True,
                output_sanitization=True,
            )

            # 内容安全检测（脚本分析、URL检测、混淆检测）
            self.content_safety = ContentSafetyDetector()

            # 设置批准模式（auto 模式，自动处理）
            self.engine.set_approval_mode("auto")

            print(f"[CALLISTO] 引擎已初始化，脱敏器已启用", file=sys.stderr)

        # 加载持久化的熔断状态
        self._load_breaker_states()

    def get_session(self, session_id: str) -> Session:
        if session_id not in self.sessions:
            self.sessions[session_id] = Session(
                session_id=session_id,
                agent_id="openclaw"
            )
        return self.sessions[session_id]

    def get_breaker(self, session_id: str) -> CircuitBreaker:
        if session_id not in self.breakers:
            self.breakers[session_id] = CircuitBreaker(threshold=self.threshold)
        return self.breakers[session_id]

    def _load_breaker_states(self) -> None:
        """Load breaker states from disk. Clear expired OPEN states."""
        states = CircuitBreaker.load_state_file(self.BREAKER_STATE_FILE)
        now = time.time()
        for session_id, data in states.items():
            breaker = CircuitBreaker.from_dict(data)
            breaker.threshold = self.threshold
            # Reset expired OPEN states
            if breaker.state == "open" and now - breaker._opened_at > breaker.reset_timeout:
                breaker.state = "closed"
                breaker._consecutive_alerts = 0
                breaker._opened_at = 0.0
            self.breakers[session_id] = breaker

    def _save_breaker_states(self) -> None:
        """Save all breaker states to disk."""
        states = {}
        for session_id, breaker in self.breakers.items():
            states[session_id] = breaker.to_dict()
        CircuitBreaker.save_state_file(self.BREAKER_STATE_FILE, states)

    def _is_benign_command(self, cmd: str) -> bool:
        """检查是否是良性命令"""
        for pattern in _BENIGN_PATTERNS:
            if re.match(pattern, cmd, re.IGNORECASE):
                return True
        return False

    def _is_malicious_command(self, cmd: str) -> Optional[str]:
        """检查是否是恶意命令，返回匹配的描述"""
        for pattern in _MALICIOUS_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return pattern
        return None

    def _contains_sensitive_path(self, path: str) -> bool:
        """检查路径是否包含敏感文件"""
        path_lower = path.lower()
        for sensitive in _SENSITIVE_PATHS:
            if sensitive.lower() in path_lower:
                return True
        return False

    def _is_internal_address(self, target: str) -> bool:
        """检查是否是内网地址"""
        for pattern in _INTERNAL_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                return True
        return False

    def detect(self, tool_name: str, parameters: Dict, session_id: str) -> DetectResult:
        """检测单次工具调用的风险 - 使用完整引擎"""
        breaker = self.get_breaker(session_id)

        # 写入调试日志
        log_file = "/tmp/callisto-python.log"
        try:
            with open(log_file, "a") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] detect: tool={tool_name}, session={session_id}\n")
        except Exception as e:
            pass

        # 检查熔断状态
        if breaker.should_block():
            return DetectResult(
                status="blocked",
                session_id=session_id,
                alerts=[],
                circuit_breaker="OPEN",
                consecutive_alerts=breaker._consecutive_alerts,
                message=f"Session blocked: {breaker._consecutive_alerts} consecutive HIGH risk operations"
            )

        # ========== 初始化会话告警计数 ==========
        if session_id not in self.session_alert_counts:
            self.session_alert_counts[session_id] = 0

        # ========== 使用完整引擎（如果可用）==========
        if CALLISTO_AVAILABLE and self.engine:
            # 获取或创建会话
            session = self.get_session(session_id)

            # 创建事件
            event = CallEvent(
                event_id=f"{session_id}_{len(session.events)}",
                session_id=session_id,
                agent_id="openclaw",
                timestamp=time.time(),
                event_type=EventType.TOOL_CALL,
                tool_name=tool_name,
                parameters=parameters,
            )
            session.add_event(event)

            # ========== 脱敏处理 ==========
            if self.sanitizer:
                # 对参数进行脱敏
                for key, value in parameters.items():
                    if isinstance(value, str):
                        parameters[key] = self.sanitizer.sanitize(value)

            # ========== 使用引擎分析 ==========
            try:
                alerts = self.engine.analyze_session(session)

                # ========== 新增：恶意命令检测（即使引擎可用也要检测） ==========
                cmd = parameters.get("command", "") or parameters.get("cmd", "") or ""
                if cmd:
                    from callisto.engine import _is_malicious_command
                    if _is_malicious_command(cmd):
                        alerts.append(Alert(
                            timestamp=time.time(),
                            session_id=session_id,
                            risk_level=RiskLevel.HIGH,
                            attack_type=AttackType.A2_PRIV_ESCALATION,
                            source_module="CallistoAgent",
                            score=0.95,
                            explanation=f"检测到恶意命令：{cmd[:100]}"
                        ))

                # ========== 内容安全检测（脚本分析、URL、混淆） ==========
                if hasattr(self, 'content_safety'):
                    cs_findings = self.content_safety.analyze(tool_name, parameters)
                    for finding in cs_findings:
                        severity_map = {
                            "critical": (RiskLevel.CRITICAL, 0.98),
                            "high": (RiskLevel.HIGH, 0.92),
                            "medium": (RiskLevel.MEDIUM, 0.75),
                            "low": (RiskLevel.LOW, 0.5),
                        }
                        rl, sc = severity_map.get(finding.severity, (RiskLevel.LOW, 0.5))
                        alerts.append(Alert(
                            timestamp=time.time(),
                            session_id=session_id,
                            risk_level=rl,
                            attack_type=AttackType.A2_PRIV_ESCALATION,
                            source_module=f"ContentSafety:{finding.category}",
                            score=sc,
                            explanation=f"[{finding.severity.upper()}] {finding.description}"
                        ))

                # 记录告警到熔断器
                for alert in alerts:
                    if alert.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                        breaker.record_alert(alert)
                        self.session_alert_counts[session_id] += 1
                self._save_breaker_states()

                # 转换为字典格式
                alert_dicts = []
                for alert in alerts[-5:]:  # 只返回最新 5 个告警
                    alert_dicts.append({
                        "attack_type": alert.attack_type.value if hasattr(alert.attack_type, 'value') else str(alert.attack_type),
                        "risk_level": alert.risk_level.name if hasattr(alert.risk_level, 'name') else str(alert.risk_level),
                        "score": alert.score,
                        "explanation": alert.explanation[:200] if alert.explanation else "",
                    })

                # ========== 新增：同步告警到 Web Dashboard ==========
                if alert_dicts:
                    try:
                        import urllib.request
                        dashboard_url = "http://localhost:8765/api/alerts/add"
                        for alert in alert_dicts:
                            data = json.dumps({
                                "severity": alert["risk_level"].lower(),
                                "category": alert["attack_type"],
                                "message": alert["explanation"],
                                "session_id": session_id,
                            }).encode('utf-8')
                            req = urllib.request.Request(dashboard_url, data=data, headers={'Content-Type': 'application/json'})
                            urllib.request.urlopen(req, timeout=2)
                    except Exception as e:
                        # Dashboard 可能未启动，忽略错误
                        pass

                    # 同步会话信息到 Web Dashboard（使用 /sync 端点）
                    self._sync_session_to_dashboard(session_id, breaker)

                return DetectResult(
                    status="warning" if alert_dicts else "ok",
                    session_id=session_id,
                    alerts=alert_dicts,
                    circuit_breaker=breaker.state,
                    consecutive_alerts=breaker._consecutive_alerts
                )

            except Exception as e:
                print(f"[CALLISTO] 引擎分析错误：{e}", file=sys.stderr)
                # 降级到简单检测

        # ========== 降级：简单快速检测 ==========
        alerts = []

        # 速率洪水检测
        current_time = time.time()
        if session_id not in self.last_tool_times:
            self.last_tool_times[session_id] = []
        self.last_tool_times[session_id].append(current_time)
        self.last_tool_times[session_id] = [
            t for t in self.last_tool_times[session_id]
            if current_time - t <= 5.0
        ]
        if len(self.last_tool_times[session_id]) >= 8:
            alerts.append({
                "attack_type": "rate_flood",
                "risk_level": "HIGH",
                "score": 0.9,
                "explanation": f"速率洪水检测：{len(self.last_tool_times[session_id])} 次调用/5 秒"
            })

        # 获取命令内容
        cmd = parameters.get("command", "") or parameters.get("cmd", "") or ""
        file_path = parameters.get("file_path", "") or parameters.get("path", "") or ""
        url = parameters.get("url", "") or parameters.get("host", "") or ""

        # 恶意命令检测（使用扩展模式）
        if cmd:
            if CALLISTO_AVAILABLE:
                from callisto.engine import _is_malicious_command, _is_priv_escalation_command
                if _is_malicious_command(cmd) or _is_priv_escalation_command(cmd):
                    alerts.append({
                        "attack_type": "privilege_escalation",
                        "risk_level": "HIGH",
                        "score": 0.95,
                        "explanation": f"检测到危险命令"
                    })
            else:
                malicious = self._is_malicious_command(cmd)
                if malicious:
                    alerts.append({
                        "attack_type": "privilege_escalation",
                        "risk_level": "HIGH",
                        "score": 0.95,
                        "explanation": f"检测到恶意命令模式"
                    })

        # 内容安全检测（fallback 路径）
        if hasattr(self, 'content_safety'):
            cs_findings = self.content_safety.analyze(tool_name, parameters)
            for finding in cs_findings:
                severity_score = {"critical": 0.98, "high": 0.92, "medium": 0.75, "low": 0.5}.get(finding.severity, 0.5)
                risk_level = "HIGH" if finding.severity in ("critical", "high") else "MEDIUM"
                alerts.append({
                    "attack_type": "content_safety",
                    "risk_level": risk_level,
                    "score": severity_score,
                    "explanation": f"[{finding.severity.upper()}] {finding.description}"
                })

        # 敏感文件读取
        if file_path and self._contains_sensitive_path(file_path):
            alerts.append({
                "attack_type": "data_exfil",
                "risk_level": "HIGH" if any(x in file_path.lower() for x in ["shadow", "passwd", "sudoers", "id_rsa", "secret", "token"]) else "MEDIUM",
                "score": 0.85,
                "explanation": f"尝试读取敏感文件：{file_path[:100]}"
            })

        # 内网访问
        if url and self._is_internal_address(url):
            alerts.append({
                "attack_type": "data_exfil",
                "risk_level": "HIGH",
                "score": 0.85,
                "explanation": f"访问内网地址：{url[:100]}"
            })

        # 更新熔断器
        for alert in alerts:
            if alert["risk_level"] == "HIGH":
                alert_obj = type('obj', (object,), {
                    'risk_level': type('obj', (object,), {'value': 3, 'name': 'HIGH'})()
                })()
                breaker.record_alert(alert_obj)
                self.session_alert_counts[session_id] += 1
            self._save_breaker_states()

        # ========== 同步告警到 Web Dashboard ==========
        if alerts:
            try:
                import urllib.request
                dashboard_url = "http://localhost:8765/api/alerts/add"
                for alert in alerts:
                    data = json.dumps({
                        "severity": alert["risk_level"].lower(),
                        "category": alert["attack_type"],
                        "message": alert["explanation"],
                        "session_id": session_id,
                    }).encode('utf-8')
                    req = urllib.request.Request(dashboard_url, data=data, headers={'Content-Type': 'application/json'})
                    urllib.request.urlopen(req, timeout=2)
            except Exception:
                pass

        result = DetectResult(
            status="warning" if alerts else "ok",
            session_id=session_id,
            alerts=alerts,
            circuit_breaker=breaker.state,
            consecutive_alerts=breaker._consecutive_alerts
        )

        # ========== 同步会话到 Web Dashboard ==========
        self._sync_session_to_dashboard(session_id, breaker)

        return result

    def content_analysis(self, text: str, stage: str = "input", session_id: str = "") -> Dict[str, Any]:
        """Analyze text content for security risks.

        Stages:
        - "input": user message → prompt injection, malicious instructions
        - "output": agent response → data exfil, phishing, credential leakage
        - "reply": agent reply (interceptable) → same as output + blocking
        """
        findings = []
        if CALLISTO_AVAILABLE and hasattr(self, 'content_safety'):
            findings = self.content_safety.analyze_text(text, stage)

        alert_dicts = []
        max_severity = "low"
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        for finding in findings:
            alert_dicts.append({
                "severity": finding.severity,
                "category": finding.category,
                "description": finding.description,
                "evidence": finding.evidence[:200] if finding.evidence else "",
            })
            if severity_order.get(finding.severity, 0) > severity_order.get(max_severity, 0):
                max_severity = finding.severity

        return {
            "status": "blocked" if max_severity == "critical" and stage == "input" else ("warning" if alert_dicts else "ok"),
            "stage": stage,
            "alerts": alert_dicts,
            "max_severity": max_severity,
            "should_block": max_severity == "critical",
            "session_id": session_id,
        }

    def _sync_session_to_dashboard(self, session_id: str, breaker) -> None:
        """同步会话状态到 Web Dashboard"""
        try:
            import urllib.request
            session_url = f"http://localhost:8765/api/session/{session_id}/sync"
            data = json.dumps({
                "session_id": session_id,
                "state": breaker.state,
                "consecutive_alerts": breaker._consecutive_alerts,
                "tool_calls": len(self.last_tool_times.get(session_id, [])),
            }).encode('utf-8')
            req = urllib.request.Request(session_url, data=data, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            # Dashboard 可能未启动，忽略错误
            pass


def main():
    import argparse
    parser = argparse.ArgumentParser(description="CALLISTO OpenClaw Plugin Backend")
    parser.add_argument('action', choices=['scan', 'block', 'status', 'detect', 'startup_scan', 'content_analysis'], help='Action to perform')
    parser.add_argument('--session', type=str, help='Session ID')
    parser.add_argument('--threshold', type=int, default=3, help='Circuit breaker threshold')
    parser.add_argument('--reason', type=str, help='Block reason')

    args = parser.parse_args()

    # 创建 Agent
    agent = CallistoAgent(threshold=args.threshold)

    # 获取会话 ID
    session_id = args.session or f"session_{int(time.time())}"

    # 执行动作
    if args.action == 'detect':
        # Plugin 模式：从 stdin 读取工具调用信息
        input_data = json.loads(sys.stdin.read())
        # 优先使用 payload 中的 session_id（来自 OpenClaw ctx.sessionId）
        session_id = input_data.get('session_id', session_id)
        result = agent.detect(input_data.get('tool_name', 'unknown'),
                              input_data.get('parameters', {}),
                              session_id)
    elif args.action == 'scan':
        result = agent.scan(session_id) if hasattr(agent, 'scan') else DetectResult("ok", session_id, [])
    elif args.action == 'block':
        result = agent.block(session_id, args.reason) if hasattr(agent, 'block') else None
    elif args.action == 'status':
        breaker = agent.get_breaker(session_id)
        result = {
            "circuit_breaker": breaker.state,
            "consecutive_alerts": breaker._consecutive_alerts,
            "threshold": agent.threshold,
            "session_id": session_id
        }
    elif args.action == 'startup_scan':
        # OpenClaw 启动时扫描配置和技能文件
        try:
            # 添加 scripts 目录到路径
            # 路径：.../openclaw_plugin/callisto-skill/python/ → .../callisto-plugin/
            base_path = Path(__file__).resolve().parent.parent.parent.parent
            scripts_dir = base_path / "scripts"
            sys.path.insert(0, str(scripts_dir))
            from auto_scanner import AutoScanner
            scanner = AutoScanner(base_dir=base_path)
            scan_result = scanner.scan_all(force=True)
            result = {
                "status": "completed" if scan_result.get("total_issues", 0) == 0 else "warning",
                "scan_result": scan_result
            }
        except ImportError as e:
            result = {
                "status": "error",
                "error": f"AutoScanner not available: {e}"
            }
        except Exception as e:
            result = {
                "status": "error",
                "error": str(e)
            }
    elif args.action == 'content_analysis':
        # 内容安全审查：从 stdin 读取 {text, stage, session_id}
        input_data = json.loads(sys.stdin.read())
        session_id = input_data.get('session_id', session_id)
        result = agent.content_analysis(
            text=input_data.get('text', ''),
            stage=input_data.get('stage', 'input'),
            session_id=session_id,
        )
    else:
        result = {"error": f"Unknown action: {args.action}"}

    # 输出 JSON 结果
    if hasattr(result, '__dataclass_fields__'):
        print(json.dumps(asdict(result), indent=2))
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    import argparse
    main()
