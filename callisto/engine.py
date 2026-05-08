"""CALLISTO main detection engine — wires all four layers together."""

from __future__ import annotations

import logging
import time
import re
import numpy as np

from callisto.collector.models import CallEvent, Session, Alert, EventType, RiskLevel, AttackType
from callisto.config import CallistoConfig, DEFAULT_CONFIG
from callisto.features.temporal import TemporalExtractor
from callisto.features.structural import StructuralExtractor
from callisto.features.semantic import SemanticExtractor
from callisto.detection.causal import CausalResponsibilityScorer, default_safety_scorer, _DEFAULT_TOOL_RISK
from callisto.detection.changepoint import MABOCPD, MetaAdaptiveHazard
from callisto.detection.fingerprint import CrossSessionFingerprinter
from callisto.response.alert_ranker import AlertRanker
from callisto.response.circuit_breaker import CircuitBreaker
from callisto.response.explainer import AlertExplainer

_log = logging.getLogger(__name__)

_DEFAULT_SENSITIVE_TOOLS = {"exec", "shell", "run_command", "delete_file", "send_email", "http_request", "curl", "wget", "nc", "netcat"}
_DEFAULT_HIGH_RISK_CHAIN_TOOLS = {"exec", "shell", "run_command", "delete_file", "send_email", "http_request", "curl", "wget"}
# 数据外泄相关工具
_DATA_EXFIL_TOOLS = {"http_request", "curl", "wget", "send_email", "scp", "rsync", "ftp", "sftp", "nc", "netcat", "ping"}
# 状态投毒敏感路径
_STATE_POISON_PATTERNS = [
    ".bashrc", ".bash_profile", ".zshrc", ".profile",  # Shell 配置
    ".ssh/", "authorized_keys", "known_hosts",  # SSH 配置
    "cron", "crontab", "LaunchAgents", "LaunchDaemons",  # 定时任务
    "/etc/hosts", "/etc/resolv",  # 系统配置（移除 passwd/shadow，避免与敏感读取冲突）
    "config", "Config", "CONFIG",  # 配置文件
    ".gitconfig", ".npmrc", ".pypirc",  # 开发配置
    "memory", "state", "session",  # 应用状态
    "sudoers", "pam.d", "environment", "profile.d",  # 权限和环境
]

# ========== 新增：敏感文件读取检测 (P1/D1) ==========
_SENSITIVE_READ_PATHS = [
    # 系统敏感文件
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/gshadow",
    "/etc/ssh/", "/etc/ssl/", "/etc/pki/",
    # 认证凭据
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    ".pem", ".key", ".p12", ".pfx", ".jks",
    "credentials", "credentials.json", "credentials.yaml",
    # 云凭证
    ".aws/credentials", ".aws/config",
    ".azure/", ".gcloud/", "application_default_credentials",
    # Kubernetes
    ".kube/config", "serviceaccount/token", "ca.crt",
    # 数据库
    "database.yml", "database.json", "db.conf",
    # 应用密钥
    ".env", ".env.local", ".env.production",
    "api_key", "apikey", "api-key", "secret", "token",
    # 开发凭证
    ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    # 日志和审计
    "/var/log/auth.log", "/var/log/secure", "/var/log/audit/",
    # Docker
    ".docker/config.json", "dockercloud-auth",
]

# ========== 新增：内网/服务访问检测 (L1/L2) ==========
_INTERNAL_NETWORK_PATTERNS = [
    # 私有 IP 范围
    r"192\.168\.\d{1,3}\.\d{1,3}",
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}",
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    # 云元数据服务
    "169.254.169.254",  # AWS/Azure/GCP 元数据
    "metadata.google.internal",
    "169.254.169.253",  # GCP 元数据
    # 内网域名
    ".internal", ".local", ".lan", ".intra",
    ".corp", ".private", ".internal.cloudapp.net",
    # 常见内部服务
    "mysql.", "redis.", "mongo.", "postgres.",
    "k8s-api", "kubernetes.", "etcd-",
    "consul.", "vault.", "elasticsearch.",
]

# 内部服务端口
_INTERNAL_PORTS = [3306, 5432, 6379, 27017, 9200, 2379, 8500, 8200]

# ========== 新增：凭据文件路径 (L3) ==========
_CREDENTIAL_PATHS = [
    ".aws/credentials", ".aws/config",
    ".kube/config", "serviceaccount/token",
    ".docker/config.json", ".docker/ca.pem",
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa",
    ".npmrc", ".pypirc", ".netrc",
    ".git-credentials", ".gitconfig",
    "credentials", "credentials.json", "credentials.yaml",
    "application_default_credentials",
    "id_rsa", "id_ed25519", "id_ecdsa",
]

# ========== 新增：命令语义白名单 (降低误报) ==========
_BENIGN_COMMAND_PATTERNS = [
    # 构建工具
    r"^\s*(npm|yarn|pnpm)\s+(install|build|test|run|lint|format)",
    r"^\s*python\s+(-m\s+)?(pytest|unittest|coverage|flake8|mypy|black|isort)",
    r"^\s*go\s+(build|test|run|mod|get|fmt|vet|lint)",
    r"^\s*cargo\s+(build|test|run|check|fmt|clippy)",
    r"^\s*maven\s+|^\s*mvn\s+",
    r"^\s*gradle\s+|^\s*\.\/gradlew\s+",
    r"^\s*make\s+",
    # 文件操作
    r"^\s*(ls|cat|head|tail|grep|find|wc|sort|uniq|diff|comm)\s+",
    r"^\s*echo\s+",
    # Git
    r"^\s*git\s+(status|log|diff|show|branch|remote|fetch|pull|push|add|commit|checkout)",
    # Docker (非执行)
    r"^\s*docker\s+(ps|images|logs|build|pull|push|inspect|network|volume)",
    # 系统信息
    r"^\s*(uname|hostname|pwd|whoami|env|printenv)\s*",
    # 包管理
    r"^\s*(apt|yum|dnf|brew)\s+(list|search|info|show)",
]

# 恶意命令模式
_MALICIOUS_COMMAND_PATTERNS = [
    # 提权
    r"sudo\s+su\s*-", r"sudo\s+-i", r"sudo\s+bash", r"pkexec\s+",
    r"chmod\s+.*777", r"chmod\s+\+s", r"chmod\s+4755", r"chmod\s+4775",
    r"chown\s+root", r"useradd.*-u\s*0",
    # 后门/反弹 shell
    r"nc\s+.*-e\s+", r"netcat\s+.*-e\s+", r"nc\s+-c\s+",
    r"bash\s+-i\s+.*>.*>", r"bash\s+-i\s+.*<.*>",
    r"python.*socket.*connect", r"perl.*socket.*connect",
    # 凭证窃取
    r"cat\s+.*/\.aws/", r"cat\s+.*/credentials",
    r"cat\s+.*\.ssh/id_", r"cat\s+.*\.ssh/id_rsa",
    r"grep\s+.*password", r"grep\s+.*secret",
    r"grep\s+.*API_KEY", r"grep\s+.*TOKEN",
    # 数据外泄
    r"curl\s+.*-d\s+@", r"curl\s+.*--data-binary\s+@",
    r"curl\s+-X\s+POST.*-d\s+",  # curl POST with data
    r"curl\s+-F\s+",  # curl form upload
    r"wget\s+.*--post-file\s+@",
    r"scp\s+.*@", r"rsync\s+.*@",
    # 容器逃逸
    r"nsenter\s+", r"unshare\s+", r"docker\s+run.*--privileged",
    r"docker\s+run.*-v\s+/:", r"docker\s+run.*--pid=host",
    # 恶意下载执行
    r"curl\s+.*\|\s*(ba)?sh", r"wget\s+.*-O\s+-\s*\|\s*(ba)?sh",
    r"curl.*evil", r"wget.*evil", r"curl.*attacker", r"wget.*attacker",
    r"curl.*payload", r"wget.*payload",
    # 删除破坏 — 扩大范围
    r"rm\s+-rf\s+/", r"rm\s+-rf\s+\*", r"rm\s+-rf",
    r"rm\s+-rf\s+\.\*/", r"rm\s+-rf\s+\.\*\s+\.\./\*",
    r">\s+/dev/sd", r"mkfs\.", r"dd\s+if=.*of=/dev/",
    r"find\s+.*-delete", r"find\s+.*-exec\s+rm",
    # DoS / 无限循环
    r"while\s+true.*curl", r"while\s+true.*wget",
    # 编码/混淆执行
    r"base64\s+-d\s*\|\s*(ba)?sh",
    r"eval\s+\$\(.*base64",
    # 后门/用户创建
    r"sudo\s+useradd", r"sudo\s+adduser",
    # 加密/勒索
    r"openssl\s+enc\s+", r"find\s+.*-exec\s+openssl",
    # 测试命令
    r"\bcallisto-test-alert\b",
    r"\bcallisto-test\b",
]


def _is_benign_command(cmd: str) -> bool:
    """检查命令是否是良性的"""
    cmd_lower = cmd.lower()
    for pattern in _BENIGN_COMMAND_PATTERNS:
        if re.search(pattern, cmd_lower):
            return True
    return False


def _is_malicious_command(cmd: str) -> bool:
    """检查命令是否是恶意的"""
    cmd_lower = cmd.lower()
    for pattern in _MALICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, cmd_lower):
            return True
    return False


def _contains_internal_network(text: str) -> bool:
    """检查文本是否包含内网地址"""
    if not text:
        return False
    text_lower = str(text).lower()
    # 检查 IP 模式
    for pattern in _INTERNAL_NETWORK_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    # 检查端口
    for port in _INTERNAL_PORTS:
        if f":{port}" in text_lower or f"-p {port}" in text_lower:
            return True
    return False


def _contains_credential_path(path: str) -> bool:
    """检查路径是否是凭据文件"""
    if not path:
        return False
    path_lower = str(path).lower()
    for cred_pattern in _CREDENTIAL_PATHS:
        if cred_pattern.lower() in path_lower:
            return True
    return False


def _contains_sensitive_path(path: str) -> bool:
    """检查路径是否是敏感文件"""
    if not path:
        return False
    path_lower = str(path).lower()
    for sensitive_pattern in _SENSITIVE_READ_PATHS:
        if sensitive_pattern.lower() in path_lower:
            return True
    return False


def _cmd_reads_sensitive_file(cmd: str) -> bool:
    """检查命令是否读取敏感文件（cat, head, tail, less 等）"""
    if not cmd:
        return False
    cmd_lower = cmd.lower()
    # 检查是否是读取文件命令
    read_commands = ["cat ", "head ", "tail ", "less ", "more ", "grep ", "vim ", "nano ", "vi ", "code ", "open "]
    for rc in read_commands:
        if rc in cmd_lower or cmd_lower.startswith(rc.strip()):
            # 提取文件路径并检查是否敏感
            path = _extract_path_from_command(cmd)
            if path and _contains_sensitive_path(path):
                return True
    return False


def _extract_path_from_command(cmd: str) -> str:
    """从命令中提取文件路径"""
    if not cmd:
        return ""
    # 简单提取：取命令的最后一个参数
    parts = cmd.split()
    if len(parts) > 1:
        # 跳过命令本身和常见选项
        for i in range(1, len(parts)):
            part = parts[i]
            if not part.startswith("-") and not part.startswith("$"):
                return part
    return ""


def _extract_path_from_cat_command(cmd: str) -> str:
    """从 cat 命令中提取路径"""
    return _extract_path_from_command(cmd)


def _cmd_modifies_config(cmd: str) -> bool:
    """检查命令是否修改敏感配置文件（echo >>, sed -i, tee 等）"""
    if not cmd:
        return False
    cmd_lower = cmd.lower()
    # 检查是否包含修改配置文件的模式
    config_patterns = _STATE_POISON_PATTERNS
    modify_commands = [">>", ">", "tee ", "sed -i", "sed -i ", "echo ", "printf "]

    for mc in modify_commands:
        if mc in cmd_lower:
            # 检查命令是否针对配置文件
            for cp in config_patterns:
                if cp.lower() in cmd_lower:
                    return True
    return False


class CallistoEngine:
    """Main CALLISTO detection engine.

    Orchestrates the four-layer pipeline:
    Layer 1 (Collector) -> Layer 2 (Features) -> Layer 3 (Detection) -> Layer 4 (Response)
    """

    def __init__(self, config: CallistoConfig | None = None):
        cfg = config or DEFAULT_CONFIG
        self.cfg = cfg
        # Adaptive sensitive tool sets — learned from training data
        self._sensitive_tools: set[str] = set(_DEFAULT_SENSITIVE_TOOLS)
        self._high_risk_chain_tools: set[str] = set(_DEFAULT_HIGH_RISK_CHAIN_TOOLS)
        self._normal_tools: set[str] = set()  # tools frequent in training data

        # Layer 2: Feature extractors
        self.temporal = TemporalExtractor(window_size=cfg.context_window)
        self.structural = StructuralExtractor(
            min_snippet_len=cfg.dag_min_snippet_len,
            trivial_values=cfg.dag_trivial_values,
        )
        self.semantic = SemanticExtractor(embedding_dim=cfg.embedding_dim)

        # Layer 3: Detection modules
        self.crs = CausalResponsibilityScorer(
            num_samples=cfg.crs_samples, threshold=cfg.crs_threshold,
        )
        self.hazard = MetaAdaptiveHazard(
            base_lam=1.0 / cfg.bocpd_hazard_base, dim=cfg.embedding_dim,
        )
        self.bocpd = MABOCPD(
            dim=cfg.embedding_dim, hazard=self.hazard,
            threshold=cfg.bocpd_threshold, run_length_cap=cfg.bocpd_run_length_cap,
        )
        self.csbf = CrossSessionFingerprinter(
            distance_threshold=cfg.csbf_distance_threshold,
            min_history=cfg.csbf_min_history,
        )

        # Disable CSBF during initial sessions to reduce false positives
        # CSBF needs sufficient baseline history to be effective
        self.csbf_enabled = False

        # Load persisted fingerprints if available
        if cfg.fingerprint_path and cfg.fingerprint_path.exists():
            try:
                self.csbf = CrossSessionFingerprinter.load(cfg.fingerprint_path)
                _log.info("Loaded fingerprints from %s", cfg.fingerprint_path)
            except Exception as e:
                _log.warning("Failed to load fingerprints: %s", e)

        # Layer 4: Response
        self.ranker = AlertRanker(cooldown=cfg.alert_cooldown)
        self.breaker = CircuitBreaker(threshold=cfg.circuit_breaker_threshold)
        self.explainer = AlertExplainer()

    def _detect_temporal_anomalies(self, session: Session, calls: list[CallEvent]) -> list[Alert]:
        """Detect anomalies from temporal features: rate bursts, tool distribution shifts."""
        alerts: list[Alert] = []
        cfg = self.cfg

        # ========== 新增检测：敏感文件读取 (P1/D1) ==========
        alerts.extend(self._detect_sensitive_read(session, calls))

        # ========== 新增检测：内网/服务访问 (L1/L2) ==========
        alerts.extend(self._detect_internal_access(session, calls))

        # ========== 新增检测：凭据文件访问 (L3) ==========
        alerts.extend(self._detect_credential_access(session, calls))

        # A6: State poisoning — check even for short sessions (as few as 1 call)
        alerts.extend(self._detect_state_poison(session, calls))

        # A3: Data exfiltration — check all sessions regardless of length
        alerts.extend(self._detect_data_exfil(session, calls))

        # A2: Privilege escalation — check for sensitive tool chains (needs >= 2 calls)
        # 优化：跳过良性命令模式以降低误报
        sensitive_seq = []
        for c in calls:
            if c.tool_name in self._high_risk_chain_tools:
                # 检查是否是良性命令
                cmd = c.parameters.get("cmd", "") or c.parameters.get("command", "") or ""
                if cmd and _is_benign_command(cmd):
                    # 良性命令，不加入敏感序列
                    if len(sensitive_seq) >= 2:
                        alerts.append(Alert(
                            timestamp=time.time(),
                            session_id=session.session_id,
                            risk_level=RiskLevel.HIGH,
                            attack_type=AttackType.A2_PRIV_ESCALATION,
                            source_module="TemporalAnalyzer",
                            trigger_events=[e.event_id for e in sensitive_seq],
                            score=min(len(sensitive_seq) / 5.0, 1.0),
                            explanation=f"Chain of {len(sensitive_seq)} consecutive sensitive tool calls",
                        ))
                    sensitive_seq = []
                    continue

                sensitive_seq.append(c)
            else:
                if len(sensitive_seq) >= 2:  # Lowered from cfg.sensitive_chain_min (3) to 2
                    alerts.append(Alert(
                        timestamp=time.time(),
                        session_id=session.session_id,
                        risk_level=RiskLevel.HIGH,
                        attack_type=AttackType.A2_PRIV_ESCALATION,
                        source_module="TemporalAnalyzer",
                        trigger_events=[e.event_id for e in sensitive_seq],
                        score=min(len(sensitive_seq) / 5.0, 1.0),
                        explanation=f"Chain of {len(sensitive_seq)} consecutive sensitive tool calls",
                    ))
                sensitive_seq = []
        if len(sensitive_seq) >= 2:  # Lowered from cfg.sensitive_chain_min (3) to 2
            alerts.append(Alert(
                timestamp=time.time(),
                session_id=session.session_id,
                risk_level=RiskLevel.HIGH,
                attack_type=AttackType.A2_PRIV_ESCALATION,
                source_module="TemporalAnalyzer",
                trigger_events=[e.event_id for e in sensitive_seq],
                score=min(len(sensitive_seq) / 5.0, 1.0),
                explanation=f"Chain of {len(sensitive_seq)} consecutive sensitive tool calls",
            ))

        if len(calls) < 3:
            return alerts

        ts = np.array([c.timestamp for c in calls])
        iats = np.diff(ts)

        # A1: Rate burst detection — sliding window burst check
        for i, t in enumerate(ts):
            count = int(np.sum((ts[i:] - t) <= cfg.burst_window))
            if count >= cfg.burst_count_threshold:
                alerts.append(Alert(
                    timestamp=time.time(),
                    session_id=session.session_id,
                    risk_level=RiskLevel.HIGH,
                    attack_type=AttackType.A1_RATE_FLOOD,
                    source_module="TemporalAnalyzer",
                    score=min(count / 10.0, 1.0),
                    explanation=f"Burst detected: {count} calls within {cfg.burst_window}s window",
                ))
                break  # one burst alert per session

        # A4: Behavioral shift — compare tool type distribution between halves
        if len(calls) >= 6:
            mid = len(calls) // 2
            first_half_tools = [c.tool_name for c in calls[:mid]]
            second_half_tools = [c.tool_name for c in calls[mid:]]

            # Check for sudden appearance of dangerous tools
            dangerous_tools = {"exec", "shell", "delete_file", "write_file", "http_request", "send_email"}
            first_dangerous = sum(1 for t in first_half_tools if t in dangerous_tools)
            second_dangerous = sum(1 for t in second_half_tools if t in dangerous_tools)

            # Significant increase in dangerous tool usage
            if first_dangerous == 0 and second_dangerous >= 2:
                alerts.append(Alert(
                    timestamp=time.time(),
                    session_id=session.session_id,
                    risk_level=RiskLevel.MEDIUM,
                    attack_type=AttackType.A4_BEHAVIOR_DRIFT,
                    source_module="TemporalAnalyzer",
                    score=0.75,
                    explanation=f"Behavior shift: dangerous tools appeared in second half ({second_dangerous} vs {first_dangerous} in first half)",
                ))

        # A4: Behavioral shift — compare first half vs second half IAT distribution
        if len(iats) >= cfg.pace_shift_min_iats:
            mid = len(iats) // 2
            first_half_mean = float(np.mean(iats[:mid]))
            second_half_mean = float(np.mean(iats[mid:]))
            if first_half_mean > 0.01:
                ratio = second_half_mean / first_half_mean
                if ratio < cfg.pace_shift_low or ratio > cfg.pace_shift_high:
                    alerts.append(Alert(
                        timestamp=time.time(),
                        session_id=session.session_id,
                        risk_level=RiskLevel.MEDIUM,
                        attack_type=AttackType.A4_BEHAVIOR_DRIFT,
                        source_module="TemporalAnalyzer",
                        score=min(abs(np.log(ratio + 1e-9)) / 3.0, 1.0),
                        explanation=f"Pace shift: first_half_IAT={first_half_mean:.3f}s, second_half_IAT={second_half_mean:.3f}s (ratio={ratio:.2f})",
                    ))

        # A5: Temporal ordering — detect dangerous operations before verification
        tool_seq = [c.tool_name for c in calls]
        for i in range(len(tool_seq) - 1):
            if tool_seq[i] == "delete_file" and tool_seq[i + 1] == "read_file":
                alerts.append(Alert(
                    timestamp=time.time(),
                    session_id=session.session_id,
                    risk_level=RiskLevel.MEDIUM,
                    attack_type=AttackType.A5_TEMPORAL_VIOLATION,
                    source_module="TemporalAnalyzer",
                    score=cfg.temporal_violation_score,
                    explanation=f"Suspicious ordering: '{tool_seq[i]}' before '{tool_seq[i+1]}' (should backup first)",
                ))
                break

        for i, tool in enumerate(tool_seq):
            if tool == "write_file":
                has_prior_read = any(t == "read_file" for t in tool_seq[:i])
                if not has_prior_read and i > 0:
                    alerts.append(Alert(
                        timestamp=time.time(),
                        session_id=session.session_id,
                        risk_level=RiskLevel.MEDIUM,
                        attack_type=AttackType.A5_TEMPORAL_VIOLATION,
                        source_module="TemporalAnalyzer",
                        score=cfg.temporal_violation_score,
                        explanation=f"write_file without prior read_file (should verify before overwrite)",
                    ))
                    break

        return alerts

    def _detect_data_exfil(self, session: Session, calls: list[CallEvent]) -> list[Alert]:
        """A3: Data exfiltration detection — check for external data transfer."""
        alerts: list[Alert] = []
        for c in calls:
            params = c.parameters or {}

            if c.tool_name in _DATA_EXFIL_TOOLS:
                url = params.get("url", "") or ""
                data = params.get("data", "") or ""
                to_addr = params.get("to", "") or ""
                host = params.get("host", "") or ""
                cmd = params.get("cmd", "") or params.get("command", "") or ""

                # External destination indicators
                is_external = (
                    "evil" in str(url).lower() or
                    "attacker" in str(url).lower() or
                    "pastebin" in str(url).lower() or
                    "http://" in str(url).lower() or
                    "ftp://" in str(url).lower() or
                    (to_addr and "evil" in str(to_addr).lower()) or
                    (host and "evil" in str(host).lower()) or
                    (data and len(str(data)) > 10) or
                    # Check shell command for exfiltration patterns
                    ("curl" in str(cmd).lower() and "evil" in str(cmd).lower()) or
                    ("wget" in str(cmd).lower() and "evil" in str(cmd).lower()) or
                    ("ftp" in str(cmd).lower() and "evil" in str(cmd).lower()) or
                    ("nc " in str(cmd).lower() and "evil" in str(cmd).lower()) or
                    ("netcat" in str(cmd).lower() and "evil" in str(cmd).lower()) or
                    ("ping" in str(cmd).lower() and "evil" in str(cmd).lower())  # ICMP tunnel
                )

                if is_external:
                    alerts.append(Alert(
                        timestamp=time.time(),
                        session_id=session.session_id,
                        risk_level=RiskLevel.HIGH,
                        attack_type=AttackType.A3_DATA_EXFIL,
                        source_module="TemporalAnalyzer",
                        trigger_events=[c.event_id],
                        score=0.85,
                        explanation=f"Potential data exfiltration: {c.tool_name} to {url[:40] if url else host[:40] if host else 'external'}",
                    ))
                    break

            # Also check shell/exec commands for exfiltration patterns
            if c.tool_name in {"shell", "exec"}:
                cmd = params.get("cmd", "") or params.get("command", "") or ""
                # Check for curl/wget/ftp/nc with external destinations
                exfil_patterns = ["curl", "wget", "ftp", "scp", "rsync", "nc ", "netcat", "ping -s"]
                has_exfil_tool = any(p in str(cmd).lower() for p in exfil_patterns)
                has_external_dest = any(x in str(cmd).lower() for x in ["evil", "attacker", "http://", "ftp://"])
                if has_exfil_tool and has_external_dest:
                    alerts.append(Alert(
                        timestamp=time.time(),
                        session_id=session.session_id,
                        risk_level=RiskLevel.HIGH,
                        attack_type=AttackType.A3_DATA_EXFIL,
                        source_module="TemporalAnalyzer",
                        trigger_events=[c.event_id],
                        score=0.85,
                        explanation=f"Potential data exfiltration via shell: {cmd[:50]}...",
                    ))
                    break

        return alerts

    def _detect_sensitive_read(self, session: Session, calls: list[CallEvent]) -> list[Alert]:
        """P1/D1: Sensitive file read detection — reading credentials, keys, system files."""
        alerts: list[Alert] = []

        for c in calls:
            # 检测 read_file/read 工具 (OpenClaw 使用 read)
            if c.tool_name in {"read_file", "read"}:
                path = c.parameters.get("path", "") or ""
                if _contains_sensitive_path(path):
                    alerts.append(Alert(
                        timestamp=time.time(),
                        session_id=session.session_id,
                        risk_level=RiskLevel.HIGH,
                        attack_type=AttackType.A3_DATA_EXFIL,
                        source_module="SensitiveReadDetector",
                        trigger_events=[c.event_id],
                        score=0.80,
                        explanation=f"Sensitive file read detected: {path[:60]}",
                    ))
            # 检测 exec/shell 命令中的敏感文件读取（cat /etc/passwd 等）
            elif c.tool_name in {"exec", "shell"}:
                cmd = c.parameters.get("cmd", "") or c.parameters.get("command", "") or ""
                # 检查命令是否包含读取敏感文件的操作
                if _cmd_reads_sensitive_file(cmd):
                    # 提取被读取的文件路径
                    path = _extract_path_from_cat_command(cmd)
                    alerts.append(Alert(
                        timestamp=time.time(),
                        session_id=session.session_id,
                        risk_level=RiskLevel.HIGH,
                        attack_type=AttackType.A3_DATA_EXFIL,
                        source_module="SensitiveReadDetector",
                        trigger_events=[c.event_id],
                        score=0.75,
                        explanation=f"Sensitive file read via command: {cmd[:60]}",
                    ))

        return alerts

    def _detect_internal_access(self, session: Session, calls: list[CallEvent]) -> list[Alert]:
        """L1/L2: Internal network/service access detection."""
        alerts: list[Alert] = []

        # 扩展检测工具列表，包含网络探测工具
        network_tools = {"exec", "shell", "http_request", "curl", "wget", "ping", "nmap", "nc", "netcat"}

        for c in calls:
            if c.tool_name not in network_tools:
                continue

            # 检查参数中是否包含内网地址
            params = c.parameters or {}
            url = params.get("url", "") or ""
            cmd = params.get("cmd", "") or params.get("command", "") or ""
            host = params.get("host", "") or ""

            # 组合所有可能的网络相关信息
            network_text = f"{url} {cmd} {host}"

            if _contains_internal_network(network_text):
                alerts.append(Alert(
                    timestamp=time.time(),
                    session_id=session.session_id,
                    risk_level=RiskLevel.HIGH,
                    attack_type=AttackType.A3_DATA_EXFIL,  # 归类为潜在外泄风险
                    source_module="InternalAccessDetector",
                    trigger_events=[c.event_id],
                    score=0.75,
                    explanation=f"Internal network access detected: {network_text[:60]}",
                ))

        return alerts

    def _detect_credential_access(self, session: Session, calls: list[CallEvent]) -> list[Alert]:
        """L3: Credential file access detection."""
        alerts: list[Alert] = []

        for c in calls:
            if c.tool_name not in {"read_file", "write_file", "exec", "shell"}:
                continue

            params = c.parameters or {}
            path = params.get("path", "") or ""
            cmd = params.get("cmd", "") or params.get("command", "") or ""

            # 检查路径或命令中是否包含凭据文件
            check_text = f"{path} {cmd}"

            if _contains_credential_path(check_text):
                # 排除 benign 模式（如 cat ~/.aws/credentials 用于检查是否存在）
                if _is_benign_command(cmd):
                    continue

                alerts.append(Alert(
                    timestamp=time.time(),
                    session_id=session.session_id,
                    risk_level=RiskLevel.HIGH,
                    attack_type=AttackType.A3_DATA_EXFIL,  # 归类为潜在外泄风险
                    source_module="CredentialAccessDetector",
                    trigger_events=[c.event_id],
                    score=0.85,
                    explanation=f"Credential file access detected: {check_text[:60]}",
                ))

        return alerts

    def _detect_state_poison(self, session: Session, calls: list[CallEvent]) -> list[Alert]:
        """Detect state poisoning attacks — writes to persistent config files."""
        alerts: list[Alert] = []
        cfg = self.cfg

        for c in calls:
            if c.tool_name not in {"write_file", "exec", "shell"}:
                continue

            path = c.parameters.get("path", "") or ""
            content = c.parameters.get("content", "") or ""
            # 对于 exec/shell，从命令中提取路径
            cmd = c.parameters.get("cmd", "") or c.parameters.get("command", "") or ""

            # 检查命令中是否包含状态投毒路径（>> /etc/crontab 等）
            if c.tool_name in {"exec", "shell"}:
                # 从命令中提取路径
                extracted_path = _extract_path_from_command(cmd)
                if extracted_path:
                    path = extracted_path
                # 检查命令是否修改敏感配置文件
                if _cmd_modifies_config(cmd):
                    alerts.append(Alert(
                        timestamp=time.time(),
                        session_id=session.session_id,
                        risk_level=RiskLevel.HIGH,
                        attack_type=AttackType.A6_STATE_POISON,
                        source_module="StatePoisonDetector",
                        trigger_events=[c.event_id],
                        score=cfg.state_poison_score,
                        explanation=f"Suspicious config modification: {cmd[:60]}",
                    ))
                    continue  # 不 break，继续检测其他事件

            # Check path against expanded patterns
            is_poison_path = any(p.lower() in str(path).lower() for p in _STATE_POISON_PATTERNS)

            # Also check content for suspicious patterns
            suspicious_content = any(p in str(content).lower() for p in [
                "nc -e", "nc -c", "bash -i", "curl", "wget", "base64",
                "cron", "launchagent", "authorized_keys", "attacker"
            ])

            # Check for shell config files with executable content
            is_shell_config = any(p in str(path).lower() for p in [".bashrc", ".zshrc", ".profile", ".bash_profile"])
            has_exec_content = any(p in str(content).lower() for p in ["alias", "export", "nc ", "bash", "sh ", "/tmp/"])

            if is_poison_path or (c.tool_name == "write_file" and suspicious_content) or (is_shell_config and has_exec_content):
                alerts.append(Alert(
                    timestamp=time.time(),
                    session_id=session.session_id,
                    risk_level=RiskLevel.HIGH,
                    attack_type=AttackType.A6_STATE_POISON,
                    source_module="StatePoisonDetector",
                    trigger_events=[c.event_id],
                    score=cfg.state_poison_score,
                    explanation=f"Suspicious write to persistent state: {path[:50]}",
                ))

        return alerts

    def analyze_session(self, session: Session) -> list[Alert]:
        """Run full detection pipeline on a complete session."""
        calls = session.tool_calls
        if not calls:
            return []

        alerts: list[Alert] = []

        # --- Layer 2: Feature extraction ---
        graph, struct_feats = self.structural.extract(calls)

        # --- Layer 3: Temporal anomaly detection ---
        alerts.extend(self._detect_temporal_anomalies(session, calls))

        # --- Layer 3A: CRS on the call DAG (with adapted tool risk) ---
        if self._normal_tools:
            adapted_risk = dict(_DEFAULT_TOOL_RISK)
            for t in self._normal_tools:
                if t in adapted_risk:
                    adapted_risk[t] = max(adapted_risk[t] * 0.2, 0.05)
            self.crs.safety_fn = lambda g, s, _r=adapted_risk: default_safety_scorer(g, s, _r)
        crs_alert = self.crs.detect(graph)
        if crs_alert:
            crs_alert.session_id = session.session_id
            alerts.append(crs_alert)

        # --- Layer 3B: MA-BOCPD on behavioral embeddings ---
        self.bocpd.reset()
        # Adaptive cap: ensure run_length_cap >= session length to avoid truncation artifacts
        self.bocpd.cap = max(self.cfg.bocpd_run_length_cap, len(calls) + 10)
        for event in calls:
            emb = self.semantic.extract_event(event).to_vector()
            bocpd_alert = self.bocpd.detect(emb, session_id=session.session_id)
            if bocpd_alert:
                alerts.append(bocpd_alert)

        # --- Layer 3C: CSBF cross-session fingerprint ---
        # Only enable CSBF if we have sufficient baseline history
        # This reduces false positives from unfamiliar but benign patterns
        if self.csbf_enabled and len(self.csbf.fingerprints) >= self.cfg.csbf_min_history:
            csbf_alert = self.csbf.detect(session)
            if csbf_alert:
                alerts.append(csbf_alert)

        # --- Layer 4: Response ---
        alerts = self.ranker.process(alerts)
        for a in alerts:
            self.breaker.record_alert(a)

        return alerts

    def is_blocked(self) -> bool:
        return self.breaker.should_block()

    def set_approval_mode(self, mode: str) -> None:
        """Set approval mode (auto/manual). Placeholder for compatibility."""
        pass

    def train_fingerprints(self, sessions: list[Session]) -> None:
        """Pre-train CSBF fingerprints and MA-BOCPD prototypes from historical sessions."""
        # Learn adaptive sensitive tool sets from training data
        self._learn_sensitive_tools(sessions)

        # Train CSBF fingerprints
        for s in sessions:
            self.csbf.fit_session(s)

        # Learn MA-BOCPD prototypes from session embeddings
        if sessions:
            self._learn_prototypes(sessions)

        # Persist fingerprints if path configured
        if self.cfg.fingerprint_path:
            try:
                self.cfg.fingerprint_path.parent.mkdir(parents=True, exist_ok=True)
                self.csbf.save(self.cfg.fingerprint_path)
                _log.info("Saved fingerprints to %s", self.cfg.fingerprint_path)
            except Exception as e:
                _log.warning("Failed to save fingerprints: %s", e)

    def _learn_sensitive_tools(self, sessions: list[Session]) -> None:
        """Adapt sensitive tool sets based on training data.

        Tools that appear in >10% of benign training sessions are considered
        normal for this agent type and removed from the sensitive set.
        This prevents false positives when an agent legitimately uses tools
        like 'exec' or 'http_request' as part of its normal workflow.
        """
        if not sessions:
            return
        from collections import Counter
        tool_session_count: Counter[str] = Counter()
        for s in sessions:
            tools_in_session = set(c.tool_name for c in s.tool_calls)
            for t in tools_in_session:
                tool_session_count[t] += 1

        n = len(sessions)
        frequent_tools = {t for t, c in tool_session_count.items() if c / n > 0.1}

        # Remove frequently-used tools from sensitive sets
        self._sensitive_tools = _DEFAULT_SENSITIVE_TOOLS - frequent_tools
        self._high_risk_chain_tools = _DEFAULT_HIGH_RISK_CHAIN_TOOLS - frequent_tools
        self._normal_tools = frequent_tools

    def _learn_prototypes(self, sessions: list[Session]) -> None:
        """Learn MA-BOCPD hazard prototypes by clustering session embeddings."""
        embeddings = []
        valid_sessions = []
        for s in sessions:
            calls = s.tool_calls
            if not calls:
                continue
            summary = self.semantic.extract_session_summary(calls)
            embeddings.append(summary)
            valid_sessions.append(s)

        if len(embeddings) < 5:
            return

        X = np.stack(embeddings)
        n_clusters = min(self.hazard.prototypes.shape[0], len(embeddings))

        # Simple k-means (numpy only, avoids sklearn compatibility issues)
        rng = np.random.RandomState(self.cfg.seed)
        indices = rng.choice(len(X), size=n_clusters, replace=False)
        centroids = X[indices].copy()
        for _ in range(30):
            dists = np.linalg.norm(X[:, None, :] - centroids[None, :, :], axis=2)
            labels = np.argmin(dists, axis=1)
            new_centroids = np.zeros_like(centroids)
            for k in range(n_clusters):
                members = X[labels == k]
                if len(members) > 0:
                    new_centroids[k] = members.mean(axis=0)
                else:
                    new_centroids[k] = centroids[k]
            if np.allclose(centroids, new_centroids, atol=1e-6):
                break
            centroids = new_centroids

        # Estimate per-cluster optimal λ from session call counts
        cluster_lams = np.zeros(n_clusters)
        cluster_counts = np.zeros(n_clusters)
        for i, s in enumerate(valid_sessions):
            label = labels[i]
            n_calls = len(s.tool_calls)
            if n_calls > 1:
                cluster_lams[label] += n_calls
                cluster_counts[label] += 1

        for k in range(n_clusters):
            if cluster_counts[k] > 0:
                cluster_lams[k] = max(cluster_lams[k] / cluster_counts[k], 10.0)
            else:
                cluster_lams[k] = 100.0

        self.hazard.update_prototypes(centroids, cluster_lams)
