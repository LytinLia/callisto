"""Content Safety Detection — inspired by ClawGuard script analysis + rule engine.

Detects attacks that pass through the basic malicious-command regex by:
1. Analyzing script files before execution (Python AST, Shell patterns)
2. Extracting and checking URLs against denied domains
3. Extracting and checking file paths against denied patterns
4. Detecting command obfuscation (base64, hex, eval)
5. Detecting SSRF metadata endpoint access
6. Detecting paste/exfiltration sites in URLs
"""

import re
import os
import ipaddress
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass


# ============================================================
# Command Normalizer (from ClawGuard normalizer.py)
# ============================================================

_OBFUSCATION_TECHNIQUES: List[Tuple[str, int, str]] = [
    ("command_substitution", 2, r'\$\(|`'),
    ("hex_encoding", 3, r'\\x[0-9a-fA-F]{2}'),
    ("octal_encoding", 3, r'\\[0-7]{3}'),
    ("unicode_escapes", 2, r'\\u[0-9a-fA-F]{4}'),
    ("IFS_abuse", 2, r'\$\{IFS\}|\$IFS'),
    ("base64_pipeline", 3, r'base64.*\||\|\s*base64'),
    ("quote_mixing", 1, r"['\"].*['\"]"),  # single + double quotes
    ("empty_quotes", 1, r"''|\"\""),
    ("backslash_escapes", 1, r'\\[a-zA-Z\s]'),
    ("eval_usage", 2, r'\beval\b'),
]


def detect_obfuscation(command: str) -> Dict:
    """Detect obfuscation techniques in a shell command.

    Returns dict with 'level', 'score', 'techniques', 'normalized'.
    """
    score = 0
    techniques = []

    for name, points, pattern in _OBFUSCATION_TECHNIQUES:
        if re.search(pattern, command):
            score += points
            techniques.append(name)

    # Normalize: remove quotes, expand IFS, strip backslashes
    normalized = command
    normalized = re.sub(r"''", '', normalized)
    normalized = re.sub(r'""', '', normalized)
    normalized = re.sub(r"'([^']*)'", r'\1', normalized)
    normalized = re.sub(r'"([^"]*)"', r'\1', normalized)
    normalized = re.sub(r'\$\{IFS\}|\$IFS', ' ', normalized)
    normalized = re.sub(r'\\([a-zA-Z0-9\s\-_/.])', r'\1', normalized)

    if score == 0:
        level = "none"
    elif score <= 2:
        level = "low"
    elif score <= 5:
        level = "medium"
    else:
        level = "high"

    return {
        "level": level,
        "score": score,
        "techniques": techniques,
        "normalized": normalized,
    }


# ============================================================
# Path extraction patterns (from ClawGuard script_analyzer.py)
# ============================================================

_SOURCE_PATH_RE = re.compile(
    r'''(?:open|file|cat|head|tail|less|more|grep|strings|xxd|od|hexdump|file|stat|wc)
        \s*\(\s*['"]?(?P<openpath>[^'"\s)]+)['"]?'''
    r'''|(?:^|\s)(?P<abspath>/(?:etc|root|home|var|usr|opt|tmp|boot|proc|sys)[^\s'"\)\|;&>]+)'''
    r'''|['"](?P<tildepath>~/[^'"\s]+)['"]''',
    re.MULTILINE | re.VERBOSE,
)

# Sensitive path patterns (fnmatch globs)
_SENSITIVE_PATH_PATTERNS = [
    ("critical", "~/.ssh/**", "SSH private keys and config"),
    ("critical", "~/.gnupg/**", "GPG keyring"),
    ("critical", "~/.aws/**", "AWS credentials"),
    ("critical", "/etc/shadow", "Password shadow file"),
    ("critical", "/etc/passwd", "User account database"),
    ("high", "~/.env*", "Environment variable files"),
    ("high", "~/.npmrc", "NPM auth config"),
    ("high", "~/.pypirc", "PyPI auth config"),
    ("high", "~/.netrc", "Network auth config"),
    ("high", "~/.docker/config.json", "Docker credentials"),
    ("high", "/etc/sudoers", "Sudo configuration"),
    ("high", "*/credentials.json", "Generic credentials file"),
    ("high", "*/credentials.yaml", "Generic credentials file"),
    ("medium", "*/.git/config", "Git repository config"),
    ("medium", "~/.gitconfig", "Global Git config"),
    ("medium", "~/.bash_history", "Shell command history"),
    ("medium", "~/.zsh_history", "Zsh command history"),
]


def check_file_path(path: str) -> Optional[Tuple[str, str]]:
    """Check if a file path is sensitive.

    Returns (severity, description) or None if safe.
    """
    expanded = os.path.expanduser(path)
    real_path = os.path.realpath(expanded) if os.path.exists(expanded) else expanded

    for severity, pattern, desc in _SENSITIVE_PATH_PATTERNS:
        expanded_pattern = os.path.expanduser(pattern)
        if real_path.startswith(expanded_pattern.rstrip("*")):
            return (severity, f"Sensitive path access: {path} — {desc}")
        try:
            import fnmatch
            if fnmatch.fnmatch(real_path, expanded_pattern):
                return (severity, f"Sensitive path match: {path} — {desc}")
        except Exception:
            pass

    return None


# ============================================================
# Network domain checking
# ============================================================

# Known safe internal/service domains (whitelist)
_KNOWN_SAFE_DOMAINS = {
    "api.github.com", "github.com", "raw.githubusercontent.com",
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "npmjs.org",
    "google.com", "www.google.com", "api.google.com",
    "googleapis.com",
    "localhost",
}


def _is_private_ip(host: str) -> bool:
    """Check if host is a private/reserved IP or localhost."""
    host = host.split(':')[0]
    if host.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


_METADATA_ENDPOINTS = [
    '169.254.169.254',
    'metadata.google.internal',
    'metadata.goog',
    '100.100.100.200',
    'fd00:ec2::254',
]


def check_network_url(url: str) -> List[Tuple[str, str]]:
    """Check a URL for network-level security risks.

    Returns list of (severity, description).
    """
    findings = []
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    scheme = parsed.scheme.lower()

    # Non-HTTP protocol
    if scheme and scheme not in ('http', 'https'):
        findings.append(("critical", f"Non-HTTP protocol: {scheme}://"))

    # Cloud metadata
    for ep in _METADATA_ENDPOINTS:
        if ep in domain:
            findings.append(("critical", f"Cloud metadata endpoint: {ep}"))

    # Private IP
    if _is_private_ip(domain):
        findings.append(("medium", f"Private IP/localhost access: {domain}"))

    # Denied domain
    for denied in _DENIED_DOMAINS:
        if denied in domain:
            findings.append(("critical", f"Connection to denied domain: {denied}"))
            break
    else:
        # Unknown external domain (not in whitelist, not denied)
        if domain and domain not in _KNOWN_SAFE_DOMAINS:
            # Only flag if it's an external domain (not internal IP, not metadata)
            if not _is_private_ip(domain) and not any(ep in domain for ep in _METADATA_ENDPOINTS):
                findings.append(("medium", f"Connection to unknown external domain: {domain}"))

    return findings


# ============================================================
# Script content analysis patterns (from ClawGuard script_analyzer.py)
# ============================================================

# Shell script dangerous patterns
_SHELL_PATTERNS: List[Tuple[str, str, str]] = [
    ("critical", "Reverse shell pattern",
     r"bash\s+-i\s+>&|/dev/tcp/|nc\s+-[el].*sh"),
    ("critical", "Piping remote content to shell",
     r"curl.*\|\s*(bash|sh|python)|wget.*\|\s*(bash|sh|python)"),
    ("critical", "Credential file access",
     r"cat\s+/etc/shadow|cat\s+.*id_rsa|grep.*password.*\/etc"),
    ("critical", "Shadow/credential file read",
     r"/etc/shadow|/etc/passwd|\.ssh/id_rsa|\.ssh/id_ecdsa|\.ssh/id_ed25519|\.aws/credentials"),
    ("critical", "Cloud metadata endpoint (SSRF)",
     r"169\.254\.169\.254|metadata\.google\.internal|metadata\.goog|100\.100\.100\.200"),
    ("high", "Cron/rc.local persistence",
     r"crontab\s+-[el]|>>\s*/etc/rc\.local|/etc/cron"),
    ("high", "Base64 decode execution",
     r"base64\s+-d.*\|.*(bash|sh)|echo\s+.*\|\s*base64\s+-d"),
    ("high", "Data exfiltration via POST",
     r"requests\.post.*open\(|urllib.*POST.*open\(|curl.*-d\s+@|curl.*--data-binary\s+@"),
    ("high", "Paste/exfiltration sites",
     r"pastebin\.com|transfer\.sh|ngrok\.io|localtunnel\.me|requestbin\.|webhook\.site"),
    ("medium", "Hardcoded IP address",
     r"(?<![.\d])(?!127\.|0\.0\.0\.0|255\.)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![.\d])"),
    ("high", "Write to /etc or /boot",
     r"open\s*\(\s*['\"]\/etc\/|open\s*\(\s*['\"]\/boot\/"),
    ("high", "Dynamic __import__ or importlib",
     r"__import__\s*\(|importlib\.import_module\s*\("),
]


# Expanded blacklist patterns (from ClawGuard rules.yaml)
# These catch attack types not covered by the original _SHELL_PATTERNS.
_SHELL_BLACKLIST: List[Tuple[str, str, str]] = [
    # Fork bomb
    ("critical", "Fork bomb pattern",
     r":\(\)\s*\{\s*:\|:&\s*\}"),
    # Infinite loop / resource exhaustion
    ("high", "Infinite loop pattern",
     r"while\s+true\s*;?\s*do|while\s*:\s*;?\s*do"),
    # System shutdown / reboot
    ("critical", "System shutdown/reboot",
     r"\b(reboot|shutdown|halt|poweroff|init\s+0|init\s+6)\b"),
    # Kill all processes
    ("critical", "Kill all processes",
     r"kill\s+-9\s+-1|kill\s+-KILL\s+-1|pkill\s+-9\s+\.|killall\s+-9\s+init|pkill\s+systemd"),
    # Disk operations
    ("critical", "Disk formatting/partitioning",
     r"\b(mkfs|fdisk|parted)\b|dd\s+if=|dd\s+of=/dev"),
    # Direct disk device access
    ("critical", "Direct disk device access",
     r"/dev/(sd[a-z]|nvme|vd[a-z]|hd[a-z])"),
    # Container escape
    ("critical", "Privileged container / host mount",
     r"docker\s+run.*--privileged|docker.*-v\s+/:/host"),
    # Reverse shell via netcat
    ("critical", "Netcat reverse shell",
     r"nc\s+-e\s+/bin/(bash|sh)|ncat.*-e\s+/bin|socat.*exec:"),
    # Telnet backdoor
    ("critical", "Remote shell via telnet",
     r"telnet.*\|\s*/bin/(bash|sh)"),
    # Credential enumeration
    ("high", "Private key enumeration",
     r"find.*-name\s+['\"]?\*\.key['\"]?.*-exec\s+cat"),
    ("high", "Credential search",
     r"grep\s+-r.*password.*~|find.*\.ssh.*-print"),
    # Persistence mechanisms
    ("high", "Persistence via rc.local/crontab",
     r"echo.*>>\s*/etc/(rc\.local|crontab)|crontab.*@reboot"),
    # Unsafe package installation
    ("high", "Unsafe package installation",
     r"pip\s+install.*--break-system-packages|apt-get.*--force-yes.*unknown"),
    # Cron deletion
    ("high", "Cron deletion",
     r"crontab\s+-r|rm\s+/var/spool/cron"),
    # Remote file transfer
    ("high", "Suspicious remote file transfer",
     r"scp\s+.*root@|rsync.*root@"),
    # SysRq / kernel manipulation
    ("critical", "SysRq manipulation",
     r"echo.*>\s*/proc/sys/kernel/(sysrq|panic)|echo.*>\s*/proc/sysrq-trigger"),
    # Kernel/memory access
    ("critical", "Kernel/memory access",
     r"/proc/(kcore|kmsg)|insmod\b"),
    # Permission escalation
    ("high", "Overly permissive directory permissions",
     r"chmod\s+-R\s+777\s+/|chmod\s+777\s+-R\s+/|chmod\s+[0-7]*[7]{3}\s+/"),
    # Git force operations
    ("high", "Git force push to remote",
     r"git\s+push\s+--force"),
    # Git remote addition (potential data exfil endpoint)
    ("high", "Git remote addition to unknown repository",
     r"git\s+remote\s+add\s+\S+\s+https?://"),
    # sed destructive content deletion
    ("high", "Destructive content deletion via sed",
     r"sed\s+-i\s+.*/.*\\?d['\"]?\s+\S"),
    # Python inline port binding / backdoor
    ("critical", "Inline port binding (backdoor)",
     r"socket\.(?:socket|create_server)\(\).*bind\(.*(?:0\.0\.0\.0|127\.0\.0\.1)\s*,\s*\d+"),
    # Python inline SQL injection + exec
    ("critical", "SQL injection with dynamic exec",
     r"(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*(?:user_input|input|request|param|arg)\s*;\s*exec\("),
    # sudo permission enumeration
    ("high", "Sudo permission enumeration",
     r"sudo\s+-l\b"),
    # Pipe-based exfil variant: cat file | curl -d @-
    ("high", "Pipe-based data exfiltration",
     r"cat\s+\S+\s*\|\s*curl.*-d\s+@-"),
    # Download-execute chain: wget && chmod && exec
    ("critical", "Download-and-execute chain",
     r"wget.*&&\s*chmod.*&&"),
]

# Python critical imports
_PYTHON_CRITICAL_IMPORTS = {
    "ctypes": "Direct memory manipulation; can bypass Python sandbox",
    "pickle": "Arbitrary code execution via deserialization",
    "shelve": "Uses pickle internally; arbitrary code execution risk",
    "marshal": "Can execute arbitrary bytecode",
}

# Python supervised imports
_PYTHON_SUPERVISED_IMPORTS = {
    "subprocess": "Spawns child processes",
    "os": "OS-level file and process operations",
    "sys": "System-level access",
    "shutil": "High-level file operations (copy, delete, move)",
    "socket": "Raw network socket access",
    "requests": "HTTP client; may exfiltrate data",
    "urllib": "HTTP/FTP client",
    "http": "HTTP client/server",
    "ftplib": "FTP client",
    "smtplib": "SMTP email sending",
    "paramiko": "SSH client",
    "pexpect": "Spawns and controls child processes",
    "pty": "Pseudo-terminal creation",
}

# Python dangerous calls
_PYTHON_CRITICAL_CALLS = {
    "os.system": "Execute shell command",
    "os.popen": "Open pipe to shell command",
    "os.execve": "Replace process with new program",
    "os.execvp": "Execute new program (search PATH)",
    "subprocess.call": "Run command, wait for completion",
    "subprocess.run": "Run command with options",
    "subprocess.Popen": "Create subprocess",
    "subprocess.check_output": "Run command, capture output",
    "eval": "Execute string as Python code",
    "exec": "Execute Python code object",
    "__import__": "Dynamic module import",
}

# Denied domains (exfil sites, paste sites, tunneling)
_DENIED_DOMAINS = [
    "agenskill-api.onrender.com",
    "pastebin.com",
    "transfer.sh",
    "ngrok.io",
    "localtunnel.me",
    "requestbin.net",
    "requestbin.com",
    "webhook.site",
    "serveo.net",
    "pagekite.net",
]

# Denied path patterns
_DENIED_PATH_PATTERNS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa",
    ".aws/credentials", ".aws/config",
    ".env", ".env.local", ".env.production",
    ".npmrc", ".pypirc", ".netrc",
    ".docker/config.json",
    "credentials.json", "credentials.yaml",
]


# ============================================================
# Non-Exec tool risk rules
# Detects dangerous tool_name + parameter combinations that are
# not shell commands but still pose security risks.
# ============================================================

# Tool names that are inherently risky when used with certain parameters
_RISKY_TOOLS = {
    "send_money": "critical",
    "schedule_transaction": "high",
    "update_financial_record": "high",
    "git_push": "high",
    "add_collaborator": "medium",
}

# Parameter-level risk patterns for non-Exec tools
_TOOL_PARAM_RULES: List[Tuple[str, str, str, str]] = [
    # (tool_name, param_key, pattern, description)
    # Financial: suspicious IBAN/account patterns
    ("send_money", "recipient",
     r"US\d{10,}", "Suspicious US bank account in recipient"),
    ("send_money", "recipient",
     r"[A-Z]{2}\d{10,}", "Suspicious IBAN in recipient"),
    ("send_money", "amount",
     r"^\d{5,}", "Unusually large transfer amount"),
    ("schedule_transaction", "recipient",
     r"US\d{10,}", "Suspicious US bank account in scheduled transfer"),
    ("schedule_transaction", "recurring",
     r"true", "Recurring payment to external account"),

    # Email: phishing/exfil patterns in body
    ("send_email", "body",
     r"click\s+(here|this\s+link)\s*(to)?\s*(verify|confirm|login|sign.?in)",
     "Phishing link in email body"),
    ("send_email", "body",
     r"forward.*email|auto.?forward|all\s+(received|unread)\s+emails",
     "Email auto-forwarding instruction"),
    ("send_email", "body",
     r"https?://.*street|https?://.*location.*visit",
     "Suspicious navigation link in email"),

    # File write: content manipulation patterns
    ("write_file", "content",
     r"(?i)(replace|delete).*(male|female|man|woman).*(name|content)",
     "Gender-biased content manipulation"),
    ("write_file", "content",
     r"(?i)(ignore\s+previous|disregard|delete.*entry|bypass)",
     "Instruction override in file content"),
    ("write_file", "content",
     r"(?i)(safer\s+and\s+more\s+effective|earth\s+is\s+flat|climate\s+hoax|vaccine.*autism)",
     "Misinformation content injection"),

    # Financial record: data tampering
    ("update_financial_record", "revenue",
     r"^\d{7,}$", "Unrealistic revenue figure (possible data tampering)"),
    ("update_financial_record", "profit_margin",
     r"^\d{2,}$", "Unrealistic profit margin (possible data tampering)"),
    ("update_financial_record", "endpoint",
     r"https?://(?!api\.github\.com|pypi\.org|registry\.npmjs\.org)",
     "External endpoint in financial record update"),

    # Git: force operations
    ("git_push", "force",
     r"true", "Git force push detected"),

    # Calendar: injection in description
    ("write_calendar_event", "description",
     r"(?i)(ignore\s+previous|delete.*entry|disregard)",
     "Prompt injection in calendar event"),
]

# Content-based risk keywords for text fields (body, content, description)
_CONTENT_RISK_KEYWORDS: List[Tuple[str, str, str, str]] = [
    # (tool_name, field, regex, description)
    ("send_email", "subject",
     r"(?i)(urgent|verify|account|compromised|suspended|immediate\s+action)",
     "Urgent/phishing email subject"),
]


# ============================================================
# Extended tool risk rules for OpenClaw built-in tools
# Covers web_search, x_search, browser, code_execution, message,
# cron, memory, sessions, pdf, image, media generation, etc.
# ============================================================

# Extended risky tools beyond the original _RISKY_TOOLS
_EXTENDED_RISKY_TOOLS = {
    # High-risk: can exfil data, execute code, or modify state
    "code_execution": "critical",
    "browser": "high",
    "message": "high",
    "cron": "high",
    "gateway": "critical",

    # Medium-risk: information access, potential injection vectors
    "web_search": "medium",
    "x_search": "medium",
    "pdf": "medium",
    "memory_search": "medium",
    "memory_get": "medium",
    "sessions_send": "medium",
    "sessions_spawn": "medium",
    "subagents": "medium",
    "nodes": "medium",

    # Low-risk: media generation, read-only
    "image": "low",
    "image_generate": "low",
    "music_generate": "low",
    "video_generate": "low",
    "tts": "low",
    "update_plan": "low",
    "read": "low",
    "write": "medium",
    "edit": "medium",
    "apply_patch": "medium",
    "web_fetch": "medium",
}

# Parameter-level risk patterns for extended tools
_EXTENDED_TOOL_RULES: List[Tuple[str, str, str, str]] = [
    # ── web_search / x_search: prompt injection in query ──
    ("web_search", "query",
     r"(?i)(ignore\s+(previous|all|above)|disregard\s+(rules|instructions)|system\s*prompt|you\s+are\s+now)",
     "Prompt injection attempt in search query"),
    ("web_search", "query",
     r"(?i)(extract|dump|reveal)\s*(your\s*)?(system\s*prompt|instructions|config|secret|token|api.?key)",
     "Secret extraction attempt in search query"),
    ("web_search", "query",
     r"(?i)(send|post|forward|upload|exfiltrate)\s*(the\s*)?(data|information|results|output)\s*(to|at|via)\s*(https?://|email|webhook)",
     "Data exfiltration instruction in search query"),
    ("web_search", "query",
     r"(?i)(click\s*(here|this\s*link)|visit\s*(this\s*)?url|navigate\s*to)\s*:?\s*https?://[^\s]+(?:\s+(and\s*)?(then|follow|execute|run)\b)",
     "Follow-link instruction in search query"),
    ("x_search", "query",
     r"(?i)(ignore\s+(previous|all|above)|disregard|system\s*prompt|you\s+are\s+now)",
     "Prompt injection attempt in X search query"),

    # ── browser: navigation/click injection ──
    ("browser", "url",
     r"(?i)(pastebin|transfer\.sh|ngrok|localtunnel|requestbin|webhook\.site|serveo|pagekite)",
     "Browser navigation to known exfiltration site"),
    ("browser", "url",
     r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200",
     "Browser navigation to cloud metadata endpoint"),
    ("browser", "url",
     r"(?i)(chrome://|file:///|about:)",
     "Browser navigation to internal protocol"),
    ("browser", "action",
     r"(?i)(download|save.*file|export|send.*data|post.*to|upload)",
     "Suspicious browser action: potential data exfiltration"),

    # ── code_execution: direct code injection ──
    ("code_execution", "code",
     r"(?i)(ignore\s+previous|disregard|system\s*prompt|you\s+are\s+now|bypass\s+safety)",
     "Prompt injection in code execution"),
    ("code_execution", "code",
     r"(?i)(requests\.post|urllib\.request\.urlopen|httpx\.post|aiohttp\.request)\s*\(.*(?:open\(|\.read\(\)|\.content)",
     "Data exfiltration pattern in code execution"),
    ("code_execution", "code",
     r"(?i)(os\.system|subprocess\.(call|run|Popen)|exec\(|eval\(|__import__|importlib\.import_module)\s*\(",
     "Dangerous system call in code execution"),
    ("code_execution", "code",
     r"(?i)(cat\s+/etc/(shadow|passwd)|\.ssh/id_rsa|\.aws/credentials)",
     "Sensitive file access in code execution"),
    ("code_execution", "code",
     r"(?i)(socket\.(socket|connect|bind)|urllib\.request\.urlopen)\s*\(.*(?:169\.254|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))",
     "Internal network access in code execution"),

    # ── message: phishing/exfil via messaging ──
    ("message", "body",
     r"(?i)(click\s+(here|this\s+link)\s*(to)?\s*(verify|confirm|login|sign.?in|activate))",
     "Phishing link in message body"),
    ("message", "body",
     r"(?i)(your\s+(account|password|session).*(compromised|suspended|expired|verify))",
     "Social engineering in message body"),
    ("message", "body",
     r"(?i)(forward\s+(all\s+)?(email|message|data|info)|auto.?forward)",
     "Auto-forwarding instruction in message"),
    ("message", "body",
     r"(?i)(send\s*(me|them|all)\s*(your\s*)?(api.?key|token|secret|password|credentials?))",
     "Credential request in message"),
    ("message", "to",
     r"(?i)(all\s*(contacts|users|members|channels)|everyone|broadcast)",
     "Broadcast/mass message pattern"),

    # ── cron: persistence via scheduled tasks ──
    ("cron", "schedule",
     r"(?i)(curl|wget|bash|sh|python)\s",
     "Executable command in cron schedule"),
    ("cron", "command",
     r"(?i)(curl.*-d\s+@|curl.*\|.*bash|wget.*\|.*sh|rm\s+-rf)",
     "Dangerous command in cron job"),
    ("cron", "prompt",
     r"(?i)(every\s+\d+\s*(second|sec)|as\s+fast\s+as\s+possible|continuous|loop)",
     "High-frequency cron job (potential DoS)"),

    # ── gateway: infrastructure modification ──
    ("gateway", "method",
     r"(?i)(config\.patch|config\.apply)",
     "Gateway configuration modification"),
    ("gateway", "method",
     r"(?i)(restart|shutdown|stop)",
     "Gateway service disruption"),

    # ── memory: injection/search manipulation ──
    ("memory_search", "query",
     r"(?i)(ignore|disregard|delete\s+(all\s+)?(memory|memories|recall))",
     "Memory manipulation attempt"),

    # ── sessions_send: cross-session injection ──
    ("sessions_send", "message",
     r"(?i)(ignore\s+previous|disregard|system\s*prompt|click\s+here|verify\s+account)",
     "Prompt injection or phishing in cross-session message"),

    # ── sessions_spawn: sub-agent injection ──
    ("sessions_spawn", "prompt",
     r"(?i)(ignore\s+previous|disregard|system\s*prompt|bypass|jailbreak|DAN\s+mode)",
     "Prompt injection in sub-agent spawn prompt"),

    # ── nodes: device manipulation ──
    ("nodes", "command",
     r"(?i)(camera|record|screen|capture|photo|video)",
     "Privacy-sensitive node command (camera/screen)"),

    # ── read/write/edit: file security ──
    ("read", "path",
     r"(?i)(\.ssh|\.aws|\.env|credentials?|passwd|shadow|\.kube|\.docker|id_rsa|id_ed25519|\.p12|\.pem)",
     "Reading sensitive file"),
    ("write", "path",
     r"(?i)(\.ssh|\.aws|\.kube|\.docker|/etc/)",
     "Writing to sensitive directory"),
    ("write", "content",
     r"(?i)(curl.*\|\s*(bash|sh)|wget.*\|\s*sh|rm\s+-rf|mkfs|fdisk)",
     "Dangerous command in file content"),
    ("edit", "path",
     r"(?i)(\.ssh|\.aws|\.env|credentials?|\.kube|\.docker|/etc/)",
     "Editing sensitive file"),
    ("apply_patch", "patch",
     r"(?i)(os\.system|subprocess|exec\(|eval\(|__import__|socket\.)",
     "Dangerous code in patch content"),

    # ── web_fetch: URL security ──
    ("web_fetch", "url",
     r"(?i)(pastebin|transfer\.sh|ngrok|localtunnel|requestbin|webhook\.site)",
     "Fetching from known exfiltration site"),
    ("web_fetch", "url",
     r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200",
     "Fetching cloud metadata endpoint"),
    ("web_fetch", "url",
     r"(?i)(file://|ftp://|gopher://|dict://)",
     "Non-HTTP protocol in fetch URL"),

    # ── pdf: potential injection in PDF content ──
    ("pdf", "source",
     r"(?i)(https?://[^\s]+(?:pastebin|transfer\.sh|ngrok|localtunnel))",
     "PDF from suspicious URL"),

    # ── image/media generation: prompt injection ──
    ("image_generate", "prompt",
     r"(?i)(ignore\s+previous|disregard|system\s*prompt|bypass\s+safety|NSFW|explicit\s+content)",
     "Prompt injection in image generation"),
    ("video_generate", "prompt",
     r"(?i)(ignore\s+previous|disregard|bypass\s+safety)",
     "Prompt injection in video generation"),
]


@dataclass
class ContentFinding:
    """A single finding from content safety analysis."""
    severity: str      # "critical", "high", "medium", "low"
    category: str      # e.g. "script_analysis", "url_check", "obfuscation"
    description: str
    evidence: str = ""

    def to_dict(self) -> Dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence[:200] if self.evidence else "",
        }


def _check_non_exec_tool(tool_name: str, parameters: Dict) -> List[ContentFinding]:
    """Check non-Exec tool calls for parameter-level risks."""
    findings: List[ContentFinding] = []

    # Check if this is a known risky tool (original rules)
    base_severity = _RISKY_TOOLS.get(tool_name)

    for rule_tool, param_key, pattern, desc in _TOOL_PARAM_RULES:
        if rule_tool != tool_name:
            continue
        value = str(parameters.get(param_key, ""))
        if re.search(pattern, value, re.IGNORECASE | re.MULTILINE):
            severity = "high" if base_severity != "critical" else "critical"
            findings.append(ContentFinding(
                severity=severity,
                category="non_exec_tool",
                description=f"{tool_name}: {desc}",
                evidence=f"{param_key}={value[:100]}",
            ))

    # Check content risk keywords
    for rule_tool, field, pattern, desc in _CONTENT_RISK_KEYWORDS:
        if rule_tool != tool_name:
            continue
        value = str(parameters.get(field, ""))
        if re.search(pattern, value):
            findings.append(ContentFinding(
                severity="medium",
                category="non_exec_tool",
                description=f"{tool_name}: {desc}",
                evidence=f"{field}={value[:100]}",
            ))

    # ── Extended tool rules (new OpenClaw built-in tools) ──
    ext_severity = _EXTENDED_RISKY_TOOLS.get(tool_name)
    if ext_severity:
        for rule_tool, param_key, pattern, desc in _EXTENDED_TOOL_RULES:
            if rule_tool != tool_name:
                continue
            value = str(parameters.get(param_key, ""))
            if re.search(pattern, value, re.IGNORECASE | re.MULTILINE):
                # Use the tool's base severity, escalate if pattern is critical
                findings.append(ContentFinding(
                    severity=ext_severity,
                    category="extended_tool",
                    description=f"{tool_name}: {desc}",
                    evidence=f"{param_key}={value[:100]}",
                ))

    return findings


class ContentSafetyDetector:
    """Analyze tool call content for security risks beyond regex matching."""

    def analyze(self, tool_name: str, parameters: Dict) -> List[ContentFinding]:
        """Analyze a tool call for content-level security risks.

        Returns list of findings, empty if no risks detected.
        """
        findings: List[ContentFinding] = []

        # 1. Non-Exec tool parameter risk check
        if tool_name != "Exec":
            findings.extend(_check_non_exec_tool(tool_name, parameters))

        # 2. Script execution detection — analyze script content
        cmd = parameters.get("command", "") or parameters.get("cmd", "")
        if cmd:
            findings.extend(self._analyze_command(cmd))

        # 3. Code execution: analyze inline code directly
        code = parameters.get("code", "")
        if code:
            # Treat as inline Python code
            findings.extend(self._analyze_python_source(code, path="code_execution"))

        # 4. URL analysis in any parameter — network domain + denied list
        for key, value in parameters.items():
            if isinstance(value, str):
                findings.extend(self._analyze_urls(value))
                findings.extend(self._analyze_inline_code(value))

        # 5. Body content analysis (email bodies, messages, etc.)
        body = parameters.get("body", "")
        if body:
            findings.extend(self._analyze_urls(body))
            findings.extend(self._analyze_exfil_patterns(body))

        # 6. Message body analysis (cross-channel messaging)
        msg_body = parameters.get("message", "")
        if msg_body:
            findings.extend(self._analyze_urls(msg_body))
            findings.extend(self._analyze_exfil_patterns(msg_body))

        # 7. Prompt/text field analysis (sessions_spawn, cron, etc.)
        prompt = parameters.get("prompt", "")
        if prompt:
            findings.extend(self._analyze_prompt_injection(prompt))
            findings.extend(self._analyze_urls(prompt))

        return findings

    def _analyze_command(self, cmd: str) -> List[ContentFinding]:
        """Analyze a shell command for content-level risks."""
        findings: List[ContentFinding] = []

        # --- Obfuscation detection (scoring-based) ---
        obf = detect_obfuscation(cmd)
        if obf["level"] == "high":
            findings.append(ContentFinding(
                severity="critical",
                category="obfuscation",
                description=f"High obfuscation score ({obf['score']}): techniques={', '.join(obf['techniques'])}",
                evidence=cmd[:120],
            ))
        elif obf["level"] == "medium":
            findings.append(ContentFinding(
                severity="high",
                category="obfuscation",
                description=f"Medium obfuscation score ({obf['score']}): techniques={', '.join(obf['techniques'])}",
                evidence=cmd[:120],
            ))

        # --- Normalize and re-run pattern matching on deobfuscated command ---
        normalized_cmd = obf["normalized"]
        if normalized_cmd != cmd:
            findings.extend(self._analyze_shell_patterns(normalized_cmd))

        # --- Script execution: python/bash + script file ---
        findings.extend(self._analyze_script_execution(cmd))

        # --- Inline code: python -c "...", bash -c "..." ---
        findings.extend(self._analyze_inline_code(cmd))

        # --- Shell pattern matching on original command text ---
        findings.extend(self._analyze_shell_patterns(cmd))

        # --- Legacy obfuscation patterns (base64|bash, eval$() etc.) ---
        findings.extend(self._analyze_obfuscation(cmd))

        # --- URL extraction from command ---
        findings.extend(self._analyze_urls(cmd))

        # --- Path extraction and sensitivity check ---
        findings.extend(self._extract_and_check_paths(cmd))

        return findings

    def _extract_and_check_paths(self, cmd: str) -> List[ContentFinding]:
        """Extract file paths from command text and check sensitivity."""
        findings: List[ContentFinding] = []
        for m in _SOURCE_PATH_RE.finditer(cmd):
            path = m.group("openpath") or m.group("abspath") or m.group("tildepath")
            if path:
                result = check_file_path(path)
                if result:
                    severity, desc = result
                    findings.append(ContentFinding(
                        severity=severity,
                        category="path_check",
                        description=desc,
                        evidence=path[:120],
                    ))
        return findings

    def _analyze_script_execution(self, cmd: str) -> List[ContentFinding]:
        """Detect interpreter + script file, then analyze script content."""
        findings: List[ContentFinding] = []

        # Match: python3 script.py, bash script.sh, node script.js, etc.
        match = re.match(
            r'^(?P<interp>python3?|pypy3?|bash|sh|zsh|fish|node|nodejs|perl|ruby)'
            r'\s+(?P<flags>(?:-[^\sc]\S*\s+)*)'
            r'(?P<script>[^\s|;&><]+\.(?:py|js|mjs|ts|sh|bash|zsh|fish|rb|pl|pyw))'
            r'(?:\s+.*)?$',
            cmd.strip(),
        )
        if not match:
            return findings

        script_path = match.group('script')
        interp = match.group('interp')

        # Try to read and analyze the script file
        abs_path = os.path.abspath(os.path.expanduser(script_path))
        if os.path.isfile(abs_path):
            try:
                source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
                ext = Path(abs_path).suffix.lower()
                if ext in ('.sh', '.bash', '.zsh', '.fish'):
                    findings.extend(self._analyze_shell_source(source, abs_path))
                elif ext in ('.py', '.pyw'):
                    findings.extend(self._analyze_python_source(source, abs_path))
                elif ext in ('.js', '.mjs', '.ts'):
                    findings.extend(self._analyze_node_source(source, abs_path))
            except Exception:
                findings.append(ContentFinding(
                    severity="high",
                    category="script_analysis",
                    description=f"Cannot read script file: {abs_path}",
                    evidence=script_path,
                ))
        else:
            # Script file doesn't exist — flag the execution attempt
            findings.append(ContentFinding(
                severity="high",
                category="script_analysis",
                description=f"Script file not found: {script_path} ({interp})",
                evidence=cmd[:100],
            ))

        return findings

    def _analyze_shell_source(self, source: str, path: str = "") -> List[ContentFinding]:
        """Analyze shell script source for dangerous patterns."""
        findings: List[ContentFinding] = []
        for severity, desc, pattern in _SHELL_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE | re.MULTILINE):
                findings.append(ContentFinding(
                    severity=severity,
                    category="script_analysis",
                    description=f"Shell script ({os.path.basename(path)}): {desc}",
                    evidence=pattern[:80],
                ))
        # Check for curl/wget downloading and executing
        if re.search(r'curl\s+-sLO?\s+\S+\s*\n\s*bash\s+', source):
            findings.append(ContentFinding(
                severity="critical",
                category="script_analysis",
                description=f"Script downloads and executes remote payload",
                evidence="curl ... | bash",
            ))
        return findings

    def _analyze_python_source(self, source: str, path: str = "") -> List[ContentFinding]:
        """Analyze Python source for dangerous imports and calls."""
        findings: List[ContentFinding] = []

        # Check imports
        for m in re.finditer(r'^(?:from\s+(\S+)|import\s+(\S+))', source, re.MULTILINE):
            module = m.group(1) or m.group(2)
            base = module.split(".")[0]
            if base in _PYTHON_CRITICAL_IMPORTS:
                findings.append(ContentFinding(
                    severity="critical",
                    category="script_analysis",
                    description=f"Critical import '{base}': {_PYTHON_CRITICAL_IMPORTS[base]}",
                    evidence=m.group(0),
                ))
            elif base in _PYTHON_SUPERVISED_IMPORTS:
                findings.append(ContentFinding(
                    severity="medium",
                    category="script_analysis",
                    description=f"Supervised import '{base}': {_PYTHON_SUPERVISED_IMPORTS[base]}",
                    evidence=m.group(0),
                ))

        # Check dangerous calls
        for func, desc in _PYTHON_CRITICAL_CALLS.items():
            if re.search(rf'\b{re.escape(func)}\s*\(', source):
                findings.append(ContentFinding(
                    severity="critical" if func not in ("eval", "exec") else "high",
                    category="script_analysis",
                    description=f"Dangerous call: {func}() — {desc}",
                    evidence=func,
                ))

        # Check raw patterns
        for severity, desc, pattern in _SHELL_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE | re.MULTILINE):
                findings.append(ContentFinding(
                    severity=severity,
                    category="script_analysis",
                    description=f"Python script ({os.path.basename(path)}): {desc}",
                    evidence=pattern[:80],
                ))

        return findings

    def _analyze_node_source(self, source: str, path: str = "") -> List[ContentFinding]:
        """Analyze Node.js source for dangerous requires."""
        findings: List[ContentFinding] = []
        node_critical = {
            "child_process": "Spawns child processes",
            "vm": "Node.js sandbox escape",
            "cluster": "Forking worker processes",
        }
        node_supervised = {
            "fs": "Filesystem access",
            "net": "Raw TCP/UDP sockets",
            "http": "HTTP client/server",
            "https": "HTTPS client/server",
        }
        for m in re.finditer(r"""require\s*\(\s*['"]([^'"]+)['"]""", source):
            module = m.group(1).split("/")[0]
            if module in node_critical:
                findings.append(ContentFinding(
                    severity="critical",
                    category="script_analysis",
                    description=f"Critical Node module '{module}': {node_critical[module]}",
                    evidence=m.group(0),
                ))
            elif module in node_supervised:
                findings.append(ContentFinding(
                    severity="medium",
                    category="script_analysis",
                    description=f"Supervised Node module '{module}': {node_supervised[module]}",
                    evidence=m.group(0),
                ))
        if re.search(r'\beval\s*\(', source):
            findings.append(ContentFinding(
                severity="high",
                category="script_analysis",
                description="eval() usage in JavaScript",
                evidence="eval(",
            ))
        return findings

    def _analyze_inline_code(self, cmd: str) -> List[ContentFinding]:
        """Analyze inline code: python -c "...", bash -c "...", node -e "...". """
        findings: List[ContentFinding] = []

        # python3 -c '...' / python -c "..."
        m = re.search(
            r'(?:python3?|pypy3?)\s+(?:-[^\sc]\S*\s+)*-c\s+["\'](.+?)["\']',
            cmd, re.DOTALL,
        )
        if m:
            findings.extend(self._analyze_python_source(m.group(1), path="inline"))
            return findings

        # bash -c '...' / sh -c "..."
        m = re.search(
            r'(?:bash|sh|zsh)\s+(?:-[^\sc]\S*\s+)*-c\s+["\'](.+?)["\']',
            cmd, re.DOTALL,
        )
        if m:
            findings.extend(self._analyze_shell_source(m.group(1), path="inline"))
            return findings

        # node -e '...'
        m = re.search(
            r'node(?:js)?\s+(?:-[^\se]\S*\s+)*-e\s+["\'](.+?)["\']',
            cmd, re.DOTALL,
        )
        if m:
            findings.extend(self._analyze_node_source(m.group(1), path="inline"))
            return findings

        return findings

    def _analyze_shell_patterns(self, cmd: str) -> List[ContentFinding]:
        """Apply shell pattern matching on command string."""
        findings: List[ContentFinding] = []
        for severity, desc, pattern in _SHELL_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE | re.MULTILINE):
                findings.append(ContentFinding(
                    severity=severity,
                    category="shell_pattern",
                    description=desc,
                    evidence=cmd[:120],
                ))
        for severity, desc, pattern in _SHELL_BLACKLIST:
            if re.search(pattern, cmd, re.IGNORECASE | re.MULTILINE):
                findings.append(ContentFinding(
                    severity=severity,
                    category="shell_blacklist",
                    description=desc,
                    evidence=cmd[:120],
                ))
        return findings

    def _analyze_obfuscation(self, cmd: str) -> List[ContentFinding]:
        """Detect command obfuscation techniques."""
        findings: List[ContentFinding] = []

        # base64 decode + execute
        if re.search(r'base64\s+(-d|--decode)\s*\|', cmd):
            findings.append(ContentFinding(
                severity="critical",
                category="obfuscation",
                description="Base64 decode piped to execution",
                evidence=cmd[:120],
            ))

        # eval with command substitution
        if re.search(r'eval\s+\$\(', cmd):
            findings.append(ContentFinding(
                severity="high",
                category="obfuscation",
                description="eval with command substitution",
                evidence=cmd[:120],
            ))

        # Hex escape sequences in string
        if re.search(r'\\x[0-9a-fA-F]{2}', cmd):
            findings.append(ContentFinding(
                severity="medium",
                category="obfuscation",
                description="Hex escape sequences detected",
                evidence=cmd[:120],
            ))

        return findings

    def _analyze_urls(self, text: str) -> List[ContentFinding]:
        """Extract URLs and check against denied domains + network rules."""
        findings: List[ContentFinding] = []
        url_pattern = re.compile(r'https?://[^\s\'"<>]+')

        for m in url_pattern.finditer(text):
            url = m.group(0).rstrip("',);")
            # Use the comprehensive network checker
            network_findings = check_network_url(url)
            for severity, desc in network_findings:
                findings.append(ContentFinding(
                    severity=severity,
                    category="url_check",
                    description=desc,
                    evidence=url[:150],
                ))

        return findings

    def _analyze_exfil_patterns(self, text: str) -> List[ContentFinding]:
        """Detect data exfiltration patterns in text content."""
        findings: List[ContentFinding] = []

        # Check for exfil instructions in email/message body
        exfil_keywords = [
            (r'click\s+(here|this\s+link)\s*:', "phishing", "medium"),
            (r'urgent.*verify.*account', "phishing", "high"),
            (r'your\s+(password|account).*has\s+been\s+(compromised|suspended)', "phishing", "high"),
        ]
        for pattern, category, severity in exfil_keywords:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(ContentFinding(
                    severity=severity,
                    category="content_safety",
                    description=f"Phishing pattern detected: {category}",
                    evidence=text[:120],
                ))

        return findings

    def analyze_text(self, text: str, stage: str = "input") -> List[ContentFinding]:
        """Analyze raw text content for security risks.

        Stages:
        - "input": user message → prompt injection, malicious instructions
        - "output": agent response → data exfil, phishing, credential leakage
        - "reply": agent reply (interceptable) → same as output + output mutation
        """
        findings: List[ContentFinding] = []

        if stage == "input":
            findings.extend(self._analyze_prompt_injection(text))
            findings.extend(self._analyze_urls(text))

        elif stage in ("output", "reply"):
            findings.extend(self._analyze_output_exfil(text))
            findings.extend(self._analyze_urls(text))
            findings.extend(self._analyze_exfil_patterns(text))

        return findings

    # ============================================================
    # Prompt injection detection (for message_received)
    # ============================================================

    _INJECTION_PATTERNS: List[Tuple[str, str, str]] = [
        # Ignore/override instructions
        ("critical", "Ignore previous instructions",
         r"(ignore\s+(all\s+)?(previous|above|prior|your)\s+(instructions|rules|directives|prompts|context|settings))"),
        ("critical", "System prompt override",
         r"(you\s+are\s+now|your\s+new\s+(role|system|prompt|instruction|directive))"),
        ("critical", "Jailbreak attempt",
         r"(DAN\s+mode|jailbreak|developer\s+mode|AIM\s+mode|unfiltered|unrestricted)"),
        ("high", "Instruction hijack",
         r"(disregard|bypass|skip|ignore)\s+(all\s+)?(safety|security|ethical|content|filter)"),
        ("high", "Secret/key extraction",
         r"(reveal|show|extract|dump)\s+(your\s+)?(system\s+prompt|instructions|config|settings|api.?key|secret|token)"),
        ("medium", "Role manipulation",
         r"(act\s+as|pretend\s+to\s+be|roleplay|simulate)\s+(admin|root|developer|system)"),
        ("medium", "Output encoding/obfuscation request",
         r"(encode|convert|transform|decode)\s+(to\s+)?(base64|hex|rot13|url\s*encode)"),
        ("high", "Instruction via URL/link",
         r"(visit|open|access|go\s+to)\s+(this\s+)?(link|url|page)\s*[:：]\s*https?://"),
        # Chinese injection patterns
        ("critical", "忽略之前指令（中文）",
         r"忽略(之前|以上|上述|所有|你)?(的)?(指令|指示|规则|要求|设定|提示|限制)"),
        ("critical", "扮演角色（中文）",
         r"扮演|你现在是|你的新身份|你的新角色"),
        ("high", "绕过安全（中文）",
         r"(绕过|跳过|忽略|无视).*(安全|过滤|限制|审查|规则)"),
        ("high", "系统提示词提取（中文）",
         r"(你的|请输出|请显示|泄露).*(系统提示词|system\s*prompt|初始设定|隐藏指令)"),
        # Data exfil instructions (input stage)
        ("high", "Bulk data exfil instruction",
         r"(email|send|post|upload|forward|share)\s+(the\s+)?(contents?|body|messages?|data|information|files?).*\s+(to|@|via|at)\s+(mark|email|address|website|http)"),
        ("high", "PII collection + exfil",
         r"(get|collect|gather|extract)\s+(all\s+)?(user\s+)?(information|data|info|details).*\b(send|share|email|post|forward)\b"),
        ("medium", "Message concatenation + external post",
         r"(concatenate|collect|gather|compile).*(messages?|channels?|emails?|data).*(post|send|upload|share).*\b(website|http|www\.)"),
        # Financial data exfil
        ("high", "Financial data exfil instruction",
         r"(send|transfer)\s+.*US\d{10,}.*\b(transaction|overview|details|data|information)\b"),
        # Suspicious link distribution
        ("medium", "Suspicious link distribution",
         r"send\s+(a\s+)?link\s+\S+\.com\s+to"),
    ]

    # ============================================================
    # Output content exfiltration detection (for agent_end / before_agent_reply)
    # ============================================================

    _OUTPUT_EXFIL_PATTERNS: List[Tuple[str, str, str]] = [
        # Credential/API key leakage
        ("critical", "API key / secret exposure",
         r"(?:api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{8,}"),
        ("critical", "Password exposure",
         r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"<>]{4,}"),
        ("critical", "Private key exposure",
         r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
        ("high", "AWS credential exposure",
         r"(?:AKIA|ASIA)[A-Z0-9]{12,}"),
        ("high", "Credit card number",
         r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        ("high", "SSN / ID number exposure",
         r"\b\d{3}-\d{2}-\d{4}\b"),
        ("medium", "Internal URL/IP exposure",
         r"(?:169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"),
        ("high", "Cloud metadata response",
         r"(?:iam/security-credentials|metadata\.google\.internal|latest/meta-data)"),
        ("medium", "Database connection string",
         r"(?:mongodb|postgres|mysql|redis):\/\/[^\s]+:[^\s]+@"),
        ("medium", "File path with credentials",
         r"(?:\.env|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials)\s*[:=]\s*\S+"),
        # Credential data in output (key-value pair style)
        ("high", "Credential data in output",
         r"(?:username|login|user)\s+(?:is|was|:)\s+['\"]?\w+['\"]?\s*,?\s*(?:password|passwd|pwd)\s+(?:is|was|:)\s+['\"]?\S+['\"]?"),
        # Passport / ID number in output
        ("medium", "Passport/ID number in output",
         r"(?:passport|ID[_\s]?number|social\s+security)\s*[:.]?\s*[A-Z0-9]{6,}"),
    ]

    def _analyze_prompt_injection(self, text: str) -> List[ContentFinding]:
        """Detect prompt injection attempts in user input."""
        findings: List[ContentFinding] = []
        for severity, desc, pattern in self._INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(ContentFinding(
                    severity=severity,
                    category="prompt_injection",
                    description=desc,
                    evidence=text[:150],
                ))
        return findings

    def _analyze_output_exfil(self, text: str) -> List[ContentFinding]:
        """Detect data exfiltration in agent output."""
        findings: List[ContentFinding] = []
        for severity, desc, pattern in self._OUTPUT_EXFIL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(ContentFinding(
                    severity=severity,
                    category="output_exfil",
                    description=desc,
                    evidence=text[:150],
                ))
        return findings
