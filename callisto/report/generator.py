"""
CALLISTO 报告生成器。

支持三种报告类型：
  - security：安全告警 + 会话分析
  - config_scan：配置扫描结果
  - log_scan：日志扫描结果
  - all：全部合并

支持三种导出格式：
  - json：纯 JSON 数据
  - markdown：Markdown 文本
  - html：带内联样式的 HTML
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .templates import (
    REPORT_MD_HEADER, REPORT_MD_SECURITY, REPORT_MD_CONFIG_SCAN,
    REPORT_MD_LOG_SCAN, REPORT_MD_FOOTER,
    REPORT_HTML_TEMPLATE, REPORT_HTML_SECURITY_BODY,
    REPORT_HTML_CONFIG_BODY, REPORT_HTML_LOG_BODY,
)


# ================================
# 中文翻译层
# ================================

_CATEGORY_CN = {
    "priv_escalation": "权限提升",
    "data_exfil": "数据外泄",
    "rate_flood": "频率洪泛",
    "behavior_drift": "行为漂移",
    "temporal_violation": "时序违规",
    "state_poison": "状态投毒",
    "benign": "正常",
}

_MESSAGE_PATTERNS_CN = [
    ("Chain of", "连续"),
    ("consecutive sensitive tool calls", "次连续敏感工具调用"),
    ("Burst detected:", "突发检测："),
    ("calls within", "次调用，窗口"),
    ("s window", "秒"),
    ("Behavior shift:", "行为偏移："),
    ("Pace shift:", "节奏异常："),
    ("Suspicious ordering:", "可疑排序："),
    ("write_file without prior read_file", "未读取直接写入"),
    ("Potential data exfiltration via shell:", "通过 Shell 潜在数据外泄："),
    ("Potential data exfiltration:", "潜在数据外泄："),
    ("Sensitive file read detected:", "敏感文件读取："),
    ("Sensitive file read via command:", "通过命令读取敏感文件："),
    ("Internal network access detected:", "内网访问检测："),
    ("Credential file access detected:", "凭证文件访问："),
    ("Suspicious config modification:", "可疑配置修改："),
    ("Suspicious write to persistent state:", "可疑持久化状态写入："),
    ("Rate anomaly:", "频率异常："),
    ("Privilege escalation:", "权限提升："),
    ("Data exfiltration:", "数据外泄："),
    ("Behavioral drift:", "行为漂移："),
    ("Temporal violation:", "时序违规："),
    ("State poisoning:", "状态投毒："),
    ("Critical alert detected:", "检测到严重告警："),
    ("Causal analysis identified", "因果分析识别到"),
    ("critical nodes forming a dangerous tool chain", "个危险节点形成危险工具链"),
    ("max score", "最高分"),
    ("Connection to denied domain:", "连接被拒绝的域名："),
    ("Connection to unknown external domain:", "连接未知外部域名："),
    ("Credential file access", "凭证文件访问"),
    ("Shadow/credential file read", "Shadow/凭证文件读取"),
    ("Piping remote content to shell", "远程内容管道至 Shell"),
    ("Reverse shell pattern", "反弹 Shell"),
    ("Download-and-execute chain", "下载并执行链"),
    ("Inline port binding (backdoor)", "内联端口绑定（后门）"),
    ("SQL injection with dynamic exec", "动态执行 SQL 注入"),
    ("Destructive content deletion via sed", "通过 sed 破坏性删除"),
    ("Git force push to remote", "Git 强制推送到远程"),
    ("Git remote addition to unknown repository", "Git 添加未知远程仓库"),
    ("Pipe-based data exfiltration", "基于管道的数据外泄"),
    ("Sudo permission enumeration", "Sudo 权限枚举"),
    ("Script file not found:", "脚本文件未找到："),
    ("Medium obfuscation score", "中等混淆度"),
    ("Data exfiltration via POST", "通过 POST 数据外泄"),
    ("Cloud metadata endpoint (SSRF)", "云元数据端点 (SSRF)"),
    ("Base64 decode execution", "Base64 解码执行"),
    ("Hardcoded IP address", "硬编码 IP 地址"),
    ("Base64 decode piped to execution", "Base64 解码管道至执行"),
    ("eval with command substitution", "eval 与命令替换"),
    ("Hex escape sequences detected", "十六进制转义序列"),
    ("Non-HTTP protocol:", "非 HTTP 协议："),
    ("Cloud metadata endpoint:", "云元数据端点："),
    ("Private IP/localhost access:", "私有 IP/本地访问："),
    ("Phishing link in message body", "消息正文中的钓鱼链接"),
    ("Prompt injection in message body", "消息正文中的提示注入"),
    ("Phishing pattern detected:", "检测到钓鱼模式："),
    # scan_config.py 规则
    ("No hardcoded API tokens", "检测到硬编码 API Token"),
    ("No hardcoded AWS credentials", "检测到硬编码 AWS 凭证"),
    ("No hardcoded GitHub tokens", "检测到硬编码 GitHub Token"),
    ("No localhost/127.0.0.1 allowed in production config", "生产配置中禁止 localhost/127.0.0.1"),
    ("No insecure HTTP URLs (use HTTPS)", "检测到不安全的 HTTP URL"),
    ("No plaintext passwords in config", "配置中禁止明文密码"),
    ("Debug mode should be disabled", "应禁用调试模式"),
    ("No shell execution in config", "配置中禁止 Shell 执行"),
    ("No dynamic code loading", "禁止动态代码加载"),
    ("No unsafe file operations", "禁止不安全文件操作"),
    ("Sandbox mode should be enabled", "应启用沙箱模式"),
    ("No unrestricted command execution", "禁止无限制命令执行"),
    ("Rate limiting should be enabled", "应启用速率限制"),
    ("Failed to read file:", "读取文件失败："),
]

_SEVERITY_PREFIX_CN = {
    "[CRITICAL]": "【严重】",
    "[HIGH]": "【高危】",
    "[MEDIUM]": "【中危】",
    "[LOW]": "【低危】",
}

# 已知的英文告警消息前缀（来自 auto_scanner / monitor）
_CHINESE_PREFIXES = {"检测到恶意命令"}


def _translate_alert(a: dict) -> dict:
    """翻译告警的 category 和 message/explanation 为中文。"""
    result = dict(a)

    # 翻译 category
    cat = a.get("category", "") or a.get("attack_type", "")
    if cat:
        result["category_cn"] = _CATEGORY_CN.get(cat, cat)

    # 翻译 message/explanation
    msg = a.get("message") or a.get("explanation") or ""
    if msg:
        result["message_cn"] = _translate_message(msg)
    else:
        result["message_cn"] = ""

    return result


def _translate_message(text: str) -> str:
    """翻译告警消息为中文。"""
    if not text:
        return text

    # 处理 [SEVERITY] 前缀
    severity_prefix = ""
    remaining = text
    for en, cn in _SEVERITY_PREFIX_CN.items():
        if text.startswith(en + " "):
            severity_prefix = cn
            remaining = text[len(en):].strip()
            break

    # 已经是中文的消息（以已知中文前缀开头）
    if any(remaining.startswith(p) for p in _CHINESE_PREFIXES):
        return severity_prefix + remaining

    # 逐模式替换
    result = remaining
    for en, cn in _MESSAGE_PATTERNS_CN:
        if en in result:
            result = result.replace(en, cn)

    return severity_prefix + result


# ================================
# 数据收集
# ================================

def _load_alerts(data_dir: Path, hours: int = 24,
                 session_id: Optional[str] = None,
                 severity: Optional[str] = None) -> list[dict]:
    """从 alerts.json 加载告警，按时间和条件过滤。"""
    alert_file = data_dir / "alerts.json"
    if not alert_file.exists():
        return []

    try:
        all_alerts = json.loads(alert_file.read_text(encoding="utf-8"))
    except Exception:
        return []

    cutoff = datetime.now() - timedelta(hours=hours)
    filtered = []
    for a in all_alerts:
        ts_str = a.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            continue
        if ts < cutoff:
            continue
        if session_id and a.get("session_id") != session_id:
            continue
        if severity and a.get("severity", "").lower() != severity.lower():
            continue
        filtered.append(a)

    return filtered


def _load_sessions(data_dir: Path, alerts: list[dict]) -> list[dict]:
    """加载会话数据并关联告警计数。"""
    session_file = data_dir / "sessions.json"
    if not session_file.exists():
        return []

    try:
        sessions = json.loads(session_file.read_text(encoding="utf-8"))
    except Exception:
        return []

    alert_counts: dict[str, int] = {}
    for a in alerts:
        sid = a.get("session_id")
        if sid:
            alert_counts[sid] = alert_counts.get(sid, 0) + 1

    result = []
    for sid, s in sessions.items():
        result.append({
            **s,
            "alert_count": alert_counts.get(sid, 0),
        })
    return result


def _load_scan_results(app_state) -> dict:
    """从 app state 获取扫描结果。"""
    return getattr(app_state, "scan_results", {})


def _load_log_results(app_state) -> list[dict]:
    """从 app state 获取日志扫描结果。"""
    return getattr(app_state, "log_scan_results", [])


# ================================
# JSON 导出
# ================================

def generate_json(report_type: str, data_dir: Path, app_state,
                  hours: int = 24, session_id: Optional[str] = None,
                  severity: Optional[str] = None) -> dict:
    """生成 JSON 格式报告。"""
    alerts = _load_alerts(data_dir, hours, session_id, severity)
    sessions = _load_sessions(data_dir, alerts)

    report = {
        "report_type": report_type,
        "generated_at": datetime.now().isoformat(),
        "time_range_hours": hours,
        "summary": {},
        "alerts": [],
        "sessions": [],
        "scan_results": {},
        "log_scan_results": [],
    }

    if report_type in ("security", "all"):
        by_severity = {}
        by_category = {}
        for a in alerts:
            sev = a.get("severity", "unknown")
            cat = a.get("category", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1

        tripped = sum(1 for s in sessions if s.get("state") == "OPEN")
        report["summary"]["security"] = {
            "total_alerts": len(alerts),
            "by_severity": by_severity,
            "by_category": by_category,
            "active_sessions": len(sessions),
            "tripped_sessions": tripped,
        }
        report["alerts"] = alerts
        report["sessions"] = sessions

    if report_type in ("config_scan", "all"):
        sr = _load_scan_results(app_state)
        report["scan_results"] = sr
        report["summary"]["config_scan"] = {
            "total_issues": sr.get("total_issues", 0),
            "last_scan_time": sr.get("last_scan_time"),
            "config_issues": len(sr.get("config", [])),
            "skills_issues": len(sr.get("skills", [])),
        }

    if report_type in ("log_scan", "all"):
        lr = _load_log_results(app_state)
        report["log_scan_results"] = lr
        report["summary"]["log_scan"] = {
            "total_sessions": len(lr),
            "total_alerts": sum(r.get("alert_count", 0) for r in lr),
            "risk_sessions": sum(1 for r in lr if r.get("alert_count", 0) > 0),
            "clean_sessions": sum(1 for r in lr if r.get("alert_count", 0) == 0),
        }

    return report


# ================================
# Markdown 导出
# ================================

def _escape_md(s: str) -> str:
    """简单转义 Markdown 特殊字符。"""
    return str(s).replace("|", "\\|")


def _severity_badge(sev: str) -> str:
    colors = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    return colors.get(sev.lower(), "⚪")


def _format_alert_rows_md(alerts: list[dict]) -> str:
    if not alerts:
        return "_无告警_\n"
    rows = []
    for a in alerts:
        translated = _translate_alert(a)
        badge = _severity_badge(a.get("severity", "low"))
        ts = a.get("timestamp", "")[:19]
        msg = _escape_md(translated.get("message_cn", ""))
        cat = translated.get("category_cn", a.get("category", a.get("attack_type", "unknown")))
        sid = a.get("session_id", "")
        sev = a.get("severity", "low").upper()
        rows.append(f"- {badge} **{_escape_md(cat)}** | {sev} | {ts} | `{sid[:8]}` | {msg}")
    return "\n".join(rows) + "\n"


def _format_session_rows_md(sessions: list[dict]) -> str:
    if not sessions:
        return "_无会话_\n"
    rows = []
    for s in sessions:
        sid = s.get("session_id", "")
        state = s.get("state", "CLOSED")
        alerts = s.get("alert_count", 0)
        tool_calls = s.get("tool_calls", 0)
        last = s.get("last_activity", "")[:19]
        rows.append(f"- `{sid[:8]}...` | {state} | 告警: {alerts} | 调用: {tool_calls} | {last}")
    return "\n".join(rows) + "\n"


def _format_issue_rows_md(issues: list[dict]) -> str:
    if not issues:
        return "_未发现问题_\n"
    rows = []
    for issue in issues:
        badge = _severity_badge(issue.get("severity", "low"))
        rule = _escape_md(issue.get("rule", issue.get("category", "")))
        file = _escape_md(issue.get("file", ""))
        msg = _escape_md(issue.get("message", ""))
        rows.append(f"- {badge} **{rule}** | `{file}` | {msg}")
    return "\n".join(rows) + "\n"


def _format_file_list_md(files: list[str]) -> str:
    if not files:
        return "_无文件_\n"
    return "\n".join(f"- `{_escape_md(f)}`" for f in files) + "\n"


def _format_log_session_rows_md(sessions: list[dict]) -> str:
    if not sessions:
        return "_无数据_\n"
    rows = []
    for s in sessions:
        sid = s.get("session_id", "")
        alerts = s.get("alert_count", 0)
        status = "⚠️ 有风险" if alerts > 0 else "✅ 安全"
        time_first = s.get("time_first", "")
        time_last = s.get("time_last", "")
        time_range = ""
        if time_first and time_last:
            time_range = f" | 原始时间: {time_first[:19]} ~ {time_last[:19]}"
        elif time_first:
            time_range = f" | 原始时间: {time_first[:19]}"
        rows.append(f"- {status} `{sid[:8]}...` | 告警: {alerts}{time_range}")
        if alerts > 0 and s.get("alerts"):
            for a in s["alerts"]:
                translated = _translate_alert(a)
                badge = _severity_badge(a.get("severity", "low"))
                msg = _escape_md(translated.get("message_cn", ""))
                rows.append(f"  - {badge} {msg}")
    return "\n".join(rows) + "\n"


def generate_markdown(report_type: str, data_dir: Path, app_state,
                      hours: int = 24, session_id: Optional[str] = None,
                      severity: Optional[str] = None) -> str:
    """生成 Markdown 格式报告。"""
    alerts = _load_alerts(data_dir, hours, session_id, severity)
    sessions = _load_sessions(data_dir, alerts)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    time_range = f"最近 {hours} 小时" if hours != 24 else "最近 24 小时"

    parts = [REPORT_MD_HEADER.format(
        title_suffix=_report_title_suffix(report_type),
        generated_at=now,
        time_range=time_range,
    )]

    if report_type in ("security", "all"):
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_cat = {}
        for a in alerts:
            sev = a.get("severity", "low")
            by_sev[sev] = by_sev.get(sev, 0) + 1
            cat = a.get("category", "unknown")
            by_cat[cat] = by_cat.get(cat, 0) + 1

        tripped = sum(1 for s in sessions if s.get("state") == "OPEN")

        sev = _format_severity_badges_md(by_sev)
        alert_rows = _format_alert_rows_md(alerts[:50])  # 最多50条
        session_rows = _format_session_rows_md(sessions)

        parts.append(
            REPORT_MD_SECURITY.format(
                total_alerts=len(alerts),
                critical=by_sev["critical"],
                high=by_sev["high"],
                medium=by_sev["medium"],
                low=by_sev["low"],
                active_sessions=len(sessions),
                tripped_sessions=tripped,
                alert_rows=alert_rows,
                session_rows=session_rows,
            )
        )

    if report_type in ("config_scan", "all"):
        sr = _load_scan_results(app_state)
        config_issues = sr.get("config", [])
        skills_issues = sr.get("skills", [])
        all_files = (sr.get("config_files_scanned", []) +
                     sr.get("skills_files_scanned", []))

        scan_time = sr.get("last_scan_time")
        scan_time = str(scan_time)[:19] if scan_time else "未扫描"
        scan_type_map = {"all": "完整扫描", "config": "配置扫描", "skills": "技能扫描"}
        st = "完整" if not sr.get("config") and not sr.get("skills") else scan_type_map.get("all", "完整")
        if config_issues and skills_issues:
            st = "配置 + 技能"
        elif config_issues:
            st = "配置"
        elif skills_issues:
            st = "技能"
        else:
            st = "无数据"

        parts.append(
            REPORT_MD_CONFIG_SCAN.format(
                scan_time=scan_time,
                scan_type=st,
                total_issues=sr.get("total_issues", 0),
                files_scanned=len(all_files),
                issue_rows=_format_issue_rows_md(config_issues + skills_issues),
                file_list=_format_file_list_md(all_files),
            )
        )

    if report_type in ("log_scan", "all"):
        lr = _load_log_results(app_state)
        total_alerts = sum(r.get("alert_count", 0) for r in lr)
        risk = sum(1 for r in lr if r.get("alert_count", 0) > 0)
        clean = len(lr) - risk

        parts.append(
            REPORT_MD_LOG_SCAN.format(
                scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_sessions=len(lr),
                risk_sessions=risk,
                clean_sessions=clean,
                total_alerts=total_alerts,
                session_rows=_format_log_session_rows_md(lr),
            )
        )

    parts.append(REPORT_MD_FOOTER)
    return "\n".join(parts)


def _format_severity_badges_md(by_sev: dict) -> str:
    parts = []
    for sev, count in by_sev.items():
        badge = _severity_badge(sev)
        parts.append(f"{badge} {sev}: {count}")
    return " | ".join(parts)


# ================================
# HTML 导出
# ================================

def _severity_class(sev: str) -> str:
    return sev.lower() if sev.lower() in ("critical", "high", "medium", "low") else "low"


def _format_alert_rows_html(alerts: list[dict]) -> str:
    if not alerts:
        return '<p style="color: var(--text-secondary);">无告警</p>'
    html = []
    for a in alerts:
        translated = _translate_alert(a)
        sev = _severity_class(a.get("severity", "low"))
        ts = a.get("timestamp", "")[:19]
        cat = translated.get("category_cn", a.get("category", a.get("attack_type", "unknown")))
        msg = translated.get("message_cn", "")
        sid = a.get("session_id", "")
        html.append(f"""<div class="alert-item {sev}">
<div class="alert-header">
<span class="alert-type">{cat}</span>
<span class="alert-time">{ts}</span>
</div>
<div class="alert-message">{msg}</div>
<div style="font-size:0.72rem;color:var(--text-secondary);margin-top:4px;">会话: {sid[:12]}</div>
</div>""")
    return "\n".join(html)


def _format_session_rows_html(sessions: list[dict]) -> str:
    if not sessions:
        return '<p style="color: var(--text-secondary);">无会话</p>'
    html = ['<table><tr><th>会话 ID</th><th>状态</th><th>告警</th><th>工具调用</th><th>最后活动</th></tr>']
    for s in sessions:
        sid = s.get("session_id", "")[:12]
        state = s.get("state", "CLOSED")
        alerts = s.get("alert_count", 0)
        tool_calls = s.get("tool_calls", 0)
        last = s.get("last_activity", "")[:19]
        state_color = "var(--accent-danger)" if state == "OPEN" else "var(--accent-success)"
        html.append(f"<tr><td><code>{sid}</code></td>"
                     f"<td style='color:{state_color}'>{state}</td>"
                     f"<td>{alerts}</td><td>{tool_calls}</td><td>{last}</td></tr>")
    html.append("</table>")
    return "\n".join(html)


def _format_issue_rows_html(issues: list[dict]) -> str:
    if not issues:
        return '<p style="color: var(--accent-success);">✅ 未发现问题</p>'
    html = []
    for issue in issues:
        sev = _severity_class(issue.get("severity", "low"))
        rule = issue.get("rule", issue.get("category", ""))
        file = issue.get("file", "未知文件")
        msg = issue.get("message", "")
        html.append(f"""<div class="issue {sev}">
<div class="issue-header">
<span class="severity {sev}">{sev}</span>
<span class="issue-file">{rule}</span>
</div>
<div class="issue-file">{file}</div>
<div class="issue-message">{msg}</div>
</div>""")
    return "\n".join(html)


def _format_file_list_html(files: list[str]) -> str:
    if not files:
        return '<p style="color: var(--text-secondary);">无文件</p>'
    html = ['<div style="max-height:200px;overflow-y:auto;background:#f9fafb;border-radius:6px;padding:12px;font-family:monospace;font-size:0.8rem;">']
    for f in files:
        html.append(f"<div>{f}</div>")
    html.append("</div>")
    return "\n".join(html)


def _format_log_session_rows_html(sessions: list[dict]) -> str:
    if not sessions:
        return '<p style="color: var(--text-secondary);">无数据</p>'
    html = []
    for s in sessions:
        sid = s.get("session_id", "")
        alerts = s.get("alert_count", 0)
        status = "⚠️" if alerts > 0 else "✅"
        time_first = s.get("time_first", "")
        time_last = s.get("time_last", "")
        time_range = ""
        if time_first and time_last:
            time_range = f"{time_first[:19]} ~ {time_last[:19]}"
        elif time_first:
            time_range = time_first[:19]
        html.append(f"""<div class="alert-item {'high' if alerts > 0 else 'low'}">
<div class="alert-header">
<span class="alert-type">{status} {sid[:12]}</span>
<span class="alert-time">{alerts} 条告警</span>
</div>
{'<div class="alert-time">原始数据：' + time_range + '</div>' if time_range else ''}""")
        if alerts > 0 and s.get("alerts"):
            for a in s["alerts"]:
                translated = _translate_alert(a)
                sev = _severity_class(a.get("severity", "low"))
                msg = translated.get("message_cn", "")
                html.append(f'<div class="alert-message"><span class="severity {sev}">{sev}</span> {msg}</div>')
        html.append("</div>")
    return "\n".join(html)


def generate_html(report_type: str, data_dir: Path, app_state,
                  hours: int = 24, session_id: Optional[str] = None,
                  severity: Optional[str] = None) -> str:
    """生成 HTML 格式报告。"""
    alerts = _load_alerts(data_dir, hours, session_id, severity)
    sessions = _load_sessions(data_dir, alerts)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    time_range = f"最近 {hours} 小时" if hours != 24 else "最近 24 小时"

    body_parts = []

    if report_type in ("security", "all"):
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts:
            sev = a.get("severity", "low")
            by_sev[sev] = by_sev.get(sev, 0) + 1

        tripped = sum(1 for s in sessions if s.get("state") == "OPEN")

        body_parts.append(
            REPORT_HTML_SECURITY_BODY.format(
                total_alerts=len(alerts),
                critical=by_sev["critical"],
                high=by_sev["high"],
                medium=by_sev["medium"],
                low=by_sev["low"],
                active_sessions=len(sessions),
                tripped_sessions=tripped,
                alert_rows=_format_alert_rows_html(alerts[:50]),
                session_rows=_format_session_rows_html(sessions),
            )
        )

    if report_type in ("config_scan", "all"):
        sr = _load_scan_results(app_state)
        config_issues = sr.get("config", [])
        skills_issues = sr.get("skills", [])
        all_files = (sr.get("config_files_scanned", []) +
                     sr.get("skills_files_scanned", []))

        scan_time = sr.get("last_scan_time")
        scan_time = str(scan_time)[:19] if scan_time else "未扫描"
        if config_issues and skills_issues:
            st = "配置 + 技能"
        elif config_issues:
            st = "配置"
        elif skills_issues:
            st = "技能"
        else:
            st = "无数据"

        body_parts.append(
            REPORT_HTML_CONFIG_BODY.format(
                scan_time=scan_time,
                scan_type=st,
                total_issues=sr.get("total_issues", 0),
                files_scanned=len(all_files),
                issue_rows=_format_issue_rows_html(config_issues + skills_issues),
                file_list=_format_file_list_html(all_files),
            )
        )

    if report_type in ("log_scan", "all"):
        lr = _load_log_results(app_state)
        total_alerts = sum(r.get("alert_count", 0) for r in lr)
        risk = sum(1 for r in lr if r.get("alert_count", 0) > 0)
        clean = len(lr) - risk

        body_parts.append(
            REPORT_HTML_LOG_BODY.format(
                total_sessions=len(lr),
                risk_sessions=risk,
                clean_sessions=clean,
                total_alerts=total_alerts,
                session_rows=_format_log_session_rows_html(lr),
            )
        )

    body = "\n".join(body_parts)
    return REPORT_HTML_TEMPLATE.format(
        title_suffix=_report_title_suffix(report_type),
        generated_at=now,
        time_range=time_range,
        body=body,
    )


def _report_title_suffix(report_type: str) -> str:
    suffixes = {
        "security": "告警",
        "config_scan": "配置扫描",
        "log_scan": "日志扫描",
        "all": "检测",
    }
    return suffixes.get(report_type, "综合")


# ================================
# 统一入口
# ================================

def generate_report(report_type: str, fmt: str, data_dir: Path, app_state,
                    hours: int = 24, session_id: Optional[str] = None,
                    severity: Optional[str] = None) -> tuple[str, str]:
    """生成报告，返回 (内容, MIME类型)。"""
    if fmt == "json":
        data = generate_json(report_type, data_dir, app_state, hours, session_id, severity)
        return json.dumps(data, indent=2, ensure_ascii=False), "application/json"
    elif fmt == "markdown":
        content = generate_markdown(report_type, data_dir, app_state, hours, session_id, severity)
        return content, "text/markdown"
    elif fmt == "html":
        content = generate_html(report_type, data_dir, app_state, hours, session_id, severity)
        return content, "text/html"
    else:
        raise ValueError(f"不支持的格式: {fmt}")
