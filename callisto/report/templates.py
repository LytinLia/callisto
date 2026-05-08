"""
CALLISTO 报告模板（Markdown 和 HTML）。
"""

REPORT_MD_HEADER = """\
# CALLISTO 安全{title_suffix}报告

| 项目 | 值 |
|------|-----|
| 生成时间 | {generated_at} |
| 时间范围 | {time_range} |
| 报告版本 | 2.1.0 |

---

"""

REPORT_MD_SECURITY = """\
## 一、安全概览

| 指标 | 数量 |
|------|------|
| 总告警数 | {total_alerts} |
| 严重 (Critical) | {critical} |
| 高危 (High) | {high} |
| 中危 (Medium) | {medium} |
| 低危 (Low) | {low} |
| 活跃告警会话 | {active_sessions} |
| 熔断触发会话 | {tripped_sessions} |

## 二、告警详情

{alert_rows}

## 三、会话分析

{session_rows}

"""

REPORT_MD_CONFIG_SCAN = """\
## 一、扫描概览

| 项目 | 值 |
|------|-----|
| 扫描时间 | {scan_time} |
| 扫描类型 | {scan_type} |
| 发现问题数 | {total_issues} |
| 扫描文件数 | {files_scanned} |

## 二、问题详情

{issue_rows}

## 三、已扫描文件

{file_list}

"""

REPORT_MD_LOG_SCAN = """\
## 一、扫描概览

| 项目 | 值 |
|------|-----|
| 扫描时间 | {scan_time} |
| 扫描会话数 | {total_sessions} |
| 有风险的会话 | {risk_sessions} |
| 安全的会话 | {clean_sessions} |
| 总告警数 | {total_alerts} |

## 二、会话详情

{session_rows}

"""

REPORT_MD_FOOTER = """\
---

*本报告由 CALLISTO 安全检测系统自动生成。*
"""


# ─────────────────────────────────────────────
# HTML Templates
# ─────────────────────────────────────────────

REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CALLISTO 安全{title_suffix}报告</title>
<style>
:root {{
    --bg: #fafbfc; --card: #fff; --text: #1a1a2e; --text-secondary: #6b7280;
    --border: #e5e7eb; --danger: #dc2626; --warning: #f59e0b;
    --info: #3b82f6; --success: #16a34a;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", sans-serif;
       background: var(--bg); color: var(--text); line-height: 1.6; padding: 32px 48px; max-width: 960px; margin: 0 auto; }}
h1 {{ font-size: 1.5rem; margin-bottom: 8px; color: var(--text); }}
h2 {{ font-size: 1.15rem; margin: 28px 0 12px; padding-bottom: 6px; border-bottom: 2px solid var(--border); }}
h3 {{ font-size: 1rem; margin: 16px 0 8px; }}
.meta {{ color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 24px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.stat {{ background: var(--card); border-radius: 8px; padding: 16px; border: 1px solid var(--border); text-align: center; }}
.stat-value {{ font-size: 1.6rem; font-weight: 700; }}
.stat-label {{ font-size: 0.75rem; color: var(--text-secondary); margin-top: 2px; }}
.stat.critical .stat-value {{ color: var(--danger); }}
.stat.high .stat-value {{ color: var(--warning); }}
.stat.medium .stat-value {{ color: var(--info); }}
.stat.low .stat-value {{ color: var(--success); }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 0.85rem; }}
th {{ background: #f3f4f6; padding: 8px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid var(--border); }}
td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); }}
tr:hover td {{ background: #f9fafb; }}
.severity {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 600; text-transform: uppercase; }}
.severity.critical {{ background: var(--danger); color: #fff; }}
.severity.high {{ background: var(--warning); color: #000; }}
.severity.medium {{ background: var(--info); color: #fff; }}
.severity.low {{ background: var(--success); color: #fff; }}
.issue {{ background: var(--card); border-radius: 8px; border-left: 4px solid var(--border); padding: 12px; margin-bottom: 10px; border: 1px solid var(--border); }}
.issue.critical {{ border-left-color: var(--danger); }}
.issue.high {{ border-left-color: var(--warning); }}
.issue.medium {{ border-left-color: var(--info); }}
.issue.low {{ border-left-color: var(--success); }}
.issue-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }}
.issue-file {{ font-size: 0.8rem; color: var(--text-secondary); font-family: monospace; }}
.issue-message {{ font-size: 0.85rem; margin-top: 4px; }}
.alert-item {{ padding: 10px 12px; background: var(--card); border-radius: 6px; margin-bottom: 8px; border: 1px solid var(--border); border-left: 3px solid var(--border); }}
.alert-item.critical {{ border-left-color: var(--danger); }}
.alert-item.high {{ border-left-color: var(--warning); }}
.alert-item.medium {{ border-left-color: var(--info); }}
.alert-item.low {{ border-left-color: var(--success); }}
.alert-header {{ display: flex; justify-content: space-between; margin-bottom: 4px; }}
.alert-type {{ font-weight: 600; font-size: 0.85rem; }}
.alert-time {{ font-size: 0.75rem; color: var(--text-secondary); }}
.alert-message {{ font-size: 0.82rem; color: var(--text-secondary); }}
.footer {{ margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--text-secondary); text-align: center; }}
@media print {{ body {{ padding: 0; }} .footer {{ display: none; }} }}
</style>
</head>
<body>
<h1>CALLISTO 安全{title_suffix}报告</h1>
<div class="meta">
    <span>生成时间：{generated_at}</span> &middot;
    <span>时间范围：{time_range}</span> &middot;
    <span>CALLISTO v2.1.0</span>
</div>

{body}

<div class="footer">本报告由 CALLISTO 安全检测系统自动生成。</div>
</body>
</html>"""


REPORT_HTML_SECURITY_BODY = """\
<h2>一、安全概览</h2>
<div class="stats">
<div class="stat"><div class="stat-value">{total_alerts}</div><div class="stat-label">总告警数</div></div>
<div class="stat critical"><div class="stat-value">{critical}</div><div class="stat-label">严重</div></div>
<div class="stat high"><div class="stat-value">{high}</div><div class="stat-label">高危</div></div>
<div class="stat medium"><div class="stat-value">{medium}</div><div class="stat-label">中危</div></div>
<div class="stat low"><div class="stat-value">{low}</div><div class="stat-label">低危</div></div>
<div class="stat"><div class="stat-value">{active_sessions}</div><div class="stat-label">活跃会话</div></div>
<div class="stat critical"><div class="stat-value">{tripped_sessions}</div><div class="stat-label">熔断会话</div></div>
</div>

<h2>二、告警详情</h2>
{alert_rows}

<h2>三、会话分析</h2>
{session_rows}
"""

REPORT_HTML_CONFIG_BODY = """\
<h2>一、扫描概览</h2>
<div class="stats">
<div class="stat"><div class="stat-value">{scan_time}</div><div class="stat-label">扫描时间</div></div>
<div class="stat"><div class="stat-value">{scan_type}</div><div class="stat-label">扫描类型</div></div>
<div class="stat critical"><div class="stat-value">{total_issues}</div><div class="stat-label">发现问题</div></div>
<div class="stat"><div class="stat-value">{files_scanned}</div><div class="stat-label">扫描文件</div></div>
</div>

<h2>二、问题详情</h2>
{issue_rows}

<h2>三、已扫描文件</h2>
{file_list}
"""

REPORT_HTML_LOG_BODY = """\
<h2>一、扫描概览</h2>
<div class="stats">
<div class="stat"><div class="stat-value">{total_sessions}</div><div class="stat-label">扫描会话</div></div>
<div class="stat critical"><div class="stat-value">{risk_sessions}</div><div class="stat-label">有风险</div></div>
<div class="stat low"><div class="stat-value">{clean_sessions}</div><div class="stat-label">安全</div></div>
<div class="stat high"><div class="stat-value">{total_alerts}</div><div class="stat-label">总告警</div></div>
</div>

<h2>二、会话详情</h2>
{session_rows}
"""
