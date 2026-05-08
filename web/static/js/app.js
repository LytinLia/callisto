/**
 * CALLISTO Dashboard JavaScript
 */

// ================================
// Chinese Translation Mappings
// ================================

const ATTACK_TYPE_CN = {
    'rate_flood': '频率洪泛',
    'priv_escalation': '权限提升',
    'data_exfil': '数据外泄',
    'behavior_drift': '行为漂移',
    'temporal_violation': '时序违规',
    'state_poison': '状态投毒',
    'benign': '正常',
};

const SEVERITY_CN = {
    'critical': '严重',
    'high': '高危',
    'medium': '中危',
    'low': '低危',
    'info': '信息',
};

const SESSION_STATE_CN = {
    'OPEN': '已熔断',
    'CLOSED': '正常',
};

const TOOL_CHECK_STATUS_CN = {
    'ok': '安全',
    'completed': '安全',
    'warning': '警告',
    'blocked': '阻断',
};

const SCAN_CATEGORY_CN = {
    'script_analysis': '脚本分析',
    'url_check': 'URL 检查',
    'obfuscation': '代码混淆',
    'shell_pattern': 'Shell 模式',
    'shell_blacklist': 'Shell 黑名单',
    'path_check': '路径检查',
    'non_exec_tool': '非执行工具',
    'extended_tool': '扩展工具',
};

const EXPLANATION_PATTERNS = [
    { re: /^Chain of (\d+) consecutive sensitive tool calls/i, cn: '连续 $1 次敏感工具调用' },
    { re: /^Burst detected: (\d+) calls within ([\d.]+)s window/i, cn: '突发检测：$2 秒内 $1 次调用' },
    { re: /^Behavior shift: dangerous tools? appeared in second half/i, cn: '行为偏移：后半段出现危险工具' },
    { re: /^Pace shift:/i, cn: '节奏异常：' },
    { re: /^Suspicious ordering:/i, cn: '可疑排序：' },
    { re: /^write_file without prior read_file/i, cn: '未读取直接写入：' },
    { re: /^Potential data exfiltration via shell:/i, cn: '通过 Shell 潜在数据外泄：' },
    { re: /^Potential data exfiltration:/i, cn: '潜在数据外泄：' },
    { re: /^Sensitive file read detected:/i, cn: '敏感文件读取：' },
    { re: /^Sensitive file read via command:/i, cn: '通过命令读取敏感文件：' },
    { re: /^Internal network access detected:/i, cn: '内网访问检测：' },
    { re: /^Credential file access detected:/i, cn: '凭证文件访问：' },
    { re: /^Suspicious config modification:/i, cn: '可疑配置修改：' },
    { re: /^Suspicious write to persistent state:/i, cn: '可疑持久化状态写入：' },
    { re: /^Rate anomaly:/i, cn: '频率异常：' },
    { re: /^Privilege escalation:/i, cn: '权限提升：' },
    { re: /^Data exfiltration:/i, cn: '数据外泄：' },
    { re: /^Behavioral drift:/i, cn: '行为漂移：' },
    { re: /^Temporal violation:/i, cn: '时序违规：' },
    { re: /^State poisoning:/i, cn: '状态投毒：' },
    { re: /^Critical alert detected:/i, cn: '检测到严重告警：' },
    { re: /^Causal analysis identified/i, cn: '因果分析识别到' },
    { re: /^Download-and-execute chain/i, cn: '下载并执行链' },
    { re: /^Inline port binding/i, cn: '内联端口绑定（后门）' },
    { re: /^SQL injection with dynamic exec/i, cn: '动态执行 SQL 注入' },
    { re: /^Destructive content deletion via sed/i, cn: '通过 sed 破坏性删除内容' },
    { re: /^Git force push to remote/i, cn: 'Git 强制推送到远程' },
    { re: /^Git remote addition to unknown repository/i, cn: 'Git 添加未知远程仓库' },
    { re: /^Pipe-based data exfiltration/i, cn: '基于管道的数据外泄' },
    { re: /^Sudo permission enumeration/i, cn: 'Sudo 权限枚举' },
    { re: /^Script file not found/i, cn: '脚本文件未找到' },
    { re: /^Medium obfuscation score/i, cn: '中等混淆度' },
];

function translateExplanation(text) {
    if (!text) return text;
    for (const { re, cn } of EXPLANATION_PATTERNS) {
        const m = text.match(re);
        if (m) {
            // 如果有捕获组，用中文模板替换
            if (m.length > 1) {
                let result = cn;
                for (let i = 1; i < m.length; i++) {
                    result = result.replace('$' + i, m[i]);
                }
                // 保留正则匹配后面的原文（动态参数部分）
                const afterMatch = text.substring(m[0].length).trim();
                return result + (afterMatch ? afterMatch : '');
            }
            // 无捕获组：替换前缀，保留后面的内容
            const prefix = text.substring(0, m[0].length);
            const rest = text.substring(m[0].length);
            return cn + rest;
        }
    }
    return text;
}

function translateAttackType(type) {
    return ATTACK_TYPE_CN[type] || type;
}

function translateSeverity(sev) {
    return SEVERITY_CN[sev?.toLowerCase()] || sev;
}

function translateSessionState(state) {
    return SESSION_STATE_CN[state?.toUpperCase()] || state;
}

function translateToolCheckStatus(status) {
    return TOOL_CHECK_STATUS_CN[status] || status;
}

function translateScanCategory(cat) {
    return SCAN_CATEGORY_CN[cat] || cat;
}

// Full description/finding text translations from content_safety.py
const DESCRIPTION_CN = {
    // Network check messages
    'Non-HTTP protocol': '非 HTTP 协议',
    'Cloud metadata endpoint': '云元数据端点',
    'Private IP/localhost access': '私有 IP/本地访问',
    'Connection to denied domain': '连接被拒绝的域名',
    'Connection to unknown external domain': '连接未知外部域名',
    // Shell patterns
    'Reverse shell pattern': '反弹 Shell',
    'Piping remote content to shell': '远程内容管道至 Shell',
    'Credential file access': '凭证文件访问',
    'Shadow/credential file read': 'Shadow/凭证文件读取',
    'Cloud metadata endpoint (SSRF)': '云元数据端点 (SSRF)',
    'Cron/rc.local persistence': 'Cron/rc.local 持久化',
    'Base64 decode execution': 'Base64 解码执行',
    'Data exfiltration via POST': '通过 POST 数据外泄',
    'Paste/exfiltration sites': '粘贴/外泄站点',
    'Hardcoded IP address': '硬编码 IP 地址',
    'Write to /etc or /boot': '写入 /etc 或 /boot',
    'Dynamic __import__ or importlib': '动态导入模块',
    // Shell blacklist
    'Fork bomb pattern': 'Fork 炸弹',
    'Infinite loop pattern': '无限循环',
    'System shutdown/reboot': '系统关机/重启',
    'Kill all processes': '终止所有进程',
    'Disk formatting/partitioning': '磁盘格式化/分区',
    'Direct disk device access': '直接磁盘设备访问',
    'Privileged container / host mount': '特权容器/主机挂载',
    'Netcat reverse shell': 'Netcat 反弹 Shell',
    'Remote shell via telnet': '通过 Telnet 远程 Shell',
    'Private key enumeration': '私钥枚举',
    'Credential search': '凭证搜索',
    'Persistence via rc.local/crontab': '通过 rc.local/crontab 持久化',
    'Unsafe package installation': '不安全包安装',
    'Cron deletion': 'Cron 删除',
    'Suspicious remote file transfer': '可疑远程文件传输',
    'SysRq manipulation': 'SysRq 操作',
    'Kernel/memory access': '内核/内存访问',
    'Permission escalation': '权限提升',
    'Sensitive file manipulation': '敏感文件操作',
    'Dangerous environment variables': '危险环境变量',
    'Process hiding': '进程隐藏',
    'File permission escalation': '文件权限升级',
    'Environment tampering': '环境篡改',
    'Log tampering': '日志篡改',
    'SSH backdoor': 'SSH 后门',
    'SUID binary': 'SUID 二进制文件',
    'DNS tunneling': 'DNS 隧道',
    'Insecure curl/tar pipe': '不安全的 curl/tar 管道',
    'Wget to shell': 'Wget 管道至 Shell',
    // Tool param descriptions
    'Suspicious US bank account in recipient': '收款方可疑美国银行账户',
    'Suspicious IBAN in recipient': '收款方可疑 IBAN',
    'Unusually large transfer amount': '异常大额转账',
    'Suspicious US bank account in scheduled transfer': '定时转账可疑美国银行账户',
    'Recurring payment to external account': '向外部账户定期付款',
    'Phishing link in email body': '邮件正文钓鱼链接',
    'Email auto-forwarding instruction': '邮件自动转发指令',
    'Suspicious navigation link in email': '邮件可疑导航链接',
    'Gender-biased content manipulation': '性别偏见内容操作',
    'Instruction override in file content': '文件内容中的指令覆盖',
    'Misinformation content injection': '虚假信息注入',
    'Unrealistic revenue figure (possible data tampering)': '不现实收入数字（可能篡改数据）',
    'Unrealistic profit margin (possible data tampering)': '不现实利润率（可能篡改数据）',
    'External endpoint in financial record update': '财务记录更新中的外部端点',
    'Git force push detected': 'Git 强制推送',
    'Prompt injection in calendar event': '日历事件中的提示注入',
    'Urgent/phishing email subject': '紧急/钓鱼邮件主题',
    // Extended tool rules
    'Prompt injection attempt in search query': '搜索查询中的提示注入',
    'Secret extraction attempt in search query': '搜索查询中的密钥提取',
    'Data exfiltration instruction in search query': '搜索查询中的数据外泄指令',
    'Follow-link instruction in search query': '搜索查询中的跟随链接指令',
    'Prompt injection attempt in X search query': 'X 搜索查询中的提示注入',
    'Browser navigation to known exfiltration site': '浏览器导航至已知外泄站点',
    'Browser navigation to cloud metadata endpoint': '浏览器导航至云元数据端点',
    'Browser navigation to internal protocol': '浏览器导航至内部协议',
    'Suspicious browser action: potential data exfiltration': '可疑浏览器操作：可能数据外泄',
    'Prompt injection in code execution': '代码执行中的提示注入',
    'Data exfiltration pattern in code execution': '代码执行中的数据外泄模式',
    'Dangerous system call in code execution': '代码执行中的危险系统调用',
    'Sensitive file access in code execution': '代码执行中的敏感文件访问',
    'Internal network access in code execution': '代码执行中的内网访问',
    'Phishing link in message body': '消息正文中的钓鱼链接',
    'Prompt injection in message body': '消息正文中的提示注入',
    'Prompt injection in PDF text': 'PDF 文本中的提示注入',
    'Suspicious cron job': '可疑 Cron 任务',
    'Secret extraction in memory operation': '内存操作中的密钥提取',
    'Data exfiltration via memory': '通过内存数据外泄',
    'Prompt injection in session message': '会话消息中的提示注入',
    'Session spawn with sensitive arguments': '带有敏感参数的会话生成',
    'Node operation on sensitive path': '敏感路径上的节点操作',
    'Prompt injection in image generation': '图像生成中的提示注入',
    'Prompt injection in music generation': '音乐生成中的提示注入',
    'Prompt injection in video generation': '视频生成中的提示注入',
    'Prompt injection in TTS': 'TTS 中的提示注入',
    'Write to sensitive file': '写入敏感文件',
    'Patch application to sensitive file': '敏感文件的补丁应用',
    'Web fetch to suspicious URL': '可疑 URL 的 Web 抓取',
    // Obfuscation
    'Base64 decode piped to execution': 'Base64 解码管道至执行',
    'eval with command substitution': 'eval 与命令替换',
    'Hex escape sequences detected': '十六进制转义序列',
    // Sensitive path access
    'Sensitive path access': '敏感路径访问',
    'Sensitive path match': '敏感路径匹配',
    // Phishing patterns
    'Phishing pattern detected': '检测到钓鱼模式',
    // scan_config.py rule descriptions
    'No hardcoded API tokens': '检测到硬编码 API Token',
    'No hardcoded AWS credentials': '检测到硬编码 AWS 凭证',
    'No hardcoded GitHub tokens': '检测到硬编码 GitHub Token',
    'No localhost/127.0.0.1 allowed in production config': '生产配置中禁止 localhost/127.0.0.1',
    'No private IP ranges in production config': '生产配置中禁止私有 IP 段',
    'No cloud metadata service URLs': '检测到云元数据服务 URL',
    'No insecure HTTP URLs (use HTTPS)': '检测到不安全的 HTTP URL（建议使用 HTTPS）',
    'No open CORS origins': '检测到开放的 CORS 来源',
    'No internal domain patterns': '检测到内网域名模式',
    'No database connection strings with credentials': '检测到含凭证的数据库连接字符串',
    'Session tokens should expire': '会话 Token 应设置过期时间',
    'Secure cookie flag should be enabled': '应启用 Secure Cookie 标志',
    'HttpOnly cookie flag should be enabled': '应启用 HttpOnly Cookie 标志',
    'No plaintext passwords in config': '配置中禁止明文密码',
    'Encryption should be enabled': '应启用加密',
    'Debug mode should be disabled': '应禁用调试模式',
    'No untrusted plugin sources': '禁止不可信插件来源',
    'Plugin integrity verification': '插件完整性验证',
    'No unrestricted plugin permissions': '禁止无限制插件权限',
    'No shell execution in config': '配置中禁止 Shell 执行',
    'No dynamic code loading': '禁止动态代码加载',
    'No unsafe file operations': '禁止不安全文件操作',
    'Sandbox mode should be enabled': '应启用沙箱模式',
    'No unrestricted command execution': '禁止无限制命令执行',
    'Rate limiting should be enabled': '应启用速率限制',
    'Failed to read file': '读取文件失败',
    // Additional alert message patterns
    'Download-and-execute chain': '下载并执行链',
    'Inline port binding (backdoor)': '内联端口绑定（后门）',
    'SQL injection with dynamic exec': '动态执行 SQL 注入',
    'Destructive content deletion via sed': '通过 sed 破坏性删除内容',
    'Git force push to remote': 'Git 强制推送到远程',
    'Git remote addition to unknown repository': 'Git 添加未知远程仓库',
    'Pipe-based data exfiltration': '基于管道的数据外泄',
    'Sudo permission enumeration': 'Sudo 权限枚举',
    'Script file not found': '脚本文件未找到',
    'Medium obfuscation score': '中等混淆度',
    'Causal analysis identified': '因果分析识别到',
    // send_money, write_file, etc. tool names in alerts
    'send_money': '发送资金',
    'schedule_transaction': '定时转账',
    'write_file': '文件写入',
    'write_calendar_event': '写入日历事件',
    'send_email': '发送邮件',
    'update_financial_record': '更新财务记录',
};

const SEVERITY_PREFIX_CN = {
    '[CRITICAL]': '【严重】',
    '[HIGH]': '【高危】',
    '[MEDIUM]': '【中危】',
    '[LOW]': '【低危】',
};

function translateDescription(text) {
    if (!text) return text;

    // Handle [SEVERITY] prefix from content_safety findings
    let severityPrefix = '';
    let remaining = text;
    for (const [en, cn] of Object.entries(SEVERITY_PREFIX_CN)) {
        if (text.startsWith(en + ' ')) {
            severityPrefix = cn;
            remaining = text.slice(en.length).trim();
            break;
        }
    }

    // Exact match on remaining text
    if (DESCRIPTION_CN[remaining]) {
        return severityPrefix + DESCRIPTION_CN[remaining];
    }

    // Prefix match on remaining text
    for (const [en, cn] of Object.entries(DESCRIPTION_CN)) {
        if (remaining.startsWith(en)) {
            return severityPrefix + cn + remaining.slice(en.length);
        }
    }

    // No translation found, keep original (with translated prefix if any)
    return severityPrefix + remaining;
}

// ================================
// State
// ================================

let eventSource = null;
let isConnected = false;
let scanResults = null;
let logScanResults = null;
let vulnScanResult = null;
let vulnDbStats = null;
let openclawRunning = false;
let currentPage = 'dashboard';
let alertsCache = [];
let currentVulnMode = 'local';

// ================================
// DOM Elements
// ================================

let elements = {};

function initElements() {
    elements = {
        // Status
        statusBadge: document.getElementById('status-badge'),
        statusText: document.getElementById('status-text'),
        sidebarOcDot: document.getElementById('sidebar-oc-dot'),
        sidebarOcText: document.getElementById('sidebar-oc-text'),
        panicBanner: document.getElementById('panic-banner'),
        panicReason: document.getElementById('panic-reason'),
        btnResume: document.getElementById('btn-resume'),

        // Stats
        statTotal: document.getElementById('stat-total'),
        statCritical: document.getElementById('stat-critical'),
        statHigh: document.getElementById('stat-high'),
        statMedium: document.getElementById('stat-medium'),
        statLow: document.getElementById('stat-low'),

        // Dashboard
        alertListDash: document.getElementById('alert-list-dash'),
        alertListFull: document.getElementById('alert-list-full'),
        sessionList: document.getElementById('session-list'),
        sessionListFull: document.getElementById('session-list-full'),
        btnRefreshSessions: document.getElementById('btn-refresh-sessions'),
        btnRefreshSessions2: document.getElementById('btn-refresh-sessions2'),

        // Scan
        btnScan: document.getElementById('btn-scan'),
        scanType: document.getElementById('scan-type'),
        scanStatus: document.getElementById('scan-status'),
        btnRefreshScan: document.getElementById('btn-refresh-scan'),
        scanSummary: document.getElementById('scan-summary'),

        // Log scan
        logScanType: document.getElementById('log-scan-type'),
        logFileUpload: document.getElementById('log-file-upload'),
        btnLogScan: document.getElementById('btn-log-scan'),
        btnRefreshLogScan: document.getElementById('btn-refresh-log-scan'),
        logScanStatus: document.getElementById('log-scan-status'),
        logScanResultsSection: document.getElementById('log-scan-results-section'),
        logScanResults: document.getElementById('log-scan-results'),
        logScanStats: document.getElementById('log-scan-stats'),

        // Alerts
        btnRefreshAlerts: document.getElementById('btn-refresh-alerts'),
        btnClearAlerts: document.getElementById('btn-clear-alerts'),

        // Sessions
        historicalSessions: document.getElementById('historical-sessions'),
        historicalCount: document.getElementById('historical-count'),

        // Tool check
        toolName: document.getElementById('tool-name'),
        toolParams: document.getElementById('tool-params'),
        btnCheckTool: document.getElementById('btn-check-tool'),
        checkResult: document.getElementById('check-result'),
        resultBadge: document.getElementById('result-badge'),
        checkReason: document.getElementById('check-reason'),

        // Report
        reportType: document.getElementById('report-type'),
        reportFormat: document.getElementById('report-format'),
        reportHours: document.getElementById('report-hours'),
        reportSessionId: document.getElementById('report-session-id'),
        reportSeverity: document.getElementById('report-severity'),
        btnGenerateReport: document.getElementById('btn-generate-report'),

        // Vuln Scan
        vulnDbStats: document.getElementById('vuln-db-stats'),
        vulnVersionInput: document.getElementById('vuln-version-input'),
        vulnVersion: document.getElementById('vuln-version'),
        vulnUrlInput: document.getElementById('vuln-url-input'),
        vulnUrl: document.getElementById('vuln-url'),
        btnVulnScan: document.getElementById('btn-vuln-scan'),
        btnVulnRefresh: document.getElementById('btn-vuln-refresh'),
        vulnResultsCard: document.getElementById('vuln-results-card'),
        vulnResultsSummary: document.getElementById('vuln-results-summary'),
        vulnSeveritySummary: document.getElementById('vuln-severity-summary'),
        vulnResultsList: document.getElementById('vuln-results-list'),
    };
}

// ================================
// Navigation
// ================================

function navigateTo(page) {
    currentPage = page;
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const target = document.getElementById('page-' + page);
    if (target) target.classList.add('active');

    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navLink = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (navLink) navLink.classList.add('active');

    window.location.hash = page;
}

function initNav() {
    document.querySelectorAll('.nav-item').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            navigateTo(page);
        });
    });

    document.querySelectorAll('[data-nav]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(btn.dataset.nav);
        });
    });

    // Handle hash on load
    const hash = window.location.hash.slice(1);
    if (hash && document.getElementById('page-' + hash)) {
        navigateTo(hash);
    }
}

// ================================
// Utility Functions
// ================================

function formatDate(isoString) {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    return date.toLocaleString('zh-CN');
}

function getSeverityClass(severity) {
    const map = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'low',
    };
    return map[severity?.toLowerCase()] || 'low';
}

// ================================
// API Functions
// ================================

async function fetchStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        updateStatus(data);
    } catch (err) {
        console.error('Failed to fetch status:', err);
        setConnectionStatus(false);
    }
}

async function fetchStats() {
    try {
        const res = await fetch('/api/stats?hours=24');
        const data = await res.json();
        updateStats(data);
    } catch (err) {
        console.error('Failed to fetch stats:', err);
    }
}

async function fetchScanResults() {
    try {
        const res = await fetch('/api/scan/results');
        const data = await res.json();
        if (data.status === 'success') {
            scanResults = data.results;
            renderScanResults(scanResults);
        }
    } catch (err) {
        console.error('Failed to fetch scan results:', err);
    }
}

async function fetchAlerts() {
    try {
        const res = await fetch('/api/alerts?limit=50');
        const data = await res.json();
        if (data.status === 'success') {
            alertsCache = data.alerts;
            renderAlerts(data.alerts);
        }
    } catch (err) {
        console.error('Failed to fetch alerts:', err);
    }
}

async function fetchSessions() {
    if (!openclawRunning) {
        renderSessions([]);
        return;
    }
    try {
        const res = await fetch('/api/sessions');
        const data = await res.json();
        if (data.status === 'success') {
            renderSessions(data.sessions);
        }
    } catch (err) {
        console.error('Failed to fetch sessions:', err);
    }
}

async function runScan(scanType, force) {
    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_type: scanType, force }),
        });
        const data = await res.json();
        if (data.status === 'success') {
            await fetchScanResults();
            await fetchStats();
            showNotification('扫描完成', 'success');
        } else {
            showNotification('扫描失败：' + (data.detail || '未知错误'), 'error');
        }
    } catch (err) {
        showNotification('扫描失败：' + err.message, 'error');
    }
}

async function checkTool(toolName, params) {
    try {
        const paramsObj = typeof params === 'string' ? JSON.parse(params) : params;
        const res = await fetch(`/api/tool/check?tool_name=${encodeURIComponent(toolName)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(paramsObj),
        });
        const data = await res.json();
        return data;
    } catch (err) {
        return { status: 'error', error: err.message };
    }
}

async function generateReport(reportType, format, hours, sessionId, severity) {
    try {
        const params = new URLSearchParams();
        params.set('report_type', reportType || 'security');
        params.set('format', format || 'html');
        if (hours) params.set('hours', hours);
        if (sessionId) params.set('session_id', sessionId);
        if (severity) params.set('severity', severity);

        // Trigger browser download via hidden link
        const url = '/api/report/generate?' + params.toString();
        const link = document.createElement('a');
        link.href = url;
        link.download = '';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showNotification('报告生成中，请稍候...', 'success');
    } catch (err) {
        showNotification('报告生成失败：' + err.message, 'error');
    }
}

async function clearAlerts() {
    try {
        const res = await fetch('/api/alerts/clear', { method: 'DELETE' });
        const data = await res.json();
        if (data.status === 'success') {
            fetchAlerts();
            fetchStats();
            showNotification('告警已清空', 'success');
        }
    } catch (err) {
        showNotification('清空失败：' + err.message, 'error');
    }
}

async function scanSessionLogs() {
    try {
        elements.logScanStatus.classList.remove('hidden');
        const res = await fetch('/api/session-log/scan', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            renderSessionLogScanResults(data.sessions);
            showNotification('日志扫描完成', 'success');
        } else {
            showNotification('扫描失败：' + (data.detail || '未知错误'), 'error');
        }
    } catch (err) {
        showNotification('扫描失败：' + err.message, 'error');
    } finally {
        elements.logScanStatus.classList.add('hidden');
    }
}

async function uploadAndScan(file) {
    try {
        elements.logScanStatus.classList.remove('hidden');
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/session-log/upload-file', {
            method: 'POST',
            body: formData,
        });
        const data = await res.json();
        if (data.status === 'success') {
            renderSessionLogScanResults(data.sessions);
            showNotification('文件扫描完成', 'success');
        } else {
            showNotification('扫描失败：' + (data.detail || data.error || '未知错误'), 'error');
        }
    } catch (err) {
        showNotification('扫描失败：' + err.message, 'error');
    } finally {
        elements.logScanStatus.classList.add('hidden');
    }
}

// ================================
// Vuln Scan
// ================================

async function fetchVulnDbStats() {
    try {
        const res = await fetch('/api/vuln/stats');
        const data = await res.json();
        if (data.status === 'success') {
            vulnDbStats = data.stats;
            renderVulnDbStats(data.stats);
        }
    } catch (err) {
        console.error('Failed to fetch vuln stats:', err);
    }
}

function renderVulnDbStats(stats) {
    if (!elements.vulnDbStats) return;
    const sev = stats.by_severity || {};
    elements.vulnDbStats.innerHTML =
        `<span style="color:var(--text-secondary);font-size:0.8rem;">共 ${stats.total} 条规则 | ` +
        `<span class="scan-issue-severity critical" style="display:inline;">严重 ${sev.CRITICAL || 0}</span> ` +
        `<span class="scan-issue-severity high" style="display:inline;">高危 ${sev.HIGH || 0}</span> ` +
        `<span class="scan-issue-severity medium" style="display:inline;">中危 ${sev.MEDIUM || 0}</span> ` +
        `<span class="scan-issue-severity low" style="display:inline;">低危 ${sev.LOW || 0}</span></span>`;
}

async function runVulnScan(mode, version, url) {
    try {
        const body = { mode, is_internal: true };
        if (mode === 'version') body.version = version;
        if (mode === 'remote') { body.url = url; body.timeout = 5; }

        if (elements.btnVulnScan) {
            elements.btnVulnScan.textContent = '扫描中...';
            elements.btnVulnScan.disabled = true;
        }

        const res = await fetch('/api/vuln/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();

        if (data.status === 'success') {
            vulnScanResult = data.result;
            renderVulnResults(data.result);
        } else {
            showNotification('扫描失败：' + (data.detail || '未知错误'), 'error');
        }
    } catch (err) {
        showNotification('扫描失败：' + err.message, 'error');
    } finally {
        if (elements.btnVulnScan) {
            elements.btnVulnScan.textContent = '开始扫描';
            elements.btnVulnScan.disabled = false;
        }
    }
}

function renderVulnResults(result) {
    if (!elements.vulnResultsCard) return;
    elements.vulnResultsCard.style.display = 'block';

    const statusIcon = result.error ? '⚠️' : (result.vuln_count > 0 ? '🔴' : '✅');
    const versionText = result.detected_version === 'unknown' ? '无法检测版本' : `v${result.detected_version}`;
    elements.vulnResultsSummary.innerHTML =
        `<span style="font-size:0.85rem;">${statusIcon} ${result.target} — ${versionText} — ` +
        `发现 <strong style="color:var(--accent-danger);">${result.vuln_count}</strong> 条漏洞` +
        (result.error ? ` — <span style="color:var(--accent-warning);">${result.error}</span>` : '') +
        `</span>`;

    if (result.vulns && result.vulns.length > 0) {
        const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const v of result.vulns) {
            const s = (v.severity || 'low').toLowerCase();
            if (bySev[s] !== undefined) bySev[s]++;
        }
        elements.vulnSeveritySummary.innerHTML =
            `<div class="vuln-severity-bars">` +
            `<div class="vuln-bar critical"><span>严重</span><span>${bySev.critical}</span></div>` +
            `<div class="vuln-bar high"><span>高危</span><span>${bySev.high}</span></div>` +
            `<div class="vuln-bar medium"><span>中危</span><span>${bySev.medium}</span></div>` +
            `<div class="vuln-bar low"><span>低危</span><span>${bySev.low}</span></div>` +
            `</div>`;
    } else {
        elements.vulnSeveritySummary.innerHTML =
            '<p style="color:var(--accent-success);text-align:center;padding:16px;">✅ 未发现已知漏洞</p>';
    }

    if (result.vulns && result.vulns.length > 0) {
        let html = '';
        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        const sorted = result.vulns.slice().sort((a, b) =>
            (sevOrder[a.severity?.toLowerCase()] ?? 4) - (sevOrder[b.severity?.toLowerCase()] ?? 4)
        );
        for (const v of sorted) {
            const sev = v.severity?.toLowerCase() || 'low';
            html += `<div class="vuln-item ${sev}">`;
            html += `<div class="vuln-item-header" onclick="toggleVulnDetail(this)">`;
            html += `<div><span class="vuln-id">${v.id || v.cve}</span> `;
            html += `<span class="scan-issue-severity ${sev}">${translateSeverity(v.severity)}</span></div>`;
            html += `<span class="vuln-expand">▶</span>`;
            html += `</div>`;
            html += `<div class="vuln-item-body">`;
            html += `<div class="vuln-summary">${v.summary || ''}</div>`;
            html += `<div class="vuln-detail-section">${v.details || ''}</div>`;
            if (v.security_advise) {
                html += `<div class="vuln-advice"><strong>修复建议：</strong>${v.security_advise}</div>`;
            }
            if (v.references && v.references.length > 0) {
                html += `<div class="vuln-refs">`;
                for (const ref of v.references) {
                    html += `<a href="${ref}" target="_blank" class="vuln-ref">${ref.split('/').slice(0, 5).join('/')}/...</a> `;
                }
                html += `</div>`;
            }
            html += `</div></div>`;
        }
        elements.vulnResultsList.innerHTML = html;
    } else {
        elements.vulnResultsList.innerHTML =
            '<p style="text-align:center;color:var(--accent-success);padding:24px;">🎉 当前版本未发现已知漏洞</p>';
    }
}

function toggleVulnDetail(headerEl) {
    const body = headerEl.parentElement.querySelector('.vuln-item-body');
    const icon = headerEl.querySelector('.vuln-expand');
    if (body && icon) {
        body.classList.toggle('expanded');
        icon.style.transform = body.classList.contains('expanded') ? 'rotate(90deg)' : 'rotate(0deg)';
    }
}

// ================================
// Render Functions
// ================================

function updateStatus(data) {
    if (data.status === 'running') {
        setConnectionStatus(true);
    } else {
        setConnectionStatus(false);
    }

    if (data.panic_state === 'OPEN') {
        elements.panicBanner.classList.remove('hidden');
    } else {
        elements.panicBanner.classList.add('hidden');
    }

    if (data.openclaw_running !== undefined) {
        updateOpenclawStatus(data.openclaw_running);
    }
}

function updateOpenclawStatus(isRunning) {
    openclawRunning = isRunning;
    if (elements.sidebarOcDot) {
        elements.sidebarOcDot.className = 'sidebar-dot' + (isRunning ? ' running' : '');
    }
    if (elements.sidebarOcText) {
        elements.sidebarOcText.textContent = isRunning ? 'OpenClaw 运行中' : 'OpenClaw 未运行';
    }
    fetchHistoricalSessions();
}

function updateStats(data) {
    const bySeverity = data.by_severity || {};
    elements.statTotal.textContent = data.total_alerts || 0;
    elements.statCritical.textContent = bySeverity.critical || 0;
    elements.statHigh.textContent = bySeverity.high || 0;
    elements.statMedium.textContent = bySeverity.medium || 0;
    elements.statLow.textContent = bySeverity.low || 0;
}

function setConnectionStatus(connected) {
    if (!elements.statusText) return;
    isConnected = connected;
    const dot = elements.statusBadge.querySelector('.sidebar-dot');
    if (connected) {
        elements.statusText.textContent = '运行中';
        if (dot) dot.style.background = 'var(--accent-success)';
    } else {
        elements.statusText.textContent = '已断开';
        if (dot) dot.style.background = 'var(--accent-danger)';
    }
}

// ================================
// Render: Alerts
// ================================

function renderAlertItem(alert) {
    const severity = getSeverityClass(alert.severity);
    return `
        <div class="alert-item ${severity}">
            <div class="alert-header">
                <span class="alert-type">${translateAttackType(alert.attack_type || alert.category || 'unknown')}</span>
                <span class="alert-time">${formatDate(alert.timestamp)}</span>
            </div>
            <div class="alert-details">
                <span class="scan-issue-severity ${severity}">${translateSeverity(alert.severity)}</span>
                ${(() => {
                    const text = alert.explanation || alert.message || '';
                    return text ? `<span style="margin-left: 8px;">${translateDescription(translateExplanation(text))}</span>` : '';
                })()}
            </div>
        </div>
    `;
}

function renderAlerts(alerts) {
    alertsCache = alerts;

    // Dashboard list (top 5)
    if (elements.alertListDash) {
        if (!alerts || alerts.length === 0) {
            elements.alertListDash.innerHTML = '<p class="empty-message">暂无告警</p>';
        } else {
            let html = '';
            for (const alert of alerts.slice().reverse().slice(0, 5)) {
                html += renderAlertItem(alert);
            }
            elements.alertListDash.innerHTML = html;
        }
    }

    // Full list
    if (elements.alertListFull) {
        if (!alerts || alerts.length === 0) {
            elements.alertListFull.innerHTML = '<p class="empty-message">暂无告警</p>';
        } else {
            let html = '';
            for (const alert of alerts.slice().reverse()) {
                html += renderAlertItem(alert);
            }
            elements.alertListFull.innerHTML = html;
        }
    }
}

// ================================
// Render: Sessions
// ================================

function renderSessionItem(session) {
    const stateClass = session.state?.toLowerCase() === 'open' ? 'open' : 'closed';
    return `
        <div class="session-item">
            <div class="session-info">
                <div class="session-id">${session.session_id}</div>
                <div style="font-size: 0.78rem; color: var(--text-secondary);">
                    告警数：${session.consecutive_alerts || 0}
                </div>
            </div>
            <span class="session-state ${stateClass}">${translateSessionState(session.state || 'CLOSED')}</span>
        </div>
    `;
}

function renderSessions(sessions) {
    const html = (!sessions || sessions.length === 0)
        ? (!openclawRunning
            ? '<p class="empty-message">OpenClaw 未运行，无活跃会话</p>'
            : '<p class="empty-message">暂无活跃会话</p>')
        : sessions.map(renderSessionItem).join('');

    if (elements.sessionList) elements.sessionList.innerHTML = html;
    if (elements.sessionListFull) elements.sessionListFull.innerHTML = html;
}

// ================================
// Render: Historical Sessions
// ================================

async function fetchHistoricalSessions() {
    try {
        const [sessionsRes, alertsRes] = await Promise.all([
            fetch('/api/sessions/history'),
            fetch('/api/alerts?limit=10000')
        ]);
        const sessionsData = await sessionsRes.json();
        const alertsData = await alertsRes.json();

        if (sessionsData.status === 'success' && alertsData.status === 'success') {
            renderHistoricalSessions(sessionsData.sessions, alertsData.alerts);
        }
    } catch (err) {
        console.error('Failed to fetch historical sessions:', err);
    }
}

function renderHistoricalSessions(sessions, alerts) {
    if (!elements.historicalSessions) return;

    if (!sessions || sessions.length === 0) {
        elements.historicalSessions.innerHTML = '<p class="empty-message">暂无历史会话</p>';
        if (elements.historicalCount) elements.historicalCount.textContent = '';
        return;
    }

    const sorted = sessions
        .filter(s => s.last_activity)
        .sort((a, b) => new Date(b.last_activity) - new Date(a.last_activity));

    const alertsBySession = {};
    for (const alert of alerts) {
        const sid = alert.session_id;
        if (sid) {
            if (!alertsBySession[sid]) alertsBySession[sid] = [];
            alertsBySession[sid].push(alert);
        }
    }

    let html = '';
    for (const session of sorted) {
        const sessionAlerts = alertsBySession[session.session_id] || [];
        const hasAlerts = sessionAlerts.length > 0;
        const stateClass = session.state?.toLowerCase() === 'open' ? 'open' : 'closed';

        html += `<div class="historical-session-card ${hasAlerts ? 'has-alerts' : ''}">`;
        html += `<div class="historical-session-header" onclick="toggleHistoricalSession(this)">`;
        html += `<div class="historical-session-info">`;
        html += `<div class="historical-session-id">${session.session_id}</div>`;
        html += `<div class="historical-session-meta">`;
        html += `最后活动：${formatDate(session.last_activity)}`;
        if (session.tool_calls) html += ` | 工具调用：${session.tool_calls}`;
        html += `</div></div>`;
        html += `<span class="historical-session-badge ${stateClass}">${translateSessionState(session.state || 'CLOSED')}</span>`;
        if (hasAlerts) html += `<span class="historical-alert-count">${sessionAlerts.length} 告警</span>`;
        html += `<span class="historical-expand-icon">▶</span>`;
        html += `</div>`;
        html += `<div class="historical-session-alerts">`;

        if (hasAlerts) {
            for (const alert of sessionAlerts.slice().reverse()) {
                const severity = getSeverityClass(alert.severity);
                html += `<div class="historical-session-alert">`;
                html += `<div class="historical-alert-header">`;
                html += `<span class="historical-alert-type">${translateAttackType(alert.category || alert.attack_type || 'unknown')}</span>`;
                html += `<span class="historical-alert-time">${formatDate(alert.timestamp)}</span>`;
                html += `</div>`;
                html += `<span class="scan-issue-severity ${severity}" style="display:inline-block;margin-right:8px;">${translateSeverity(alert.severity)}</span>`;
                html += `<span class="historical-alert-message">${translateDescription(translateExplanation(alert.message || alert.explanation || ''))}</span>`;
                html += `</div>`;
            }
        } else {
            html += '<p style="color:var(--text-secondary);text-align:center;">无告警</p>';
        }

        html += `</div></div>`;
    }

    elements.historicalSessions.innerHTML = html;
    if (elements.historicalCount) {
        elements.historicalCount.textContent = `共 ${sorted.length} 个会话`;
    }
}

function toggleHistoricalSession(headerEl) {
    const alertsDiv = headerEl.parentElement.querySelector('.historical-session-alerts');
    const icon = headerEl.querySelector('.historical-expand-icon');
    if (alertsDiv && icon) {
        alertsDiv.classList.toggle('expanded');
        icon.classList.toggle('expanded');
    }
}

// ================================
// Render: Scan Results
// ================================

function renderScanResults(results) {
    const { config, skills, total_issues, last_scan_time, config_files_scanned, skills_files_scanned } = results;

    let html = '';

    if (config_files_scanned || skills_files_scanned) {
        html += '<div style="margin-bottom: 16px;">';
        html += '<details class="scanned-files-details">';
        html += `<summary class="scanned-files-summary">📁 已扫描文件（共 ${(config_files_scanned?.length || 0) + (skills_files_scanned?.length || 0)} 个）</summary>`;
        html += '<div class="scanned-files-list">';

        if (config_files_scanned && config_files_scanned.length > 0) {
            html += '<div class="file-group"><strong>配置文件：</strong></div>';
            for (const f of config_files_scanned) {
                html += `<div class="file-item">${f}</div>`;
            }
        }

        if (skills_files_scanned && skills_files_scanned.length > 0) {
            html += '<div class="file-group"><strong>技能文件：</strong></div>';
            for (const f of skills_files_scanned) {
                html += `<div class="file-item">${f}</div>`;
            }
        }

        html += '</div></details></div>';
    }

    if (total_issues === 0) {
        html += `<div style="text-align:center;padding:24px;color:var(--accent-success);font-size:1.1rem;">✅ 未发现安全问题</div>`;
        html += `<p style="text-align:center;color:var(--text-secondary);font-size:0.85rem;">上次扫描时间：${formatDate(last_scan_time)}</p>`;
        elements.scanSummary.innerHTML = html;
        return;
    }

    html += `<div style="margin-bottom:16px;"><strong>总问题数：</strong>${total_issues}<span style="color:var(--text-secondary);margin-left:16px;">上次扫描：${formatDate(last_scan_time)}</span></div>`;

    if (config && config.length > 0) {
        html += '<h4 style="margin:16px 0 8px;">配置文件问题</h4>';
        for (const issue of config) html += renderScanIssue(issue);
    }

    if (skills && skills.length > 0) {
        html += '<h4 style="margin:16px 0 8px;">技能代码问题</h4>';
        for (const issue of skills) html += renderScanIssue(issue);
    }

    elements.scanSummary.innerHTML = html;
}

function renderScanIssue(issue) {
    const severity = getSeverityClass(issue.severity);
    const label = issue.rule || issue.category;
    return `
        <div class="scan-issue ${severity}">
            <div class="scan-issue-header">
                <span class="scan-issue-rule">${translateScanCategory(label)}</span>
                <span class="scan-issue-severity ${severity}">${translateSeverity(issue.severity)}</span>
            </div>
            <div class="scan-issue-file">${issue.file || '未知文件'}</div>
            <div class="scan-issue-message">${translateDescription(translateExplanation(issue.message || issue.explanation || ''))}</div>
        </div>
    `;
}

// ================================
// Render: Log Scan Results
// ================================

function renderSessionLogScanResults(sessions) {
    if (!elements.logScanResultsSection || !elements.logScanResults) return;

    elements.logScanResultsSection.style.display = 'block';

    if (!sessions || sessions.length === 0) {
        elements.logScanResults.innerHTML = '<p class="empty-message">未检测到任何会话</p>';
        if (elements.logScanStats) elements.logScanStats.textContent = '';
        return;
    }

    let totalAlerts = 0, cleanCount = 0, riskCount = 0;
    let html = '';

    for (const session of sessions) {
        const alertCount = session.alert_count || 0;
        totalAlerts += alertCount;
        if (alertCount === 0) cleanCount++; else riskCount++;

        const hasAlerts = alertCount > 0;
        html += `<div class="log-scan-session">`;
        html += `<div class="log-scan-session-header" onclick="toggleLogScanSession(this)">`;
        html += `<div><div class="log-scan-session-id">${session.session_id}</div>`;
        html += `<div class="log-scan-session-meta">${session.file ? session.file.split('/').pop() : ''}`;
        if (session.time_first) {
            const tFirst = formatDate(session.time_first);
            const tLast = session.time_last ? formatDate(session.time_last) : '';
            html += ` | 数据时间：${tFirst}${tLast ? ' ~ ' + tLast : ''}`;
        }
        html += `</div></div>`;
        html += `<span class="log-scan-badge ${hasAlerts ? 'risk' : 'clean'}">${hasAlerts ? alertCount + ' 告警' : '无风险'}</span>`;
        html += `<span class="log-scan-expand-icon">▶</span>`;
        html += `</div>`;
        html += `<div class="log-scan-alerts">`;

        if (hasAlerts && session.alerts && session.alerts.length > 0) {
            for (const alert of session.alerts) {
                const severity = getSeverityClass(alert.severity);
                html += `<div class="log-scan-alert ${severity}">`;
                html += `<div class="log-scan-alert-header">`;
                html += `<span class="log-scan-alert-type">${translateAttackType(alert.attack_type || alert.category || 'unknown')}</span>`;
                html += `<span class="log-scan-alert-time">${alert.timestamp ? formatDate(alert.timestamp) : ''}</span>`;
                html += `</div>`;
                html += `<span class="scan-issue-severity ${severity}" style="display:inline-block;margin-right:8px;">${translateSeverity(alert.severity)}</span>`;
                html += `<span class="log-scan-alert-message">${translateDescription(translateExplanation(alert.explanation || alert.message || ''))}</span>`;
                html += `</div>`;
            }
        } else {
            html += '<p style="color:var(--text-secondary);text-align:center;">未检测到风险行为</p>';
        }

        html += `</div></div>`;
    }

    elements.logScanResults.innerHTML = html;
    if (elements.logScanStats) {
        elements.logScanStats.textContent = `共 ${sessions.length} 个会话，${cleanCount} 个安全，${riskCount} 个有风险，总计 ${totalAlerts} 条告警`;
    }
    logScanResults = sessions;
}

function toggleLogScanSession(headerEl) {
    const alertsDiv = headerEl.parentElement.querySelector('.log-scan-alerts');
    const icon = headerEl.querySelector('.log-scan-expand-icon');
    if (alertsDiv && icon) {
        alertsDiv.classList.toggle('expanded');
        icon.classList.toggle('expanded');
        icon.style.transform = alertsDiv.classList.contains('expanded') ? 'rotate(90deg)' : 'rotate(0deg)';
    }
}

// ================================
// UI Functions
// ================================

function showNotification(message, type = 'info') {
    console.log(`[${type.toUpperCase()}] ${message}`);

    // Create a toast notification
    const toast = document.createElement('div');
    const colors = { success: 'var(--accent-success)', error: 'var(--accent-danger)', info: 'var(--accent-primary)', warning: 'var(--accent-warning)' };
    toast.style.cssText = `
        position: fixed; top: 20px; right: 20px; padding: 12px 20px;
        background: var(--bg-card); color: ${colors[type] || colors.info};
        border: 1px solid ${colors[type] || colors.info}; border-radius: 8px;
        font-size: 0.85rem; z-index: 10000; max-width: 400px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        animation: slideInRight 0.3s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ================================
// Event Handlers
// ================================

function initEventHandlers() {
    // Scan
    elements.btnScan.addEventListener('click', () => {
        const scanType = elements.scanType.value;
        elements.scanStatus.classList.remove('hidden');
        runScan(scanType, true).finally(() => {
            elements.scanStatus.classList.add('hidden');
        });
    });

    elements.btnRefreshScan.addEventListener('click', fetchScanResults);

    // Alerts
    elements.btnRefreshAlerts.addEventListener('click', fetchAlerts);
    elements.btnClearAlerts.addEventListener('click', () => {
        if (confirm('确定要清空所有告警吗？')) clearAlerts();
    });

    // Sessions
    if (elements.btnRefreshSessions) elements.btnRefreshSessions.addEventListener('click', fetchSessions);
    if (elements.btnRefreshSessions2) elements.btnRefreshSessions2.addEventListener('click', fetchSessions);

    // Tool check
    elements.btnCheckTool.addEventListener('click', async () => {
        const toolName = elements.toolName.value.trim();
        const paramsStr = elements.toolParams.value.trim();

        if (!toolName) {
            showNotification('请输入工具名称', 'error');
            return;
        }

        elements.checkResult.classList.remove('hidden');
        elements.resultBadge.textContent = '检查中...';
        elements.resultBadge.className = 'result-badge';

        const result = await checkTool(toolName, paramsStr);

        if (result.status === 'success') {
            const data = result.result;
            if (data.status === 'ok' || data.status === 'completed') {
                elements.resultBadge.textContent = '✅ ' + translateToolCheckStatus(data.status);
                elements.resultBadge.className = 'result-badge ok';
            } else if (data.status === 'warning') {
                elements.resultBadge.textContent = '⚠️ ' + translateToolCheckStatus(data.status);
                elements.resultBadge.className = 'result-badge warning';
            } else if (data.status === 'blocked') {
                elements.resultBadge.textContent = '🚫 ' + translateToolCheckStatus(data.status);
                elements.resultBadge.className = 'result-badge blocked';
            }
            elements.checkReason.textContent = JSON.stringify(data, null, 2);
        } else {
            elements.resultBadge.textContent = '❌ 错误';
            elements.resultBadge.className = 'result-badge';
            elements.checkReason.textContent = result.error || '未知错误';
        }
    });

    // Resume
    elements.btnResume.addEventListener('click', () => {
        showNotification('恢复功能开发中', 'info');
    });

    // Log scan
    elements.btnLogScan.addEventListener('click', async () => {
        const scanType = elements.logScanType.value;
        if (scanType === 'upload') {
            if (!elements.logFileUpload.files || elements.logFileUpload.files.length === 0) {
                showNotification('请先选择文件', 'error');
                return;
            }
            elements.btnLogScan.textContent = '扫描中...';
            elements.btnLogScan.disabled = true;
            try {
                await uploadAndScan(elements.logFileUpload.files[0]);
            } finally {
                elements.btnLogScan.textContent = '开始扫描';
                elements.btnLogScan.disabled = false;
            }
        } else {
            elements.btnLogScan.textContent = '扫描中...';
            elements.btnLogScan.disabled = true;
            try {
                await scanSessionLogs();
            } finally {
                elements.btnLogScan.textContent = '开始扫描';
                elements.btnLogScan.disabled = false;
            }
        }
    });

    if (elements.btnRefreshLogScan) {
        elements.btnRefreshLogScan.addEventListener('click', scanSessionLogs);
    }

    elements.logScanType.addEventListener('change', () => {
        if (elements.logScanType.value === 'upload') {
            elements.logFileUpload.classList.remove('hidden');
        } else {
            elements.logFileUpload.classList.add('hidden');
        }
    });

    // Report generation
    if (elements.btnGenerateReport) {
        elements.btnGenerateReport.addEventListener('click', () => {
            const reportType = elements.reportType.value;
            const format = elements.reportFormat.value;
            const hours = elements.reportHours?.value || '';
            const sessionId = elements.reportSessionId?.value?.trim() || '';
            const severity = elements.reportSeverity?.value || '';
            generateReport(reportType, format, hours, sessionId, severity);
        });
    }

    // Quick export buttons (config scan & log scan pages)
    document.querySelectorAll('.btn-export[data-report-type]').forEach(btn => {
        btn.addEventListener('click', () => {
            const reportType = btn.dataset.reportType;
            const format = btn.dataset.format;
            generateReport(reportType, format);
        });
    });

    // Vuln Scan mode switching
    document.querySelectorAll('.vuln-mode-btn[data-mode]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.vuln-mode-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentVulnMode = btn.dataset.mode;

            if (elements.vulnVersionInput) elements.vulnVersionInput.classList.toggle('hidden', currentVulnMode !== 'version');
            if (elements.vulnUrlInput) elements.vulnUrlInput.classList.toggle('hidden', currentVulnMode !== 'remote');
        });
    });

    // Vuln Scan button
    if (elements.btnVulnScan) {
        elements.btnVulnScan.addEventListener('click', () => {
            let version = '';
            let url = '';
            if (currentVulnMode === 'version') {
                version = elements.vulnVersion?.value?.trim();
                if (!version) { showNotification('请输入版本号', 'error'); return; }
            } else if (currentVulnMode === 'remote') {
                url = elements.vulnUrl?.value?.trim();
                if (!url) { showNotification('请输入 URL', 'error'); return; }
            }
            runVulnScan(currentVulnMode, version, url);
        });
    }

    // Vuln refresh button
    if (elements.btnVulnRefresh) {
        elements.btnVulnRefresh.addEventListener('click', () => {
            if (vulnScanResult) {
                renderVulnResults(vulnScanResult);
            } else {
                runVulnScan(currentVulnMode, '', '');
            }
        });
    }
}

// ================================
// SSE Event Source
// ================================

function initEventSource() {
    if (eventSource) eventSource.close();

    eventSource = new EventSource('/api/events');

    eventSource.addEventListener('heartbeat', () => {
        setConnectionStatus(true);
    });

    eventSource.addEventListener('alert', () => {
        fetchAlerts();
        fetchStats();
    });

    eventSource.onerror = () => {
        setConnectionStatus(false);
        eventSource.close();
        setTimeout(initEventSource, 5000);
    };
}

// ================================
// Initialization
// ================================

async function init() {
    console.log('[CALLISTO] app.js v22 loaded — translations:', Object.keys(DESCRIPTION_CN).length, 'descriptions,', Object.keys(ATTACK_TYPE_CN).length, 'attack types');
    initElements();
    initNav();
    initEventHandlers();
    initEventSource();

    await fetchStatus();
    await fetchStats();
    await fetchScanResults();
    await fetchAlerts();
    await fetchSessions();
    await fetchVulnDbStats();

    setInterval(fetchStats, 30000);
    setInterval(fetchSessions, 10000);
    setInterval(fetchHistoricalSessions, 60000);
    setInterval(fetchStatus, 15000);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
