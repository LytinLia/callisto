# CALLISTO 核心安全功能调用时机

**版本**: v2.0  
**生成日期**: 2026-04-23  
**文档位置**: `/Users/jiangqiang/.openclaw/extensions/callisto-plugin/CALLISTO_CALL_TIMING.md`

---

## 一、调用时机总览

```
OpenClaw 启动 → 配置/技能扫描 → 用户对话 → 工具调用 → 实时检测 → 响应处理
     ↓              ↓              ↓           ↓           ↓          ↓
  插件加载     文件哈希检查    用户请求    参数脱敏    8 类检测   熔断器更新
```

### 调用阶段

| 阶段 | 触发时机 | 调用功能 |
|------|----------|----------|
| **阶段 1** | OpenClaw 启动 | 配置文件扫描、技能代码扫描、引擎初始化 |
| **阶段 2** | 每次工具调用 | 参数脱敏、8 类检测、熔断器更新 |
| **阶段 3** | 文件变化时 | 配置/技能重新扫描 |
| **阶段 4** | 手动调用 | 按需扫描、工具检查 |
| **阶段 5** | Web Dashboard | 监控面板、实时推送 |

---

## 二、OpenClaw 启动时

### 触发时机

OpenClaw 进程启动，加载 `callisto-skill` 插件时。

### 调用流程

```
OpenClaw 启动
    ↓
加载 callisto-skill 插件 (openclaw.plugin.json 配置)
    ↓
执行 openclaw_plugin/callisto-skill/src/index.js
    ↓
调用 initialize() 函数
    ↓
执行 startup_scan 动作
    ↓
调用 auto_scanner.py:scan_all()
    ↓
扫描配置文件 + 技能代码
    ↓
输出结果到 OpenClaw 日志
```

### 调用功能详情

| 功能 | 调用方式 | 代码位置 |
|------|----------|----------|
| **配置文件扫描** | 插件初始化时自动调用 | `openclaw_plugin/callisto-skill/src/index.js` → `initialize()` |
| **技能代码扫描** | 插件初始化时自动调用 | `openclaw_plugin/callisto-skill/src/index.js` → `initialize()` |
| **检测引擎初始化** | 创建 CallistoAgent 实例 | `callisto_agent.py` → `__init__()` 第 173-201 行 |
| **脱敏器初始化** | 创建 CallistoAgent 实例 | `callisto_agent.py` → `__init__()` 第 192-196 行 |
| **熔断器初始化** | 创建 CallistoAgent 实例 | `callisto_agent.py` → `__init__()` 第 176 行 |

### 输出示例

```
[CALLISTO] 启动时自动扫描配置文件和技能代码...
[CALLISTO] 引擎已初始化，脱敏器已启用
[CALLISTO] ✓ 安全检查通过（配置：0 问题，技能：0 问题）
```

### 代码示例

**openclaw_plugin/callisto-skill/src/index.js**:
```javascript
async function initialize() {
  try {
    console.log('[CALLISTO] 启动时自动扫描配置文件和技能代码...');
    const result = await callCallisto('startup_scan');

    if (result.status === 'completed') {
      const configIssues = result.scan_result?.config_scan?.issues?.length || 0;
      const skillsIssues = result.scan_result?.skills_scan?.issues?.length || 0;
      console.log(`[CALLISTO] ✓ 安全检查通过（配置：${configIssues} 问题，技能：${skillsIssues} 问题）`);
    }
  } catch (err) {
    console.error(`[CALLISTO] 启动扫描失败：${err.message}`);
  }
}

// 插件加载时自动执行
initialize().catch(console.error);
```

---

## 三、工具调用时（核心检测）

### 触发时机

OpenClaw 准备执行**任何工具**（exec、read_file、http_request、write_file 等）时。

### 调用流程

```
用户请求
    ↓
OpenClaw 准备调用工具
    ↓
拦截 → callisto_agent.detect(tool_name, parameters, session_id)
    ↓
┌─────────────────────────────────────────────────────────┐
│  detect() 检测流程:                                      │
│  1. 检查熔断器状态 (CLOSED/BLOCKED)                      │
│  2. 参数脱敏处理 (15 类敏感信息)                           │
│  3. 创建会话事件并添加到会话历史                          │
│  4. 引擎分析 (8 类攻击检测)                               │
│  5. 更新熔断器 (HIGH 告警计数 +1)                         │
│  6. 返回检测结果 (ok/warning/blocked)                    │
└─────────────────────────────────────────────────────────┘
    ↓
status="ok" → 执行工具
status="warning" → 显示风险提示后执行
status="blocked" → 阻断操作
```

### 调用功能详情

| 功能 | 调用时机 | 代码位置 | 延迟 |
|------|----------|----------|------|
| **熔断器检查** | detect() 入口 | `callisto_agent.py` 第 257-266 行 | <1ms |
| **参数脱敏** | 工具参数处理 | `callisto_agent.py` 第 290-294 行 | <1ms |
| **速率洪水检测** | 每次工具调用 | `callisto_agent.py` 第 331-346 行 | <1ms |
| **命令安全检查** | exec/shell 工具 | `callisto_agent.py` 第 354-372 行 | <5ms |
| **敏感文件检测** | read_file 工具 | `callisto_agent.py` 第 375-381 行 | <2ms |
| **内网访问检测** | http_request 工具 | `callisto_agent.py` 第 384-390 行 | <2ms |
| **引擎分析** | 完整会话分析 | `callisto_agent.py` 第 298 行 | <50ms |
| **熔断器更新** | 检测到 HIGH 告警后 | `callisto_agent.py` 第 301-304 行 | <1ms |

### 代码示例

**callisto_agent.py:detect()**:
```python
def detect(self, tool_name: str, parameters: Dict, session_id: str) -> DetectResult:
    breaker = self.get_breaker(session_id)

    # ========== 1. 检查熔断器状态 ==========
    if breaker.should_block():
        return DetectResult(
            status="blocked",
            session_id=session_id,
            alerts=[],
            circuit_breaker="OPEN",
            message=f"Session blocked: {breaker._consecutive_alerts} consecutive HIGH risk operations"
        )

    # ========== 2. 初始化会话告警计数 ==========
    if session_id not in self.session_alert_counts:
        self.session_alert_counts[session_id] = 0

    # ========== 3. 使用完整引擎分析 ==========
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

        # ========== 4. 脱敏处理 ==========
        if self.sanitizer:
            for key, value in parameters.items():
                if isinstance(value, str):
                    parameters[key] = self.sanitizer.sanitize(value)

        # ========== 5. 引擎分析 ==========
        alerts = self.engine.analyze_session(session)

        # ========== 6. 更新熔断器 ==========
        for alert in alerts:
            if alert.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                breaker.record_alert(alert)
                self.session_alert_counts[session_id] += 1

        # 返回结果
        return DetectResult(
            status="warning" if alerts else "ok",
            session_id=session_id,
            alerts=alert_dicts,
            circuit_breaker=breaker.state,
            consecutive_alerts=breaker._consecutive_alerts
        )
```

### 检测结果处理

| 状态 | 说明 | OpenClaw 处理 |
|------|------|--------------|
| `status="ok"` | 无风险 | 直接执行工具 |
| `status="warning"` | 低风险 | 显示提示后执行 |
| `status="blocked"` | 熔断状态 | 阻断操作，拒绝执行 |

---

## 四、文件变化时（监控模式）

### 触发时机

运行 `auto_scanner.py --watch` 时，定期检测文件变化。

### 调用流程

```
启动监控模式 (--watch 60)
    ↓
首次完整扫描 (scan_all)
    ↓
进入监控循环 (每 60 秒)
    ↓
计算所有文件的 MD5 哈希
    ↓
与缓存中的哈希对比
    ↓
发现变化 → 调用 scan_all(force=False)
    ↓
生成新报告 → 更新缓存
```

### 调用功能详情

| 功能 | 触发条件 | 代码位置 |
|------|----------|----------|
| **配置文件扫描** | 配置文件哈希变化 | `auto_scanner.py:watch()` 第 292-310 行 |
| **技能代码扫描** | 技能文件哈希变化 | `auto_scanner.py:watch()` 第 292-310 行 |
| **文件哈希计算** | 每次检查 | `auto_scanner.py:_get_file_hash()` 第 91-97 行 |
| **缓存更新** | 扫描完成后 | `auto_scanner.py:_save_cache()` 第 82-89 行 |

### 输出示例

```
$ python scripts/auto_scanner.py --watch 60

[11:45:39] 开始监控（每 60 秒检查一次）...
[11:46:39] 无变化
[11:47:39] 无变化
[11:48:39] 检测到文件变化，重新扫描...
======================================================================
CALLISTO 完整安全扫描
======================================================================
扫描完成：发现 0 个问题
[11:48:40] 无变化
```

---

## 五、手动调用

### 触发时机

用户主动执行命令行或 Web Dashboard 操作。

### 命令行调用

| 命令 | 调用功能 | 代码位置 |
|------|----------|----------|
| `python scripts/auto_scanner.py --scan-all` | 完整扫描（配置 + 技能） | `auto_scanner.py:main()` 第 429-430 行 |
| `python scripts/auto_scanner.py --scan-config` | 仅配置扫描 | `auto_scanner.py:main()` 第 423-425 行 |
| `python scripts/auto_scanner.py --scan-skills` | 仅技能扫描 | `auto_scanner.py:main()` 第 426-428 行 |
| `python scripts/auto_scanner.py --watch 60` | 监控模式 | `auto_scanner.py:main()` 第 419-420 行 |
| `python scripts/auto_scanner.py --on-startup` | 启动扫描 | `auto_scanner.py:main()` 第 421-422 行 |
| `python scripts/auto_scanner.py --force` | 强制扫描（忽略缓存） | `auto_scanner.py:main()` 第 412 行 |

### Web Dashboard 调用

| 操作 | 调用功能 | API 端点 |
|------|----------|----------|
| 打开 Dashboard | 获取服务状态 | `GET /api/status` |
| 查看统计 | 获取 24h 统计 | `GET /api/stats?hours=24` |
| 点击"开始扫描" | 运行安全扫描 | `POST /api/scan` |
| 查看扫描结果 | 获取扫描结果 | `GET /api/scan/results` |
| 查看告警 | 获取告警列表 | `GET /api/alerts?limit=50` |
| 清空告警 | 清空告警历史 | `DELETE /api/alerts/clear` |
| 检查工具 | 检查工具调用风险 | `POST /api/tool/check` |
| SSE 连接 | 实时事件推送 | `GET /api/events` |

### 代码示例

**Web Dashboard 扫描调用**:
```javascript
// web/static/js/app.js
async function runScan(scanType, force) {
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
    }
}

// 绑定按钮事件
elements.btnScan.addEventListener('click', () => {
    const scanType = elements.scanType.value;
    const force = elements.scanForce.checked;
    elements.scanStatus.classList.remove('hidden');
    runScan(scanType, force).finally(() => {
        elements.scanStatus.classList.add('hidden');
    });
});
```

---

## 六、完整调用链路

### 场景 1: OpenClaw 启动

```
┌─────────────────────────────────────────────────────────────┐
│ 1. OpenClaw 启动                                             │
├─────────────────────────────────────────────────────────────┤
│ 1. openclaw 命令执行                                         │
│    ↓                                                         │
│ 2. 读取 openclaw.plugin.json                                 │
│    ↓                                                         │
│ 3. 加载 callisto-plugin                                      │
│    ↓                                                         │
│ 4. 执行 openclaw_plugin/callisto-skill/src/index.js          │
│    ↓                                                         │
│ 5. 调用 initialize()                                         │
│    ↓                                                         │
│ 6. 调用 startup_scan 动作                                     │
│    ↓                                                         │
│ 7. 加载 auto_scanner.py                                      │
│    ↓                                                         │
│ 8. 执行 scanner.scan_all(force=True)                         │
│    ↓                                                         │
│ 9. 扫描配置文件 (scan_config.py)                             │
│    ↓                                                         │
│ 10. 扫描技能代码 (scan_skills.py)                            │
│    ↓                                                         │
│ 11. 生成扫描报告                                             │
│    ↓                                                         │
│ 12. 输出结果到日志：                                         │
│    [CALLISTO] ✓ 安全检查通过                                │
└─────────────────────────────────────────────────────────────┘
```

---

### 场景 2: 良性命令执行

```
┌─────────────────────────────────────────────────────────────┐
│ 2. 用户请求"执行 ls -la"                                      │
├─────────────────────────────────────────────────────────────┤
│ 1. 用户输入："帮我列出当前目录文件"                           │
│    ↓                                                         │
│ 2. OpenClaw 调用 exec 工具                                    │
│    ↓                                                         │
│ 3. callisto_agent.detect("exec", {"command": "ls -la"})     │
│    ↓                                                         │
│ 4. 检查熔断器 → CLOSED (正常)                                │
│    ↓                                                         │
│ 5. 脱敏器.sanitize("ls -la") → 无敏感信息                    │
│    ↓                                                         │
│ 6. 引擎分析会话                                              │
│    ↓                                                         │
│ 7. 检测命令模式 → 匹配良性命令白名单                         │
│    ↓                                                         │
│ 8. 无告警生成                                                │
│    ↓                                                         │
│ 9. 返回 status="ok"                                          │
│    ↓                                                         │
│ 10. OpenClaw 执行 "ls -la"                                   │
│    ↓                                                         │
│ 11. 返回结果给用户                                           │
└─────────────────────────────────────────────────────────────┘
```

---

### 场景 3: 危险命令检测

```
┌─────────────────────────────────────────────────────────────┐
│ 3. 用户请求"执行 sudo su -"                                   │
├─────────────────────────────────────────────────────────────┤
│ 1. 用户输入："帮我获取 root 权限"                              │
│    ↓                                                         │
│ 2. OpenClaw 调用 exec 工具                                    │
│    ↓                                                         │
│ 3. callisto_agent.detect("exec", {"command": "sudo su -"})  │
│    ↓                                                         │
│ 4. 检查熔断器 → CLOSED (正常)                                │
│    ↓                                                         │
│ 5. 脱敏器处理参数                                            │
│    ↓                                                         │
│ 6. 引擎分析会话                                              │
│    ↓                                                         │
│ 7. 检测命令模式 → 匹配提权命令模式                           │
│    patterns: [r"sudo\s+su\s*-", r"sudo\s+-i", ...]          │
│    ↓                                                         │
│ 8. 生成告警：priv_escalation (HIGH, 0.95)                    │
│    ↓                                                         │
│ 9. 熔断器.record_alert() → _consecutive_alerts = 1          │
│    ↓                                                         │
│ 10. 返回 status="warning" + 告警详情                         │
│    ↓                                                         │
│ 11. OpenClaw 显示风险提示："检测到提权命令"                   │
│    ↓                                                         │
│ 12. 用户决定是否继续                                         │
└─────────────────────────────────────────────────────────────┘
```

---

### 场景 4: 熔断器触发

```
┌─────────────────────────────────────────────────────────────┐
│ 4. 连续 3 次 HIGH 告警 → 熔断器触发                            │
├─────────────────────────────────────────────────────────────┤
│ 第 1 次 HIGH 告警:                                             │
│   detect() → 告警：priv_escalation (HIGH)                   │
│   breaker._consecutive_alerts = 1                           │
│   ↓                                                         │
│ 第 2 次 HIGH 告警:                                             │
│   detect() → 告警：data_exfil (HIGH)                        │
│   breaker._consecutive_alerts = 2                           │
│   ↓                                                         │
│ 第 3 次 HIGH 告警:                                             │
│   detect() → 告警：internal_access (HIGH)                   │
│   breaker._consecutive_alerts = 3                           │
│   breaker.state = "OPEN"                                    │
│   ↓                                                         │
│ 第 4 次调用:                                                   │
│   detect() → 检查熔断器                                     │
│   breaker.should_block() → True                             │
│   返回 status="blocked"                                     │
│   OpenClaw 阻断操作："Session blocked"                       │
│   ↓                                                         │
│ 恢复：需要调用 engine.resume()                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 七、调用频率与性能

### 调用频率

| 功能 | 触发频率 | 典型场景 |
|------|----------|----------|
| 启动扫描 | OpenClaw 启动时 | 每天 1-2 次 |
| 参数脱敏 | 每次工具调用 | 每分钟 10-100 次 |
| 速率洪水检测 | 每次工具调用 | 每分钟 10-100 次 |
| 命令安全检查 | exec 工具调用 | 每分钟 5-50 次 |
| 敏感文件检测 | read_file 工具调用 | 每分钟 1-10 次 |
| 内网访问检测 | http_request 工具调用 | 每分钟 1-5 次 |
| 引擎分析 | 每次工具调用 | 每分钟 10-100 次 |
| 熔断器更新 | 检测到告警后 | 每小时 0-10 次 |
| 监控扫描 | 文件变化时 | 每小时 0-5 次 |

### 性能指标

| 功能 | 延迟 | 说明 |
|------|------|------|
| 参数脱敏 | <1ms | 正则替换 |
| 速率洪水检测 | <1ms | 时间戳对比 |
| 命令安全检查 | <5ms | 模式匹配 |
| 敏感文件检测 | <2ms | 路径匹配 |
| 内网访问检测 | <2ms | IP/域名匹配 |
| 引擎分析 | <50ms | 完整会话分析 |
| 熔断器更新 | <1ms | 计数器 +1 |

### 总体性能影响

```
单次工具调用总延迟：<60ms
对 OpenClaw 响应影响：可忽略不计
内存占用：~50MB
```

---

## 八、关键代码位置索引

| 功能 | 文件 | 行号 |
|------|------|------|
| **启动扫描调用** | `openclaw_plugin/callisto-skill/src/index.js` | 75-95 |
| **启动扫描处理** | `openclaw_plugin/callisto-skill/python/callisto_agent.py` | 451-470 |
| **检测入口** | `callisto_agent.py` | 245-407 |
| **熔断器检查** | `callisto_agent.py` | 257-266 |
| **参数脱敏** | `callisto_agent.py` | 290-294 |
| **速率洪水检测** | `callisto_agent.py` | 331-346 |
| **命令安全检查** | `callisto_agent.py` | 354-372 |
| **敏感文件检测** | `callisto_agent.py` | 375-381 |
| **内网访问检测** | `callisto_agent.py` | 384-390 |
| **熔断器更新** | `callisto_agent.py` | 301-304 |
| **自动扫描器** | `scripts/auto_scanner.py` | 230-270 |
| **配置扫描** | `scripts/scan_config.py` | 313-366 |
| **技能扫描** | `scripts/scan_skills.py` | 253-299 |
| **Web 扫描 API** | `web_server.py` | 148-180 |
| **Web 工具检查 API** | `web_server.py` | 248-264 |
| **SSE 事件推送** | `web_server.py` | 216-243 |

---

## 九、总结

### 调用时机总结

| 时机 | 调用功能 | 自动化程度 |
|------|----------|------------|
| **OpenClaw 启动** | 配置/技能扫描、引擎初始化 | ✅ 自动 |
| **工具调用** | 脱敏、检测、熔断器更新 | ✅ 自动 |
| **文件变化** | 配置/技能重新扫描 | ⚠️ 监控模式自动 |
| **手动调用** | 按需扫描、工具检查 | ❌ 手动 |
| **Web Dashboard** | 监控、推送、检查 | ⚠️ 半自动 |

### 核心调用链路

```
用户请求 → OpenClaw → callisto_agent.detect() → 检测 → 执行/阻断
                           ↓
                    1. 熔断器检查
                    2. 参数脱敏
                    3. 创建事件
                    4. 引擎分析
                    5. 更新熔断器
                           ↓
                    返回结果 (ok/warning/blocked)
```

### 自动化程度

- **95% 自动**: 用户无需手动调用任何功能
- **5% 可选**: Web Dashboard、手动扫描（按需使用）

---

**文档版本**: v1.0  
**最后更新**: 2026-04-23  
**维护者**: CALLISTO Team
