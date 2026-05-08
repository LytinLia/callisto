# CALLISTO 项目功能与检测逻辑总结

## 1. 项目定位

CALLISTO 是一个针对 OpenClaw Agent 的**实时安全检测插件**，专门防御**间接提示注入攻击**（Indirect Prompt Injection）。采用**旁路检测**架构 —— 不修改 Agent 工具链，不依赖人工审批，全自动运行。

---

## 2. 核心功能

### 2.1 七层检测体系

| 层次 | 功能 | 检测对象 | 触发时机 |
|------|------|---------|---------|
| **L1 — 内容安全** | `ContentSafetyDetector` | 工具调用参数、脚本内容、URL、注入文本 | 每次工具调用 |
| **L2 — 引擎分析** | `CallistoEngine` | 会话级工具调用序列 | 每次工具调用后 |
| **L3 — 因果图分析** | `CausalResponsibilityScorer` | 工具调用 DAG，识别危险链 | 引擎分析时 |
| **L4 — 时序检测** | `MABOCPD` | 调用频率、行为漂移 | 引擎分析时 |
| **L5 — 脱敏处理** | `Sanitizer` | 工具输出中的 API Key、Token 等 | 工具返回后 |
| **L6 — 自动熔断** | `CircuitBreaker` | 连续 HIGH 告警自动阻断会话 | 告警累积时 |
| **L7 — 告警排序** | `AlertRanker` | 告警优先级排序、解释生成 | 产生告警后 |

### 2.2 检测的攻击类型

| 类型 | 代号 | 检测手段 |
|------|------|---------|
| **速率洪水** | A1 | 滑动窗口内调用频率异常（≥8 次/5 秒） |
| **权限升级** | A2 | 恶意命令匹配、提权命令、危险脚本执行 |
| **数据外泄** | A3 | 上传模式（`curl -d @`）、敏感文件读取、网络外发 |
| **行为漂移** | A4 | 工具调用分布与基线偏离（结构特征分析） |
| **时序违例** | A5 | 调用间隔分布异常（`MABOCPD` 变点检测） |
| **状态投毒** | A6 | 敏感配置文件修改（`.bashrc`、SSH 配置、Crontab 等） |
| **敏感文件读取** | P1/D1 | 路径匹配（`.ssh`、`.aws`、`credentials` 等） |
| **内网访问** | L1/L2 | 私有 IP 段匹配、云元数据端点检测 |
| **凭证文件访问** | L3 | 密钥文件、Token 文件路径匹配 |
| **提示词注入** | — | 输入文本检测（中英文 15+ 条规则） |
| **输出外泄** | — | 输出文本检测（API Key、密码、私钥、信用卡等） |
| **非 Exec 工具风险** | — | 26 个 OpenClaw 内置工具的参数级风险检测 |

---

## 3. 项目结构

```
callisto-plugin/
├── callisto/                          # 核心检测引擎（Python 库）
│   ├── engine.py                      # 主引擎：串联所有检测层
│   ├── content_safety.py              # 内容安全检测（1246 行）
│   ├── sanitizer.py                   # 敏感信息脱敏（15 类模式）
│   ├── config.py                      # 全局配置
│   ├── collector/                     # 事件收集器
│   │   ├── models.py                  # 数据模型：CallEvent, Session, Alert
│   │   ├── interceptor.py             # 事件拦截器
│   │   └── openclaw_parser.py         # OpenClaw 日志解析器
│   ├── features/                      # 特征提取
│   │   ├── temporal.py                # 时序特征（频率、突发性、周期性）
│   │   ├── structural.py              # 结构特征（调用 DAG 图）
│   │   └── semantic.py                # 语义特征（参数嵌入向量）
│   ├── detection/                     # 检测算法
│   │   ├── causal.py                  # 因果责任评分（Shapley 值）
│   │   ├── changepoint.py             # 变点检测（MA-BOCPD）
│   │   └── fingerprint.py             # 跨会话指纹识别
│   ├── response/                      # 响应处理
│   │   ├── alert_ranker.py            # 告警排序
│   │   ├── circuit_breaker.py         # 熔断器（自动阻断）
│   │   └── explainer.py               # 告警解释生成
│   └── attacks/                       # 攻击模拟
│       └── simulator.py               # 攻击场景生成器
│
├── openclaw_plugin/                   # OpenClaw 插件层
│   └── callisto-skill/
│       ├── python/
│       │   └── callisto_agent.py      # OpenClaw Agent 入口（693 行）
│       ├── SKILL.md                   # Skill 定义
│       └── src/                       # 前端 Skill 界面
│
├── dist/
│   └── index.js                       # Plugin 入口（126 行，before_tool_call hook）
│
├── scripts/                           # 辅助脚本
│   ├── auto_scanner.py                # 自动安全扫描
│   ├── test_detection.py              # 检测能力测试
│   ├── scan_skills.py                 # Skill 扫描
│   └── monitor_openclaw.py            # 运行时监控
│
├── tests/                             # 测试集
│   ├── agentdojo_detection_test_v2.py # AgentDojo 检测测试（35 用例）
│   ├── skillinject_mcpsafe_test.py    # SkillInject + MCPSafeBench（94 用例）
│   ├── content_safety_test.py         # 内容安全测试（28 用例）
│   └── extended_tools_test.py         # 扩展工具测试（43 用例）
│
├── web_server.py                      # Web Dashboard 后端
├── openclaw.plugin.json               # 插件清单
└── package.json                       # Node.js 依赖
```

---

## 4. 检测逻辑详解

### 4.1 调用链路

```
OpenClaw 工具调用
  → dist/index.js: before_tool_call hook 拦截
    → spawn Python: callisto_agent.py detect(tool_name, params, session_id)
      │
      ├─ 1. 检查熔断状态 → OPEN → 立即阻止
      │
      ├─ 2. 创建 CallEvent → 加入 Session
      │
      ├─ 3. 脱敏处理 → Sanitizer.sanitize() 过滤参数中的敏感信息
      │
      ├─ 4. 引擎分析 → CallistoEngine.analyze_session(session)
      │     │
      │     ├─ 时序特征提取 → TemporalExtractor
      │     ├─ 结构特征提取 → StructuralExtractor（构建 DAG）
      │     ├─ 语义特征提取 → SemanticExtractor
      │     ├─ 因果责任评分 → CausalResponsibilityScorer（Shapley 值）
      │     ├─ 变点检测 → MABOCPD
      │     └─ 跨会话指纹 → CrossSessionFingerprinter
      │
      ├─ 5. 恶意命令检测 → _is_malicious_command(cmd)
      │
      ├─ 6. 内容安全检测 → ContentSafetyDetector.analyze(tool_name, params)
      │     │
      │     ├─ 非 Exec 工具参数检查（26 个工具，50+ 规则）
      │     ├─ 脚本执行分析（Python AST / Shell 模式 / Node require）
      │     ├─ 命令归一化（编码混淆、IFS 滥用、引号混淆）
      │     ├─ Shell 黑名单匹配（45+ 模式）
      │     ├─ 路径访问控制（敏感文件匹配）
      │     ├─ URL/域名检查（云元数据、私有 IP、exfil 站点）
      │     └─ 外泄模式匹配（读取+转发链）
      │
      ├─ 7. 告警 → Alert 列表 → 记录到熔断器
      │
      └─ 8. 返回 DetectResult → JS 层根据 risk_level 决定是否阻止
```

### 4.2 内容安全检测规则体系

```
ContentSafetyDetector.analyze()
│
├── _check_non_exec_tool()          # 非 Exec 工具参数级风险
│   ├── _RISKY_TOOLS                 # 5 个高风险工具
│   ├── _TOOL_PARAM_RULES           # 16 条参数规则
│   ├── _CONTENT_RISK_KEYWORDS      # 内容关键词
│   ├── _EXTENDED_RISKY_TOOLS       # 26 个 OpenClaw 内置工具
│   └── _EXTENDED_TOOL_RULES        # 50+ 条扩展规则
│
├── _analyze_command()              # Shell 命令深度分析
│   ├── detect_obfuscation()        # 混淆检测（10 种技术，评分制）
│   ├── _analyze_shell_patterns()   # 模式匹配（12 条）
│   ├── _SHELL_BLACKLIST            # 黑名单（25 条）
│   ├── _analyze_script_execution() # 脚本文件分析
│   ├── _analyze_inline_code()      # 内联代码分析（python -c / bash -c / node -e）
│   ├── _extract_and_check_paths()  # 路径提取和检查
│   └── _analyze_urls()             # URL 提取和域名检查
│
├── _analyze_python_source()        # Python 源码分析
│   ├── 关键导入检测（ctypes, pickle, shelve, marshal）
│   ├── 监督导入检测（subprocess, os, socket, requests 等）
│   ├── 危险调用检测（os.system, eval, exec, __import__）
│   └── 模式匹配（反向 Shell、凭据访问等）
│
├── _analyze_shell_source()         # Shell 脚本分析
│   ├── 模式匹配 + curl/wget 下载执行检测
│   └── 管道+执行链检测
│
├── _analyze_node_source()          # Node.js 源码分析
│   ├── 关键模块检测（child_process, vm, cluster）
│   ├── 监督模块检测（fs, net, http, https）
│   └── eval() 检测
│
├── _analyze_text()                 # 纯文本分析（输入/输出双阶段）
│   ├── stage="input" → _analyze_prompt_injection()   # 15+ 条注入规则
│   └── stage="output" → _analyze_output_exfil()       # 13 条外泄规则
│
└── _analyze_exfil_patterns()       # 外泄模式匹配
    ├── 钓鱼模式
    └── 批量数据收集+外发
```

### 4.3 内容安全规则数量

| 规则集 | 规则数 | 覆盖目标 |
|--------|--------|---------|
| `_SHELL_PATTERNS` | 12 | 反向 Shell、凭证访问、元数据、外泄 |
| `_SHELL_BLACKLIST` | 25 | Fork bomb、关机、磁盘操作、容器逃逸等 |
| `_TOOL_PARAM_RULES` | 16 | 金融、邮件、文件、日历参数检查 |
| `_CONTENT_RISK_KEYWORDS` | 1 | 邮件主题检查 |
| `_EXTENDED_TOOL_RULES` | 50+ | 26 个 OpenClaw 内置工具参数检查 |
| `_INJECTION_PATTERNS` | 15+ | 中英文提示词注入检测 |
| `_OUTPUT_EXFIL_PATTERNS` | 13 | API Key、密码、私钥、信用卡等 |
| `_OBFUSCATION_TECHNIQUES` | 10 | 编码混淆、IFS 滥用、引号混淆等 |
| `_SENSITIVE_PATH_PATTERNS` | 14 | SSH、AWS、凭据、Docker 等 |
| `_DENIED_DOMAINS` | 10 | Pastebin、ngrok、transfer.sh 等 |
| `_KNOWN_SAFE_DOMAINS` | 10 | GitHub、PyPI、NPM 等 |

### 4.4 响应处理逻辑

```
告警产生 → Alert 列表
  │
  ├─ 记录到 CircuitBreaker
  │    ├── 连续 HIGH 告警计数
  │    └─ 达到阈值 → 状态变为 OPEN → 后续调用全部阻止
  │
  ├─ 同步到 Web Dashboard（http://localhost:8765）
  │    ├── 告警列表
  │    └── 会话状态
  │
  └─ 返回给 JS 层
       ├── HIGH 告警 → block: true → 阻止工具调用
       ├── MEDIUM/LOW → 仅记录 warn 日志 → 放行
       └─ CircuitBreaker OPEN → block: true → 阻止工具调用
```

---

## 5. 测试覆盖

| 测试集 | 用例数 | 检测率 | 说明 |
|--------|--------|--------|------|
| AgentDojo | 35 | 88.6% | 组合检测（content_analysis + detect） |
| SkillInject | 59 | 92% | 真实注入文本 + 工具调用模拟 |
| MCPSafeBench | 35 | 97% | 含 credential_theft、data_tampering 等新类型 |
| 内容安全 | 28 | 100% | 输入 15 条 + 输出 13 条 |
| 扩展工具 | 43 | 100% | 新增 26 个工具的检测验证 |
| **合计** | **200** | **93.6%**（组合） | |

---

## 6. 架构特点

| 特点 | 说明 |
|------|------|
| **旁路检测** | 不修改 Agent 工具链，仅监听和告警，不改变正常工作流 |
| **全自动** | 无需人工审批，依赖规则匹配和统计检测 |
| **多层防护** | 内容安全 + 引擎分析 + 因果图 + 时序检测 + 脱敏 + 熔断 |
| **OpenClaw 全工具覆盖** | 检测 26+ 个内置工具（Exec、read、write、browser、message、cron 等） |
| **会话级分析** | 不是单点检测，而是基于整个会话的工具调用序列分析 |
| **熔断机制** | 连续高风险操作自动阻断会话，防止攻击扩散 |
| **可审计** | 所有检测记录同步到 Web Dashboard |
| **无 LLM 依赖** | 纯规则 + 统计，无需额外模型调用 |
