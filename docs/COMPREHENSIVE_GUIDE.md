# CALLISTO 完整文档

**CALLISTO** (Causal And LLM-Level Invocation Sequence Temporal Observer) 是一个针对 OpenClaw Agent 的**实时安全检测插件**，专门防御**间接提示注入攻击**（Indirect Prompt Injection）。采用**旁路检测**架构 —— 不修改 Agent 工具链，不依赖人工审批，全自动运行。

**版本**: v2.0  
**最后更新**: 2026-04-27

---

## 目录

1. [项目概述](#1-项目概述)
2. [架构设计](#2-架构设计)
3. [七层检测体系](#3-七层检测体系)
4. [检测的攻击类型](#4-检测的攻击类型)
5. [内容安全检测规则](#5-内容安全检测规则)
6. [调用链路](#6-调用链路)
7. [OpenClaw 插件集成](#7-openclaw-插件集成)
8. [自动调用机制](#8-自动调用机制)
9. [Web Dashboard](#9-web-dashboard)
10. [安全扫描](#10-安全扫描)
11. [测试覆盖与检测率](#11-测试覆盖与检测率)
12. [与 ClawGuard 对比](#12-与-clawguard-对比)
13. [API 参考](#13-api-参考)
14. [快速开始](#14-快速开始)
15. [故障排查](#15-故障排查)
16. [贡献指南](#16-贡献指南)

---

## 1. 项目概述

### 1.1 定位

CALLISTO 是一个 LLM Agent 运行时安全检测系统，通过**模式匹配 + 统计分析**检测间接提示注入攻击及其衍生的各类恶意行为。

### 1.2 核心特点

| 特点 | 说明 |
|------|------|
| **旁路检测** | 不修改 Agent 工具链，仅监听和告警，不改变正常工作流 |
| **全自动** | 无需人工审批，依赖规则匹配和统计检测 |
| **多层防护** | 内容安全 + 引擎分析 + 因果图 + 时序检测 + 脱敏 + 熔断 |
| **OpenClaw 全工具覆盖** | 检测 26+ 个内置工具（Exec、read、write、browser、message、cron 等） |
| **会话级分析** | 基于整个会话的工具调用序列分析，非单点检测 |
| **熔断机制** | 连续高风险操作自动阻断会话，防止攻击扩散 |
| **可审计** | 所有检测记录同步到 Web Dashboard |
| **无 LLM 依赖** | 纯规则 + 统计，无需额外模型调用 |

### 1.3 项目组成

```
CALLISTO 项目
├── Python 包（核心引擎）── 检测引擎、离线扫描、行为指纹、评估框架
├── OpenClaw 插件 ──────── 实时拦截、熔断阻断
└── OpenClaw Skill ─────── 手动扫描、状态查询
```

### 1.4 项目统计

| 指标 | 数值 |
|------|------|
| 总代码量 | ~22,000 行 |
| Python 文件 | 55 个 |
| JavaScript 文件 | 5 个 |
| 测试用例 | 200+ |
| 综合检测率 | 93.6% |

---

## 2. 架构设计

### 2.1 四层检测架构

```
Layer 1 (Collector) → Layer 2 (Features) → Layer 3 (Detection) → Layer 4 (Response)
```

| 层 | 功能 | 模块 |
|----|------|------|
| **Layer 1: 数据收集** | 解析日志构建 Session 对象 | `collector/models.py`, `collector/interceptor.py`, `collector/openclaw_parser.py` |
| **Layer 2: 特征提取** | 提取时序、结构、语义特征 | `features/temporal.py`, `features/structural.py`, `features/semantic.py` |
| **Layer 3: 检测算法** | 运行多种检测器生成告警 | `detection/causal.py`, `detection/changepoint.py`, `detection/fingerprint.py` |
| **Layer 4: 响应处理** | 告警排序、熔断、解释 | `response/alert_ranker.py`, `response/circuit_breaker.py`, `response/explainer.py` |

### 2.2 Plugin + Skill 双模式

CALLISTO 在 OpenClaw 中采用双模式设计：

| 模式 | 触发方式 | 用途 |
|------|----------|------|
| **Plugin** | 自动拦截 | 通过 `before_tool_call` hook 实时检测并阻断高风险操作 |
| **Skill** | 用户主动调用 | 通过 `callisto_scan`、`callisto_status` 等工具手动扫描 |

两者共用同一个 Python 后端 (`callisto_agent.py`)，确保检测逻辑一致。

```
┌─────────────────────────────────────────────────────────┐
│                    OpenClaw Gateway                     │
└───────────────────────┬─────────────────────────────────┘
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
  ┌───────────┐  ┌───────────┐   ┌─────────────┐
  │  Plugin   │  │   Skill   │   │  其他插件   │
  │ (自动拦截) │  │ (手动扫描) │   │             │
  └─────┬─────┘  └─────┬─────┘   └─────────────┘
        │              │
        └──────┬───────┘
               │ spawn python3
        ┌──────▼───────┐
        │ callisto_    │
        │ agent.py     │
        │ (检测引擎)   │
        └──────────────┘
```

### 2.3 项目结构

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

## 3. 七层检测体系

| 层次 | 功能 | 检测对象 | 触发时机 |
|------|------|---------|---------|
| **L1 — 内容安全** | `ContentSafetyDetector` | 工具调用参数、脚本内容、URL、注入文本 | 每次工具调用 |
| **L2 — 引擎分析** | `CallistoEngine` | 会话级工具调用序列 | 每次工具调用后 |
| **L3 — 因果图分析** | `CausalResponsibilityScorer` | 工具调用 DAG，识别危险链 | 引擎分析时 |
| **L4 — 时序检测** | `MABOCPD` | 调用频率、行为漂移 | 引擎分析时 |
| **L5 — 脱敏处理** | `Sanitizer` | 工具输出中的 API Key、Token 等 | 工具返回后 |
| **L6 — 自动熔断** | `CircuitBreaker` | 连续 HIGH 告警自动阻断会话 | 告警累积时 |
| **L7 — 告警排序** | `AlertRanker` | 告警优先级排序、解释生成 | 产生告警后 |

---

## 4. 检测的攻击类型

### 4.1 核心检测（A 系列）

#### A1: 速率洪水 (Rate Flood)

- **检测方式**: 滑动窗口内调用频率异常（≥8 次/5 秒）
- **算法**: 滑动窗口计数
- **风险等级**: HIGH
- **配置**: `burst_window=5.0s`, `burst_count_threshold=8`
- **检测率**: 100%

#### A2: 权限升级 (Privilege Escalation)

- **检测方式**: 恶意命令匹配、提权命令、危险脚本执行
- **算法**: 连续敏感工具链检测（≥2 个连续高敏感工具）
- **高敏感工具集**: exec, shell, run_command, delete_file, send_email, http_request, curl, wget
- **良性命令白名单**: npm install/build, go build/test, cargo build, git status/log, ls/cat/grep 等
- **风险等级**: HIGH
- **检测率**: 80%

#### A3: 数据外泄 (Data Exfiltration)

- **检测方式**: 上传模式（`curl -d @`）、敏感文件读取、网络外发
- **算法**: 工具 + 目的地组合检测
- **外泄工具集**: http_request, curl, wget, send_email, scp, rsync, ftp, sftp, nc, netcat
- **外部特征**: URL 包含 evil/attacker/pastebin/http://, 邮件地址包含 evil/attacker
- **风险等级**: HIGH
- **检测率**: 100%

#### A4: 行为漂移 (Behavioral Drift)

- **检测方式**: 工具调用分布与基线偏离（结构特征分析）
- **算法 1**: 工具分布偏移（前半段无危险工具，后半段 ≥2 个危险工具）
- **算法 2**: 节奏变化检测（IAT 比率 <0.15 或 >8.0）
- **风险等级**: MEDIUM
- **检测率**: 70%

#### A5: 时序违例 (Temporal Violation)

- **检测方式**: 调用间隔分布异常
- **模式 1**: delete_file 后紧跟 read_file（删除前无备份）
- **模式 2**: write_file 前无任何 read_file（覆盖风险）
- **风险等级**: MEDIUM
- **检测率**: 100%

#### A6: 状态投毒 (State Poisoning)

- **检测方式**: 敏感配置文件修改（`.bashrc`、SSH 配置、Crontab 等）
- **算法**: 路径 + 内容组合检测
- **投毒路径**: .bashrc, .zshrc, .ssh/, authorized_keys, cron, crontab, /etc/hosts, sudoers 等
- **风险等级**: HIGH
- **检测率**: 100%

### 4.2 细化检测场景（P/D/L 系列）

#### P1/D1: 敏感文件读取

- **检测方式**: 路径匹配（`.ssh`、`.aws`、`credentials` 等）
- **敏感路径模式**: 40+ 种（系统文件、SSH 密钥、云凭证、K8s 配置、应用密钥、开发凭证）
- **风险等级**: HIGH
- **检测率**: 80%

#### L1/L2: 内网/服务访问

- **检测方式**: 私有 IP 段匹配、云元数据端点检测
- **内网模式**: 192.168.x.x, 10.x.x.x, 172.16-31.x.x, 169.254.169.254, .internal/.local/.lan/.corp
- **内部服务端口**: 3306, 5432, 6379, 27017, 9200, 2379, 8500, 8200
- **风险等级**: HIGH
- **检测率**: L1=60%, L2=100%

#### L3: 凭证文件访问

- **检测方式**: 密钥文件、Token 文件路径匹配
- **凭证路径**: .aws/credentials, .kube/config, .ssh/id_rsa, .npmrc, .pypirc, .netrc 等 15+ 种
- **风险等级**: HIGH
- **检测率**: 60%

### 4.3 其他检测

#### 提示词注入检测

- **规则**: `_INJECTION_PATTERNS` 15+ 条（含中文）
- **覆盖类型**: ignore previous、system prompt override、jailbreak、角色操纵、URL 注入、中文注入
- **输入/输出双阶段**: `analyze_text(stage="input|output")`

#### 输出外泄检测

- **规则**: `_OUTPUT_EXFIL_PATTERNS` 13 条
- **覆盖**: API Key、密码、私钥、信用卡等

#### 非 Exec 工具风险检测

- **覆盖**: 26 个 OpenClaw 内置工具的参数级风险检测
- **规则**: 50+ 条扩展规则

---

## 5. 内容安全检测规则

### 5.1 ContentSafetyDetector 规则体系

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

### 5.2 规则数量汇总

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
| `_KNOWN_SAFE_DOMAINS` | 10 | GitHub、PyPI、NPM、Google 等 |

### 5.3 覆盖的 26 个 OpenClaw 内置工具

| 工具 | 检测内容 |
|------|---------|
| web_search / x_search | 搜索注入、prompt injection |
| browser | 导航到 exfil 站点/元数据端点、file 协议 |
| code_execution | 代码注入/外泄/危险系统调用 |
| message | 钓鱼/凭证请求/广播 |
| cron | 持久化/高频 DoS/危险命令 |
| gateway | 配置篡改/重启 |
| memory / sessions / nodes | 操纵/注入/隐私操作 |
| read / write / edit | 敏感文件访问/恶意内容写入 |
| web_fetch | 非 HTTP 协议/exfil 站点 |
| image_generate / video_generate | 提示词注入 |
| send_money / schedule_transaction | IBAN/金额/定期付款 |
| send_email | 钓鱼主题/转发指令 |
| write_file / write_calendar_event | 偏见内容/提示词注入 |

---

## 6. 调用链路

### 6.1 完整调用链路

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

### 6.2 调用阶段

| 阶段 | 触发时机 | 调用功能 |
|------|----------|----------|
| **阶段 1** | OpenClaw 启动 | 配置文件扫描、技能代码扫描、引擎初始化 |
| **阶段 2** | 每次工具调用 | 参数脱敏、8 类检测、熔断器更新 |
| **阶段 3** | 文件变化时 | 配置/技能重新扫描 |
| **阶段 4** | 手动调用 | 按需扫描、工具检查 |
| **阶段 5** | Web Dashboard | 监控面板、实时推送 |

### 6.3 性能指标

| 功能 | 延迟 | 说明 |
|------|------|------|
| 参数脱敏 | <1ms | 正则替换 |
| 速率洪水检测 | <1ms | 时间戳对比 |
| 命令安全检查 | <5ms | 模式匹配 |
| 敏感文件检测 | <2ms | 路径匹配 |
| 内网访问检测 | <2ms | IP/域名匹配 |
| 引擎分析 | <50ms | 完整会话分析 |
| 熔断器更新 | <1ms | 计数器 +1 |

**单次工具调用总延迟：<60ms**

---

## 7. OpenClaw 插件集成

### 7.1 配置

在 `~/.openclaw/openclaw.json` 中启用：

```json
{
  "plugins": {
    "enabled": true,
    "entries": {
      "callisto-plugin": {
        "config": {
          "threshold": 3,
          "cooldown": 60
        }
      }
    },
    "allow": ["callisto-plugin"]
  }
}
```

### 7.2 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CALLISTO_THRESHOLD` | `3` | 熔断阈值（HIGH 风险操作数量） |
| `CALLISTO_PYTHON` | `python3` | Python 可执行文件路径 |

### 7.3 风险级别与处理

| 级别 | 处理策略 | 示例 |
|------|----------|------|
| **HIGH** | 立即阻止，计入熔断计数 | 读取 `/etc/shadow`、访问内网 |
| **MEDIUM** | 记录警告，不阻止 | 读取普通配置文件 |
| **LOW** | 记录警告，不阻止 | 良性命令模式 |

### 7.4 熔断机制

当单个会话连续触发 `CALLISTO_THRESHOLD`（默认 3）个 HIGH 风险告警时，熔断器自动打开。

| 状态 | 说明 |
|------|------|
| **CLOSED** | 正常状态，允许操作 |
| **OPEN** | 已熔断，阻止所有操作 |

### 7.5 日志文件

| 文件 | 内容 |
|------|------|
| `/tmp/callisto-plugin.log` | Plugin hook 调用日志 |
| `/tmp/callisto-python.log` | Python 检测引擎日志 |
| `/tmp/callisto-startup.log` | 插件启动日志 |

### 7.6 插件重载

修改插件代码后不生效时：

```bash
pkill -9 -f openclaw
rm -rf ~/Library/Caches/openclaw
openclaw gateway --force
```

---

## 8. 自动调用机制

### 8.1 自动调用概述

CALLISTO 的所有核心功能都是**自动调用**的，无需手动干预。

| 场景 | 触发方式 | 自动调用的功能 |
|------|---------|---------------|
| **OpenClaw 启动** | `openclaw` 命令 | 自动扫描配置和技能文件 |
| **工具调用** | OpenClaw 执行任何工具 | 实时风险检测 + 脱敏 + 熔断 |
| **文件变更** | 监控模式运行中 | 自动重新扫描并生成报告 |
| **会话风险累积** | 连续危险操作 | 自动触发熔断 |

### 8.2 启动时自动扫描

OpenClaw 启动时会自动触发配置文件和技能代码扫描：

```
1. 用户运行 `openclaw` 命令
   ↓
2. OpenClaw 加载插件（包括 callisto-plugin）
   ↓
3. callisto-skill 插件初始化（src/index.js）
   ↓
4. 自动调用 `initialize()` 函数
   ↓
5. 执行 `startup_scan` 动作
   ↓
6. 调用 `auto_scanner.py` 扫描配置和技能
   ↓
7. 输出扫描结果到 OpenClaw 日志
```

**正常输出**:
```
[CALLISTO] 启动时自动扫描配置文件和技能代码...
[CALLISTO] 引擎已初始化，脱敏器已启用
[CALLISTO] ✓ 安全检查通过（配置：0 问题，技能：0 问题）
```

### 8.3 工具调用时实时检测

```
用户请求 → OpenClaw 准备调用工具
              ↓
        callisto_agent.detect()
              ↓
    1. 检查熔断器状态 (CLOSED/BLOCKED)
    2. 创建会话事件
    3. 脱敏处理参数 (15 类敏感信息)
    4. 引擎分析 (8 类检测)
    5. 更新熔断器计数
              ↓
        返回检测结果
              ↓
   正常 → 执行工具
   告警 → 提示风险
   熔断 → 阻断会话
```

### 8.4 监控模式

```bash
# 启动监控（每 60 秒检查一次文件变化）
python scripts/auto_scanner.py --watch 60
```

### 8.5 缓存机制

为避免每次启动都重复扫描，使用文件 MD5 哈希缓存：

```json
// .callisto_scan_cache.json
{
  "file_hashes": {
    "/path/to/file1": "md5hash1",
    "/path/to/file2": "md5hash2"
  },
  "last_scan_time": "2026-04-23T12:00:00"
}
```

- **文件未变化**: 跳过扫描（秒级完成）
- **文件已变化**: 重新扫描并更新缓存

---

## 9. Web Dashboard

### 9.1 快速启动

```bash
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin

# 基本启动
./start-web.sh

# 启动并打开浏览器
./start-web.sh --open

# 开发模式（自动重载）
./start-web.sh --reload --open

# 自定义端口
./start-web.sh --port 8766
```

### 9.2 访问地址

| 服务 | URL |
|------|-----|
| **Dashboard** | http://localhost:8765 |
| **API 文档 (Swagger)** | http://localhost:8765/docs |
| **API 文档 (Redoc)** | http://localhost:8765/redoc |
| **API 状态** | http://localhost:8765/api/status |

### 9.3 功能特性

| 功能 | 说明 |
|------|------|
| **安全扫描** | 完整扫描、配置扫描、技能扫描、强制扫描 |
| **告警监控** | 实时显示最新告警，按严重性分类，SSE 实时推送 |
| **会话管理** | 查看活跃会话列表、状态、告警计数 |
| **工具检查** | 手动检查工具调用风险 |
| **统计面板** | 24 小时告警统计，按严重性和类别分类 |

### 9.4 API 端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/` | GET | Dashboard 首页 |
| `/api/status` | GET | 服务状态 |
| `/api/stats` | GET | 统计数据 |
| `/api/scan` | POST | 运行扫描 |
| `/api/scan/results` | GET | 扫描结果 |
| `/api/alerts` | GET | 告警列表 |
| `/api/alerts/add` | POST | 添加告警 |
| `/api/alerts/clear` | DELETE | 清空告警 |
| `/api/sessions` | GET | 会话列表 |
| `/api/session/{id}/circuit-breaker` | POST | 熔断器操作 |
| `/api/events` | GET | SSE 事件推送 |
| `/api/tool/check` | POST | 工具检查 |

### 9.5 技术栈

- **后端**: Python 3.11 + FastAPI + Uvicorn
- **前端**: HTML5 + CSS3 + Vanilla JavaScript
- **实时推送**: SSE (Server-Sent Events)
- **API 文档**: Swagger UI + ReDoc

### 9.6 性能指标

| 指标 | 数值 |
|------|------|
| **启动时间** | ~2 秒 |
| **内存占用** | ~50MB |
| **API 响应** | <100ms |
| **SSE 延迟** | <1s |
| **并发连接** | 100+ |

### 9.7 安全注意

当前 Web Dashboard 没有身份验证，建议：
1. 本地运行：只监听 `127.0.0.1`
2. 内网运行：添加防火墙规则限制访问 IP
3. 生产环境：添加反向代理和身份验证

---

## 10. 安全扫描

### 10.1 扫描范围

#### 配置文件扫描

| 文件类型 | 扫描内容 |
|----------|----------|
| `.env*`, `*.env` | 敏感变量、Token、密码 |
| `config.yaml`, `config.json` | 网络配置、会话设置、调试模式 |
| `skills/**/*.md`, `skills/**/*.py` | 技能定义中的敏感信息 |

**扫描规则（25 类）**: Token 安全(3)、网络安全(7)、会话安全(3)、数据保护(3)、插件安全(3)、执行安全(6)

#### 技能代码扫描

| 类别 | 检测内容 |
|------|----------|
| 危险命令调用 | exec, eval, __import__, pickle 等 |
| 敏感文件访问 | /etc/shadow, .ssh/, .aws/credentials 等 |
| 网络 API 调用 | requests, socket, httpx 等 |
| 加密算法使用 | MD5, SHA1, DES 等弱加密 |
| 文件系统操作 | 删除、写入、权限修改 |
| 环境变量访问 | 读取、修改环境变量 |

### 10.2 扫描命令

```bash
# 完整扫描（配置 + 技能）
python scripts/auto_scanner.py --scan-all

# 仅配置扫描
python scripts/auto_scanner.py --scan-config

# 仅技能扫描
python scripts/auto_scanner.py --scan-skills

# 强制扫描（忽略缓存）
python scripts/auto_scanner.py --scan-all --force

# 监控模式（持续监控文件变化）
python scripts/auto_scanner.py --watch 60

# 启动扫描
python scripts/auto_scanner.py --on-startup
```

### 10.3 报告生成

扫描报告保存到 `test_reports/startup_scan_YYYYMMDD_HHMMSS.md`。

---

## 11. 测试覆盖与检测率

### 11.1 测试数据集

| 数据集 | 来源 | 原始规模 | 测试数 | 注入渠道 |
|--------|------|---------|--------|---------|
| **AgentDojo** | ETH Zurich | 35 tasks | 35 tasks | Web/本地内容 |
| **SkillInject** | aisa-group | 84 attacks | 59 attacks | Skill 文件 |
| **MCPSafeBench** | arXiv:2512.15163 | 215 attacks | 35 attacks | MCP 服务器 |

### 11.2 测试结果汇总

| 数据集 | 检测数 / 总数 | 检测率 | 说明 |
|--------|--------------|--------|------|
| **AgentDojo** | 31 / 35 | **88.6%** | 组合检测（content_analysis + tool_detect） |
| **SkillInject + MCPSafeBench** | 88 / 94 | **93.6%** | 组合检测 |
| → SkillInject | 54 / 59 | 92% | |
| → MCPSafeBench | 34 / 35 | 97% | |
| **内容安全审查（独立）** | 28 / 28 | **100.0%** | 对话层检测 |
| → 输入审查（input） | 15 / 15 | 100% | |
| → 输出审查（output） | 13 / 13 | 100% | |

### 11.3 AgentDojo 按场景

| 场景 | 检测率 |
|------|--------|
| banking | 100% (9/9) |
| slack | 100% (5/5) |
| travel | 100% (7/7) |
| workspace | 71% (10/14) |

### 11.4 检测机制覆盖

| 机制 | 覆盖的攻击 |
|------|-----------|
| 恶意命令模式匹配 | `curl -X POST -d @file`、`curl \| bash`、`rm -rf` 等 |
| **非 Exec 工具风险检测** | `send_money` IBAN、`schedule_transaction` 定期付款等 |
| **扩展黑名单** | Fork bomb、无限循环、容器逃逸、git force push 等 45+ 模式 |
| **命令归一化** | IFS 滥用、编码混淆、引号绕过、反斜杠转义、eval 执行 |
| **路径访问控制** | 敏感文件读取（shadow、ssh key、env、aws credentials） |
| **网络白名单** | 未知外部域名连接、云元数据访问、私有 IP 访问 |
| **内容安全检测** | 脚本分析、URL 检查、混淆检测、SSRF 检测 |
| **OpenClaw 内置工具检测** | 26 个内置工具的参数级风险检测 |

### 11.5 未覆盖的攻击类型

以下攻击需要 LLM 语义理解才能识别，纯正则/模式匹配无法覆盖：

1. **非 Exec 工具的隐蔽语义攻击** — `echo $PATH`（环境信息暴露）
2. **社交工程** — 诱导用户点击链接的邮件内容
3. **Git 滥用（非破坏性）** — `git reset --hard`
4. **安全配置修改** — 禁用 ShellCheck、跳过 SQL 注入测试
5. **偏见/偏见操控** — 已被 `write_file` 内容模式检测部分覆盖

### 11.6 运行测试

```bash
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin

# AgentDojo
.venv/bin/python tests/agentdojo_detection_test_v2.py

# SkillInject + MCPSafeBench
.venv/bin/python tests/skillinject_mcpsafe_test.py

# 内容安全
.venv/bin/python tests/content_safety_test.py

# 扩展工具
.venv/bin/python tests/extended_tools_test.py
```

---

## 12. 与 ClawGuard 对比

### 12.1 检测率对比

| 数据集/场景 | ClawGuard | CALLISTO | 差距 |
|------------|-----------|----------|------|
| **AgentDojo** | **100%** (35/35) | **88.6%** (31/35) | -11.4pp |
| **SkillInject** | 无公开数据 | **92%** (54/59) | — |
| **MCPSafeBench** | 无公开数据 | **97%** (34/35) | — |
| **内容安全审查** | sanitizer 25+ 模式 | **100%** (28/28) | 同等水平 |
| **内置工具覆盖** | ~5 个（仅 `cg_*` 封装的） | ~26 个（扩展后） | CALLISTO 更广 |

### 12.2 核心架构差异

| 维度 | ClawGuard | CALLISTO |
|------|-----------|----------|
| **策略** | 白名单（默认拒绝） | 黑名单（默认允许） |
| **工具控制** | Gateway 层禁用 + 替换 | 旁路检测，不阻止调用 |
| **人类回路** | 有（APPROVE 审批） | 无（全自动） |
| **检测时机** | 工具调用前拦截 | 工具调用时/后检测 |
| **检测范围** | ~5 个封装工具 | 全部 32+ 个内置工具 |
| **语义理解** | 无（纯正则/模式） | 无（纯正则/模式） |
| **会话级分析** | 无（单点检测） | 有（因果图、操作链、时序） |
| **零日免疫** | 是（白名单天然免疫） | 否（需要新增规则） |
| **误报风险** | 低（白名单越配越安全） | 中（黑名单可能漏报） |
| **部署复杂度** | 高（替换工具 + 修改 config + daemon） | 低（纯插件，无需修改配置） |

### 12.3 CALLISTO 优于 ClawGuard 的地方

- **内置工具覆盖**: 26 个 vs 5 个（ClawGuard 只封装了 exec/read/write/http/list）
- **提示词注入检测**: 15+ 条规则（含中文）vs 无专门注入检测
- **会话级分析**: 因果图、操作链、时序分析 vs 单点检测
- **部署方式**: 旁路检测，不修改工具链 vs 中间人，需替换工具
- **自动熔断**: CircuitBreaker 自动阻断 vs 需人工审批

### 12.4 ClawGuard 优于 CALLISTO 的地方

- **AgentDojo 100% 防御**: 通过白名单 + 审批回路实现，不是检测引擎更强
- **零日免疫**: 白名单天然免疫未知攻击
- **人工审批**: APPROVE 审批回路满足合规审计要求

### 12.5 互补使用

两者可以组合使用以获得最大覆盖：

```
用户输入 → CALLISTO content_analysis(stage="input") → 注入检测
              ↓
         工具调用 → ClawGuard L1（白名单 + 审批）
              ↓
         工具调用 → CALLISTO detect()（旁路检测全部工具）
              ↓
         工具输出 → CALLISTO content_analysis(stage="output") → 外泄检测
              ↓
         工具输出 → ClawGuard L3（sanitizer 清洗）
```

---

## 13. API 参考

### 13.1 核心模块

#### CallistoEngine

```python
from callisto.engine import CallistoEngine

engine = CallistoEngine(config: CallistoConfig | None = None)
alerts = engine.analyze_session(session)
```

#### CallistoConfig

```python
from callisto.config import CallistoConfig

config = CallistoConfig(
    context_window=10,
    embedding_dim=64,
    crs_samples=30,
    crs_threshold=0.7,
    burst_window=5.0,
    burst_count_threshold=8,
    sensitive_chain_min=3,
    circuit_breaker_threshold=3,
    bocpd_hazard_base=1/25,
    bocpd_threshold=0.5,
    csbf_distance_threshold=3.0,
    csbf_min_history=5,
)
```

#### 数据模型

```python
from callisto.collector.models import Session, CallEvent, Alert
from callisto.collector.models import RiskLevel, AttackType, EventType
```

**RiskLevel**: NONE=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4

**AttackType**: A1_RATE_FLOOD, A2_PRIV_ESCALATION, A3_DATA_EXFIL, A4_BEHAVIOR_DRIFT, A5_TEMPORAL_VIOLATION, A6_STATE_POISON, BENIGN

### 13.2 特征提取

```python
from callisto.features.temporal import TemporalExtractor
from callisto.features.structural import StructuralExtractor
from callisto.features.semantic import SemanticExtractor
```

### 13.3 检测算法

```python
from callisto.detection.causal import CausalResponsibilityScorer
from callisto.detection.changepoint import MABOCPD
from callisto.detection.fingerprint import CrossSessionFingerprinter
```

### 13.4 响应处理

```python
from callisto.response.alert_ranker import AlertRanker
from callisto.response.circuit_breaker import CircuitBreaker
from callisto.response.explainer import AlertExplainer
```

### 13.5 攻击模拟器

```python
from callisto.attacks.simulator import (
    generate_benign_session,
    generate_rate_flood,
    generate_priv_escalation,
    generate_data_exfil,
    generate_behavior_drift,
    generate_temporal_violation,
    generate_state_poison,
    generate_dataset,
)
```

### 13.6 评估工具

```python
from callisto.evaluation.metrics import evaluate_detector, per_attack_metrics, detection_latency
```

---

## 14. 快速开始

### 14.1 作为 OpenClaw 插件使用（推荐）

```bash
# 1. 进入插件目录
cd ~/.openclaw/extensions/callisto-plugin

# 2. 构建 TypeScript 插件
npm run build

# 3. 安装 Python 依赖
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 4. 在 ~/.openclaw/openclaw.json 中启用（见第 7 节）

# 5. 重启 OpenClaw
pkill -f openclaw
openclaw gateway --force

# 6. 验证
openclaw plugins list
```

### 14.2 作为 Python 包使用

```bash
cd ~/.openclaw/extensions/callisto-plugin
pip install -e .

# 使用 CLI
callisto --help
callisto scan ./logs
callisto monitor ./logs --block
callisto eval --benign 100 --attacks 30
callisto train ./logs/ --output ./fingerprints.json
```

### 14.3 启动 Web Dashboard

```bash
cd ~/.openclaw/extensions/callisto-plugin
./start-web.sh --open
```

访问: http://localhost:8765

### 14.4 验证安装

```bash
# 检查插件是否加载
openclaw plugins list | grep callisto

# 测试 Python 后端
echo '{"tool_name":"exec","parameters":{"command":"cat /etc/passwd"},"session_id":"test"}' | \
  python3 openclaw_plugin/callisto-skill/python/callisto_agent.py detect
```

---

## 15. 故障排查

### 15.1 插件未加载

```bash
# 检查插件状态
openclaw plugins list

# 确认 callisto-plugin 状态为 loaded
```

### 15.2 检测不生效

```bash
# 1. 验证 Python 后端
echo '{"tool_name":"exec","parameters":{"command":"cat /etc/passwd"},"session_id":"test"}' | \
  python3 openclaw_plugin/callisto-skill/python/callisto_agent.py detect

# 2. 重启 OpenClaw
pkill -9 -f openclaw
rm -rf ~/Library/Caches/openclaw
openclaw gateway --force
```

### 15.3 端口被占用

```bash
# 查看端口占用
lsof -i :8765

# 更换端口
./start-web.sh --port 8766
```

### 15.4 缓存文件损坏

```bash
# 删除缓存文件
rm /Users/jiangqiang/.openclaw/extensions/callisto-plugin/.callisto_scan_cache.json

# 重启 OpenClaw，会自动重建缓存
```

### 15.5 Python 依赖缺失

```bash
cd ~/.openclaw/extensions/callisto-plugin
pip install -e .
```

### 15.6 常见问题

**Q: 短会话（<3 调用）漏报 A2/A4/A5**

A: 这是设计决策。A2/A4/A5 检测需要足够的调用序列才能判断。A3/A6 支持短会话检测。

**Q: 熔断器误触发？**

A: 调整阈值：`CallistoAgent(threshold=5)` 或使用环境变量 `CALLISTO_THRESHOLD=5`。

**Q: 良性构建命令被误报**

A: 检查命令是否匹配 `_BENIGN_COMMAND_PATTERNS`。如果是新的构建工具，需要添加相应的正则模式到 `content_safety.py`。

---

## 16. 贡献指南

### 16.1 报告问题

- **Bug 报告**: 包含复现步骤、预期行为和实际行为
- **功能建议**: 描述使用场景和期望功能
- **性能问题**: 提供测试环境和基准数据

### 16.2 提交代码

1. Fork 仓库并创建分支: `git checkout -b feature/amazing-feature`
2. 遵循现有代码风格，添加必要的测试，更新相关文档
3. 运行测试: `pytest`
4. 提交: `git commit -m "Add amazing feature"`
5. 推送并创建 Pull Request

### 16.3 代码规范

- 遵循 PEP 8
- 使用类型注解
- 编写清晰的文档字符串

```python
def analyze_session(session: Session) -> list[Alert]:
    """分析会话并返回检测到的告警。
    
    Args:
        session: 要分析的会话对象
        
    Returns:
        告警列表，按风险等级排序
    """
```

### 16.4 开发环境设置

```bash
git clone https://github.com/your-username/callisto.git
cd callisto
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,full,eval]"
```

---

**项目位置**: `/Users/jiangqiang/.openclaw/extensions/callisto-plugin`  
**当前版本**: v2.0  
**最后更新**: 2026-04-27
