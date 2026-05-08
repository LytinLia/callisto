# CALLISTO 项目完整总览

**版本**: v2.0  
**生成日期**: 2026-04-23  
**项目位置**: `/Users/jiangqiang/.openclaw/extensions/callisto-plugin`

---

## 一、项目概览

CALLISTO 是一个面向 LLM Agent 的运行时安全检测系统，提供实时威胁检测、配置文件扫描、技能代码审计、可视化 Dashboard 等功能。

### 核心功能

| 功能模块 | 状态 | 说明 |
|----------|------|------|
| **检测引擎** | ✅ | 8 类攻击检测（速率洪水、提权、数据外泄、行为漂移、时序违例、状态投毒、敏感文件读取、内网访问） |
| **响应系统** | ✅ | 熔断器、告警 ranking、人类监督 |
| **脱敏引擎** | ✅ | 15 类敏感信息脱敏（AWS、GitHub、数据库凭证等） |
| **配置扫描** | ✅ | 25 类安全规则扫描 |
| **技能扫描** | ✅ | 8 类代码风险检测 |
| **Web Dashboard** | ✅ | 实时监控、扫描管理、告警可视化 |
| **OpenClaw 集成** | ✅ | 插件形式实时检测 |
| **自动调用** | ✅ | 启动自动扫描、工具调用自动检测 |

---

## 二、完整文件清单

### 2.1 核心 Python 模块 (callisto/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `callisto/__init__.py` | 20 | 包初始化，导出核心类 |
| `callisto/__main__.py` | 8 | CLI 入口点 |
| `callisto/config.py` | 60 | 配置类和默认值 |
| `callisto/engine.py` | 1400+ | 核心检测引擎 |
| `callisto/sanitizer.py` | 250 | 敏感信息脱敏 |
| `callisto/auto_config.py` | 180 | 自动配置模块 |
| `callisto/web.py` | 60 | Web 启动模块 |
| `callisto/monitor.py` | 280 | OpenClaw 监控器 |
| `callisto/openclaw.py` | 100 | OpenClaw 集成 |
| `callisto/cli.py` | 350 | 命令行接口 |

### 2.2 检测模块 (callisto/detection/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `callisto/detection/__init__.py` | 10 | 模块导出 |
| `callisto/detection/fingerprint.py` | 200 | 攻击指纹匹配 |
| `callisto/detection/causal.py` | 180 | 因果分析 |
| `callisto/detection/changepoint.py` | 150 | 变点检测 |

### 2.3 收集器模块 (callisto/collector/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `callisto/collector/__init__.py` | 10 | 模块导出 |
| `callisto/collector/models.py` | 300 | 数据模型定义 |
| `callisto/collector/interceptor.py` | 250 | 工具调用拦截 |
| `callisto/collector/openclaw_parser.py` | 120 | OpenClaw 日志解析 |

### 2.4 响应模块 (callisto/response/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `callisto/response/__init__.py` | 10 | 模块导出 |
| `callisto/response/circuit_breaker.py` | 180 | 熔断器实现 |
| `callisto/response/alert_ranker.py` | 150 | 告警优先级排序 |
| `callisto/response/explainer.py` | 120 | 告警解释生成 |

### 2.5 特征模块 (callisto/features/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `callisto/features/__init__.py` | 10 | 模块导出 |
| `callisto/features/structural.py` | 200 | 结构特征提取 |
| `callisto/features/temporal.py` | 180 | 时序特征提取 |
| `callisto/features/semantic.py` | 150 | 语义特征提取 |

### 2.6 评估模块 (callisto/evaluation/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `callisto/evaluation/__init__.py` | 10 | 模块导出 |
| `callisto/evaluation/metrics.py` | 200 | 评估指标 |
| `callisto/evaluation/run_eval.py` | 150 | 评估运行器 |
| `callisto/evaluation/run_all_experiments.py` | 100 | 批量实验 |
| `callisto/evaluation/ablation.py` | 180 | 消融实验 |
| `callisto/evaluation/adversarial.py` | 150 | 对抗测试 |
| `callisto/evaluation/baselines/detectors.py` | 200 | 基线检测器 |
| `callisto/evaluation/baselines/paper_baselines.py` | 180 | 论文基线 |
| `callisto/evaluation/case_study.py` | 120 | 案例研究 |
| `callisto/evaluation/comparative_eval.py` | 100 | 对比评估 |
| `callisto/evaluation/cross_scenario.py` | 150 | 跨场景评估 |
| `callisto/evaluation/scalability.py` | 120 | 可扩展性测试 |
| `callisto/evaluation/sensitivity.py` | 100 | 敏感性分析 |
| `callisto/evaluation/statistical.py` | 180 | 统计分析 |

### 2.7 攻击模拟 (callisto/attacks/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `callisto/attacks/__init__.py` | 10 | 模块导出 |
| `callisto/attacks/simulator.py` | 300 | 攻击场景模拟 |

### 2.8 脚本 (scripts/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `scripts/auto_scanner.py` | 440 | 自动扫描器（配置 + 技能） |
| `scripts/scan_config.py` | 500 | 配置文件扫描器 |
| `scripts/scan_skills.py` | 440 | 技能代码扫描器 |
| `scripts/monitor_openclaw.py` | 420 | OpenClaw 实时监控 |
| `scripts/batch_test_validation.py` | 400 | 批量测试验证 |
| `scripts/generate_test_batches.py` | 650 | 测试用例生成 |
| `scripts/analyze_detection_stats.py` | 450 | 检测统计分析 |
| `scripts/test_detection.py` | 500 | 检测功能测试 |
| `scripts/test_new_features.py` | 280 | 新功能测试 |
| `scripts/test_openclaw_integration.py` | 140 | OpenClaw 集成测试 |
| `scripts/auto_integration_demo.py` | 180 | 自动集成演示 |

### 2.9 Web Dashboard (web/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `web_server.py` | 280 | FastAPI 应用 |
| `web/index.html` | 150 | Dashboard 首页 |
| `web/static/css/style.css` | 400 | 响应式样式 |
| `web/static/js/app.js` | 350 | 前端交互逻辑 |
| `start-web.sh` | 80 | 快速启动脚本 |

### 2.10 OpenClaw 插件 (openclaw_plugin/)

| 文件 | 行数 | 功能 |
|------|------|------|
| `openclaw_plugin/callisto-skill/src/index.js` | 180 | Node.js 插件入口 |
| `openclaw_plugin/callisto-skill/python/callisto_agent.py` | 460 | Python 检测后端 |
| `openclaw_plugin/callisto-skill/package.json` | 15 | 包配置 |
| `openclaw_plugin/callisto-skill/README.md` | 200 | 插件文档 |
| `openclaw_plugin/callisto-skill/SKILL.md` | 100 | 技能说明 |

### 2.11 测试数据 (test_sessions/)

**100 个测试会话文件** (每个 ~2KB):
- `attack_rate_flood_*.jsonl` (20 个) - 速率洪水攻击
- `attack_priv_escalation_*.jsonl` (20 个) - 提权攻击
- `attack_data_exfil_*.jsonl` (20 个) - 数据外泄
- `attack_behavior_drift_*.jsonl` (20 个) - 行为漂移
- `attack_temporal_violation_*.jsonl` (20 个) - 时序违例
- `attack_state_poison_*.jsonl` (20 个) - 状态投毒

### 2.12 测试报告 (test_reports/)

| 文件 | 内容 |
|------|------|
| `BATCH_TEST_REPORT.md` | 批量测试报告 (66 项测试，95.5% 通过率) |
| `OPENCLAW_INTEGRATION_REPORT.md` | OpenClaw 集成报告 |
| `AUTO_INTEGRATION_REPORT.md` | 自动集成完成报告 |
| `IMPROVEMENT_SUMMARY.md` | 改进总结 |
| `PROJECT_COMPARISON.md` | 三项目对比分析 |
| `startup_scan_*.md` | 启动扫描报告 |

### 2.13 文档 (docs/)

| 文件 | 内容 |
|------|------|
| `docs/OVERVIEW.md` | 项目概览 |
| `docs/openclaw_startup_guide.md` | OpenClaw 启动指南 |

### 2.14 集成示例 (integration_examples/)

| 文件 | 内容 |
|------|------|
| `integration_examples/agent_with_callisto.py` | Agent 集成示例 |
| `integration_examples/INTEGRATION_GUIDE.md` | 集成指南 |
| `integration_examples/interceptor_patch.py` | 拦截器补丁 |

### 2.15 报告 (reports/)

| 文件 | 内容 |
|------|------|
| `reports/` | 各种评估和测试报告 |

### 2.16 专家测试会话 (expert_test_sessions/)

| 文件 | 内容 |
|------|------|
| `expert_test_sessions/` | 专家级攻击场景测试数据 |

### 2.17 根目录文档

| 文件 | 内容 |
|------|------|
| `README.md` | 项目 README |
| `README.md.backup` | README 备份 |
| `QUICKSTART.md` | 快速开始指南 |
| `API.md` | API 文档 |
| `CONTRIBUTING.md` | 贡献指南 |
| `DETECTION_LOGIC.md` | 检测逻辑说明 |
| `NEW_FEATURES_GUIDE.md` | 新功能指南 |
| `AUTO_CALL_GUIDE.md` | 自动调用指南 |
| `AUTO_INTEGRATION_GUIDE.md` | 自动集成指南 |
| `OPENCLAW_PLUGIN.md` | OpenClaw 插件文档 |
| `OPENCLAW_PLUGIN.md.backup` | 插件文档备份 |
| `WEB_DASHBOARD_GUIDE.md` | Web Dashboard 使用指南 |
| `WEB_IMPLEMENTATION_SUMMARY.md` | Web 实现总结 |
| `WEB_QUICKSTART.md` | Web 快速开始 |
| `STARTUP_SCAN_GUIDE.md` | 启动扫描指南 |

### 2.18 配置文件

| 文件 | 内容 |
|------|------|
| `pyproject.toml` | Python 项目配置 |
| `requirements.txt` | Python 依赖 |
| `package.json` | Node.js 包配置 |
| `package-lock.json` | Node.js 依赖锁定 |
| `tsconfig.json` | TypeScript 配置 |
| `openclaw.plugin.json` | OpenClaw 插件配置 |
| `.claude/settings.local.json` | Claude 本地设置 |

### 2.19 构建产物

| 文件/目录 | 内容 |
|-----------|------|
| `dist/index.js` | 编译后的 JS |
| `callisto.egg-info/` | Python 包元数据 |
| `scan_report.md` | 扫描报告 |
| `skill_scan_report.md` | 技能扫描报告 |

### 2.20 缓存和临时文件

| 文件 | 内容 |
|------|------|
| `.callisto_scan_cache.json` | 扫描缓存（文件哈希） |
| `paper.pdf`, `paper.tex`, `paper.out`, `paper.log`, `paper.aux` | 论文相关 |
| `index.ts` | TypeScript 源文件 |

### 2.21 依赖目录（不计入项目代码）

| 目录 | 内容 |
|------|------|
| `node_modules/` | Node.js 依赖（约 180 个包） |
| `.venv/` | Python 虚拟环境 |
| `__pycache__/` | Python 字节码缓存 |

---

## 三、文件统计

### 3.1 代码统计

| 语言 | 文件数 | 行数（约） |
|------|--------|-----------|
| **Python** | 55 | 12,000+ |
| **JavaScript/TypeScript** | 5 | 1,500+ |
| **HTML** | 1 | 150 |
| **CSS** | 1 | 400 |
| **Shell** | 1 | 80 |
| **Markdown** | 25 | 8,000+ |
| **JSON/YAML** | 10 | 500+ |
| **总计** | ~100 | 22,000+ |

### 3.2 目录统计

| 目录 | 文件数 | 说明 |
|------|--------|------|
| `callisto/` | 35 | 核心 Python 模块 |
| `scripts/` | 11 | 脚本工具 |
| `test_sessions/` | 100 | 测试数据 |
| `test_reports/` | 6 | 测试报告 |
| `web/` | 4 | Web Dashboard |
| `openclaw_plugin/` | 5 | OpenClaw 插件 |
| `docs/` | 2 | 文档 |
| `integration_examples/` | 3 | 集成示例 |
| `expert_test_sessions/` | ~20 | 专家测试数据 |
| 根目录 | 25 | 文档和配置 |

---

## 四、核心功能详解

### 4.1 检测引擎 (engine.py)

**8 类攻击检测**:

| 检测类型 | 代码 | 触发条件 |
|----------|------|----------|
| 速率洪水 | A1 | 5 秒内≥8 次调用 |
| 权限升级 | A2 | 提权命令匹配 |
| 数据外泄 | A3 | 工具 + 外部目标 |
| 行为漂移 | A4 | 工具分布突变 |
| 时序违例 | A5 | 危险操作顺序 |
| 状态投毒 | A6 | 写入配置文件 |
| 敏感读取 | P1/D1 | 敏感文件路径 |
| 内网访问 | L1/L2 | 内网 IP/域名 |

### 4.2 脱敏引擎 (sanitizer.py)

**15 类敏感信息**:

1. AWS Access Key
2. AWS Secret Key
3. GitHub Token
4. Slack Token
5. Stripe Key
6. Twilio Key
7. SendGrid Key
8. Mailgun Key
9. 数据库连接字符串
10. SSH 私钥
11. JWT Token
12. Google API Key
13. Azure Key
14. 通用密码模式
15. 通用 Token 模式

### 4.3 熔断器 (circuit_breaker.py)

**工作机制**:
- 连续 3 次 HIGH 风险告警 → 触发熔断
- 熔断后所有操作被阻断
- 需要手动调用 `resume()` 恢复

### 4.4 配置扫描 (scan_config.py)

**25 类安全规则**:
- Token 安全 (3 规则)
- 网络安全 (7 规则)
- 会话安全 (3 规则)
- 数据保护 (3 规则)
- 插件安全 (3 规则)
- 执行安全 (6 规则)

### 4.5 技能扫描 (scan_skills.py)

**8 类风险检测**:
1. 危险命令调用
2. 敏感文件访问
3. 网络 API 调用
4. eval/Function 使用
5. 加密算法使用
6. 文件系统操作
7. 环境变量访问
8. 技能导入

---

## 五、Web Dashboard 功能

### 5.1 界面组件

| 组件 | 功能 |
|------|------|
| Header | 服务状态指示 |
| 统计面板 | 24 小时告警统计 |
| 扫描控制 | 启动安全扫描 |
| 扫描结果 | 显示发现的问题 |
| 告警列表 | 实时告警流 |
| 会话列表 | 活跃会话状态 |
| 工具检查 | 手动检查工具调用 |

### 5.2 API 端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/` | GET | Dashboard 首页 |
| `/api/status` | GET | 服务状态 |
| `/api/stats` | GET | 统计数据 |
| `/api/scan` | POST | 运行扫描 |
| `/api/scan/results` | GET | 扫描结果 |
| `/api/alerts` | GET | 告警列表 |
| `/api/sessions` | GET | 会话列表 |
| `/api/events` | GET | SSE 事件推送 |
| `/api/tool/check` | POST | 工具检查 |

---

## 六、OpenClaw 集成

### 6.1 集成方式

```
OpenClaw → callisto-skill 插件 → callisto_agent.py → 检测引擎
```

### 6.2 自动触发

| 场景 | 触发功能 |
|------|----------|
| OpenClaw 启动 | 自动扫描配置和技能 |
| 工具调用 | 实时风险检测 + 脱敏 |
| 文件变更 | 监控模式自动重新扫描 |
| 风险累积 | 连续 3 次 HIGH 触发熔断 |

### 6.3 插件文件

- `openclaw_plugin/callisto-skill/src/index.js` - Node.js 入口
- `openclaw_plugin/callisto-skill/python/callisto_agent.py` - Python 后端

---

## 七、测试数据

### 7.1 测试会话 (test_sessions/)

**100 个测试文件**:
- 攻击类型：6 类
- 每类攻击：20 个样本
- 格式：JSONL

### 7.2 测试结果

| 测试项 | 通过率 |
|--------|--------|
| 批量测试 | 95.5% (63/66) |
| 扩展命令模式 | 100% (33/33) |
| 原有检测回归 | 100% (6/6) |
| OpenClaw 集成 | 100% (8/8) |

---

## 八、冗余文件识别

### 8.1 可删除文件

| 文件 | 原因 |
|------|------|
| `README.md.backup` | 备份文件 |
| `OPENCLAW_PLUGIN.md.backup` | 备份文件 |
| `scan_report.md` | 临时报告 |
| `skill_scan_report.md` | 临时报告 |
| `paper.*` | 论文相关（如不需要） |
| `callisto.egg-info/` | 构建产物 |
| `__pycache__/` | 缓存 |

### 8.2 可合并文档

以下文档内容有部分重叠，可考虑合并：
- `NEW_FEATURES_GUIDE.md` + `AUTO_INTEGRATION_GUIDE.md`
- `WEB_DASHBOARD_GUIDE.md` + `WEB_QUICKSTART.md`
- `AUTO_CALL_GUIDE.md` + `STARTUP_SCAN_GUIDE.md`

---

## 九、项目结构总览

```
callisto-plugin/
├── 📁 callisto/              # 核心 Python 模块
│   ├── __init__.py
│   ├── config.py
│   ├── engine.py             # 核心检测引擎
│   ├── sanitizer.py          # 脱敏引擎
│   ├── auto_config.py        # 自动配置
│   ├── web.py               # Web 启动
│   ├── cli.py               # 命令行
│   ├── monitor.py           # 监控器
│   ├── openclaw.py          # OpenClaw 集成
│   ├── detection/           # 检测模块
│   ├── collector/           # 收集器
│   ├── response/            # 响应模块
│   ├── features/            # 特征模块
│   ├── evaluation/          # 评估模块
│   └── attacks/             # 攻击模拟
│
├── 📁 scripts/              # 脚本工具
│   ├── auto_scanner.py      # 自动扫描器
│   ├── scan_config.py       # 配置扫描
│   ├── scan_skills.py       # 技能扫描
│   ├── monitor_openclaw.py  # 实时监控
│   ├── test_*.py           # 测试脚本
│   └── ...
│
├── 📁 web/                  # Web Dashboard
│   ├── index.html
│   ├── static/css/style.css
│   └── static/js/app.js
│
├── 📁 openclaw_plugin/      # OpenClaw 插件
│   └── callisto-skill/
│       ├── src/index.js
│       └── python/callisto_agent.py
│
├── 📁 test_sessions/        # 测试数据 (100 个文件)
├── 📁 test_reports/         # 测试报告
├── 📁 docs/                 # 文档
├── 📁 integration_examples/ # 集成示例
├── 📁 expert_test_sessions/ # 专家测试
├── 📁 reports/              # 各种报告
│
├── 📄 web_server.py         # FastAPI 应用
├── 📄 start-web.sh          # Web 启动脚本
├── 📄 pyproject.toml        # Python 配置
├── 📄 requirements.txt      # Python 依赖
├── 📄 package.json          # Node.js 配置
│
└── 📄 文档 (25 个 MD 文件)
    ├── README.md
    ├── QUICKSTART.md
    ├── API.md
    ├── WEB_*.md (4 个)
    ├── AUTO_*.md (2 个)
    └── ...
```

---

## 十、快速导航

### 10.1 新手入门

1. 阅读 `README.md` 了解项目
2. 阅读 `QUICKSTART.md` 快速开始
3. 运行 `./start-web.sh --open` 体验 Dashboard

### 10.2 开发者

1. 阅读 `API.md` 了解 API
2. 阅读 `DETECTION_LOGIC.md` 了解检测逻辑
3. 阅读 `CONTRIBUTING.md` 了解贡献流程

### 10.3 OpenClaw 用户

1. 阅读 `OPENCLAW_PLUGIN.md`
2. 阅读 `STARTUP_SCAN_GUIDE.md`
3. 阅读 `AUTO_CALL_GUIDE.md`

### 10.4 Web Dashboard 用户

1. 阅读 `WEB_QUICKSTART.md`
2. 阅读 `WEB_DASHBOARD_GUIDE.md`

---

## 十一、依赖清单

### Python 依赖

```
fastapi>=0.100.0
uvicorn>=0.23.0
sse-starlette>=1.6.0
pyyaml>=6.0
pydantic>=2.0.0
```

### Node.js 依赖

```
openclaw
express
typescript
```

---

## 十二、项目时间线

| 日期 | 事件 |
|------|------|
| 2026-04-20 | 项目初始化 |
| 2026-04-21 | 核心检测引擎完成 |
| 2026-04-22 | OpenClaw 插件集成 |
| 2026-04-23 | 自动扫描器完成 |
| 2026-04-23 | Web Dashboard 完成 |
| 2026-04-23 | 批量测试通过 (95.5%) |

---

**文档生成**: 2026-04-23  
**项目版本**: v2.0  
**总代码量**: ~22,000 行  
**总文件数**: ~100 个（不含依赖）
