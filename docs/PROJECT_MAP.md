# CALLISTO 项目地图

**一句话介绍**: CALLISTO 是一个面向 LLM Agent 的运行时安全检测系统。

---

## 🚀 快速开始

```bash
# 启动 Web Dashboard
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin
./start-web.sh --open
```

**访问**: http://localhost:8765

---

## 📁 核心目录

| 目录 | 内容 | 进入 |
|------|------|------|
| `callisto/` | 核心 Python 代码 (12,000 行) | [详情](PROJECT_OVERVIEW.md#21-核心-python-模块-callisto) |
| `scripts/` | 脚本工具 (扫描器、测试) | [详情](PROJECT_OVERVIEW.md#28-脚本-scripts) |
| `web/` | Web Dashboard | [详情](#-web-功能) |
| `openclaw_plugin/` | OpenClaw 插件 | [详情](#-openclaw-集成) |
| `test_sessions/` | 测试数据 (100 个文件) | - |
| `test_reports/` | 测试报告 | [详情](PROJECT_OVERVIEW.md#212-测试报告-test_reports) |

---

## 📖 文档导航

### 入门文档

| 文档 | 适合 | 阅读时间 |
|------|------|----------|
| [README.md](README.md) | 所有人 | 5 分钟 |
| [QUICKSTART.md](QUICKSTART.md) | 新用户 | 3 分钟 |
| [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | 深入了解 | 20 分钟 |

### 功能文档

| 文档 | 内容 |
|------|------|
| [DETECTION_LOGIC.md](DETECTION_LOGIC.md) | 8 类攻击检测逻辑 |
| [API.md](API.md) | 完整 API 文档 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南 |

### OpenClaw 相关

| 文档 | 内容 |
|------|------|
| [OPENCLAW_PLUGIN.md](OPENCLAW_PLUGIN.md) | 插件说明 |
| [STARTUP_SCAN_GUIDE.md](STARTUP_SCAN_GUIDE.md) | 启动扫描指南 |
| [AUTO_CALL_GUIDE.md](AUTO_CALL_GUIDE.md) | 自动调用指南 |

### Web Dashboard

| 文档 | 内容 |
|------|------|
| [WEB_QUICKSTART.md](WEB_QUICKSTART.md) | 快速开始 |
| [WEB_DASHBOARD_GUIDE.md](WEB_DASHBOARD_GUIDE.md) | 详细指南 |
| [WEB_IMPLEMENTATION_SUMMARY.md](WEB_IMPLEMENTATION_SUMMARY.md) | 实现总结 |

### 自动扫描

| 文档 | 内容 |
|------|------|
| [AUTO_INTEGRATION_GUIDE.md](AUTO_INTEGRATION_GUIDE.md) | 自动集成 |
| [NEW_FEATURES_GUIDE.md](NEW_FEATURES_GUIDE.md) | 新功能指南 |

---

## 🛠️ 核心功能

### 1. 检测引擎

**8 类攻击检测**:
- 速率洪水、权限升级、数据外泄
- 行为漂移、时序违例、状态投毒
- 敏感文件读取、内网访问

**入口**: `callisto/engine.py`

### 2. 脱敏引擎

**15 类敏感信息**: AWS 密钥、GitHub Token、数据库凭证、SSH 私钥等

**入口**: `callisto/sanitizer.py`

### 3. 熔断器

**机制**: 连续 3 次 HIGH 告警 → 阻断会话

**入口**: `callisto/response/circuit_breaker.py`

### 4. 安全扫描

**配置文件扫描**: `scripts/scan_config.py` (25 类规则)  
**技能代码扫描**: `scripts/scan_skills.py` (8 类风险)  
**自动扫描器**: `scripts/auto_scanner.py`

### 5. Web Dashboard

**功能**: 实时监控、扫描管理、告警可视化  
**启动**: `./start-web.sh`  
**入口**: `web_server.py`

### 6. OpenClaw 集成

**插件位置**: `openclaw_plugin/callisto-skill/`  
**自动触发**: 启动扫描、工具调用检测

---

## 🔧 常用命令

### Web Dashboard

```bash
# 启动
./start-web.sh --open

# 开发模式
./start-web.sh --reload --open

# 自定义端口
./start-web.sh --port 8766
```

### 安全扫描

```bash
# 完整扫描
python scripts/auto_scanner.py --scan-all

# 仅配置扫描
python scripts/auto_scanner.py --scan-config

# 仅技能扫描
python scripts/auto_scanner.py --scan-skills

# 监控模式
python scripts/auto_scanner.py --watch 60
```

### 测试

```bash
# 批量测试验证
python scripts/batch_test_validation.py

# OpenClaw 集成测试
python scripts/test_openclaw_integration.py

# 新功能测试
python scripts/test_new_features.py
```

---

## 📊 项目统计

| 指标 | 数值 |
|------|------|
| 总代码量 | ~22,000 行 |
| Python 文件 | 55 个 |
| JavaScript 文件 | 5 个 |
| 文档文件 | 25 个 |
| 测试数据 | 100 个 |
| 测试通过率 | 95.5% |

---

## 🔗 关键文件

| 文件 | 作用 |
|------|------|
| `callisto/engine.py` | 核心检测引擎 |
| `callisto/sanitizer.py` | 脱敏引擎 |
| `scripts/auto_scanner.py` | 自动扫描器 |
| `web_server.py` | Web 服务器 |
| `openclaw_plugin/callisto-skill/python/callisto_agent.py` | OpenClaw 检测后端 |

---

## 🗑️ 冗余文件

**可删除**:
- `*.backup` (备份文件)
- `scan_report.md` (临时报告)
- `paper.*` (如不需要)
- `callisto.egg-info/` (构建产物)
- `__pycache__/` (缓存)

---

## 📅 时间线

- 2026-04-20: 项目初始化
- 2026-04-22: OpenClaw 插件集成
- 2026-04-23: Web Dashboard 完成
- 2026-04-23: 批量测试 95.5% 通过

---

## 🆘 获取帮助

1. **查看文档**: [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)
2. **查看 API**: http://localhost:8765/docs
3. **查看日志**: `tail -f /tmp/callisto-python.log`

---

**项目位置**: `/Users/jiangqiang/.openclaw/extensions/callisto-plugin`  
**当前版本**: v2.0  
**最后更新**: 2026-04-23
