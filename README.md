# CALLISTO

**Causal And LLM-Level Invocation Sequence Temporal Observer**

CALLISTO 是一个用于实时监控 LLM Agent API 滥用和行为异常的安全检测系统。

## 功能特性

- **实时检测** — 通过 OpenClaw 插件 hook 在工具调用前拦截检测
- **多层分析** — 内容安全、Shell 模式匹配、行为分析、因果图分析
- **熔断机制** — 连续高危告警自动阻断执行
- **Web 控制台** — 实时监控、告警历史、会话管理、报告导出
- **漏洞数据库** — 500+ OpenClaw 漏洞规则扫描
- **CLI 工具** — 离线扫描、实时监控、指纹训练、性能评估
- **内容安全** — 脚本分析、编码混淆检测、路径访问控制、网络白名单

## 安装

### 前置条件

- Python 3.10+
- Node.js 18+（如需 OpenClaw 插件功能）
- [OpenClaw](https://github.com/openclaw/openclaw)（可选，用于实时拦截）

### 方式一：仅安装 Python 核心（CLI + Web 面板）

```bash
git clone https://github.com/LytinLia/callisto.git
cd callisto

# 创建虚拟环境（推荐）
python3 -m venv .venv
source .venv/bin/activate

# 安装依赖
pip install -e ".[full,eval]"
```

### 方式二：安装 OpenClaw 插件（实时拦截）

```bash
# 1. 进入插件目录（如果你使用自定义路径，请调整）
cd ~/.openclaw/extensions/callisto-plugin

# 2. 安装 Python 依赖
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[full]"

# 3. 构建 TypeScript 插件
npm install
npm run build
```

### 方式三：从本地克隆

```bash
# 克隆到 OpenClaw 扩展目录
git clone https://github.com/LytinLia/callisto.git ~/.openclaw/extensions/callisto-plugin
cd ~/.openclaw/extensions/callisto-plugin

# 安装依赖
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[full]"
npm install && npm run build
```

## 配置

### 在 OpenClaw 中启用插件

编辑 `~/.openclaw/openclaw.json`：

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

### 环境变量（可选）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CALLISTO_THRESHOLD` | `3` | 熔断阈值（HIGH 风险操作数量） |
| `CALLISTO_PYTHON` | `python3` | Python 可执行文件路径 |

## 使用方式

### Web 控制台

```bash
cd ~/.openclaw/extensions/callisto-plugin
.venv/bin/python web_server.py
```

打开浏览器访问 `http://localhost:8765`，可以：

- 实时查看告警和会话状态
- 查看扫描结果和漏洞扫描
- 导出安全报告（HTML / Markdown / JSON）
- 管理熔断器状态

### CLI 工具

```bash
# 离线扫描会话日志
callisto scan ./logs/

# 实时监控
callisto monitor ./logs/ --block

# 训练行为指纹
callisto train ./logs/ --output fingerprints.json

# 性能评估
callisto eval --benign 100 --attacks 30
```

### Skill 手动扫描

在 OpenClaw 会话中使用：

```bash
openclaw callisto_status    # 查看安全状态
openclaw callisto_scan      # 扫描当前会话风险
openclaw callisto_block     # 手动触发熔断
```

## 测试

### 运行单元测试

```bash
cd ~/.openclaw/extensions/callisto-plugin

# 激活虚拟环境
source .venv/bin/activate

# 内容安全检测测试
python tests/content_safety_test.py

# 工具检测测试
python tests/callisto_vs_nsf_command_test.py
```

### 运行组合攻击检测

```bash
# SkillInject + MCPSafeBench 组合检测
python tests/skillinject_mcpsafe_test.py

# AgentDojo 检测测试
python tests/agentdojo_detection_test_v2.py

# 全面评估
python tests/eval_nsf_clawguard.py
```

### 测试 Python 后端（不依赖 OpenClaw）

```bash
# 发送测试请求检测
echo '{"tool_name":"read_file","parameters":{"path":"/etc/passwd"},"session_id":"test"}' | \
  .venv/bin/python openclaw_plugin/callisto-skill/python/callisto_agent.py detect

# 预期输出：检测到读取敏感文件 /etc/passwd，返回 HIGH 风险告警
```

### 测试 Web 面板

```bash
# 启动服务
.venv/bin/python web_server.py

# 另开终端，检查 API
curl http://localhost:8765/api/status
curl http://localhost:8765/api/alerts?limit=5
```

## 检测的攻击类型

### 核心检测（A 系列）

| 代码 | 类型 | 检测方式 |
|------|------|----------|
| A1 | `rate_flood` | 8 次调用/5 秒 |
| A2 | `privilege_escalation` | 敏感工具链（连续 2 次以上） |
| A3 | `data_exfil` | 敏感文件/内网访问 |
| A4 | `behavior_drift` | 工具分布变化 |
| A5 | `temporal_violation` | 时序违例（先删除后备份） |
| A6 | `state_poison` | 配置文件修改 |

### 细化场景

| 场景 | 说明 |
|------|------|
| 敏感文件读取 | `/etc/shadow`、SSH 密钥、云凭证、`.env` 等 40+ 路径模式 |
| 内网访问 | 私有 IP、localhost、云元数据端点 |
| 凭证文件 | `.aws/credentials`、`.gcloud/`、`.kube/config` |
| Shell 攻击 | 反弹 Shell、下载执行、管道注入、编码混淆 |
| 内容安全 | 提示注入、钓鱼链接、数据外泄模式 |
| 配置安全 | 硬编码 Token、不安全 HTTP、明文密码 |

### 风险级别与处理策略

| 级别 | 处理策略 | 示例 |
|------|----------|------|
| **HIGH** | 立即阻止，计入熔断计数 | 读取 `/etc/shadow`、访问内网 |
| **MEDIUM** | 记录警告，不阻止 | 读取普通配置文件 |
| **LOW** | 记录警告，不阻止 | 良性命令模式 |

## 熔断机制

当单个会话连续触发 `CALLISTO_THRESHOLD`（默认 3）个 HIGH 风险告警时，熔断器自动打开，阻止所有后续操作。

| 状态 | 说明 |
|------|------|
| **CLOSED** | 正常状态，允许操作 |
| **OPEN** | 已熔断，阻止所有操作 |

## 项目结构

```
callisto/           # 核心 Python 引擎（~13,700 行）
├── engine.py       # 检测引擎
├── monitor.py      # 实时监控器
├── content_safety.py  # 内容安全分析器
├── collector/      # 会话日志解析
├── detection/      # 检测算法
├── features/       # 特征提取
├── response/       # 响应处理 & 熔断器
├── vulndb/         # 漏洞数据库
├── report/         # 报告生成（HTML/MD/JSON）
├── evaluation/     # 性能评估框架
├── attacks/        # 攻击模拟
└── cli.py          # 命令行工具

web/                # Web 控制台（HTML/CSS/JS）
web_server.py       # FastAPI Web 服务

openclaw_plugin/    # OpenClaw 插件 + Skill
├── callisto-skill/ # Skill 工具
└── callisto-skill/python/callisto_agent.py  # 检测引擎

tests/              # 测试套件
docs/               # 文档
scripts/            # 实用脚本
paper/              # 学术论文（LaTeX）
```

## 日志与调试

| 日志文件 | 内容 |
|----------|------|
| `/tmp/callisto-plugin.log` | Plugin hook 调用日志 |
| `/tmp/callisto-python.log` | Python 检测引擎日志 |
| `/tmp/callisto-startup.log` | 插件启动日志 |

```bash
# 实时查看插件日志
tail -f /tmp/callisto-plugin.log

# 查看最近错误
grep ERROR /tmp/callisto-python.log
```

## 文档

| 文档 | 说明 |
|------|------|
| [docs/OVERVIEW.md](docs/OVERVIEW.md) | 项目架构 |
| [docs/DETECTION_LOGIC.md](docs/DETECTION_LOGIC.md) | 检测逻辑 |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | 贡献指南 |
| [docs/API.md](docs/API.md) | API 参考 |

## License

MIT License — 详见 [LICENSE](LICENSE)
