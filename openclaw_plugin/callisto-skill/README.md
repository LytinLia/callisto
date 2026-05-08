# CALLISTO OpenClaw Skill

CALLISTO 安全检测的 OpenClaw Skill 接口，提供手动风险扫描和状态查询功能。

> **注意**: 本 Skill 与 [Plugin](../../OPENCLAW_PLUGIN.md) 共用同一个 Python 后端，但使用场景不同：
> - **Plugin**: 自动拦截，实时阻断
> - **Skill**: 手动扫描，状态查询

---

## 快速开始

### 在 OpenClaw 中使用

```bash
# 查看安全状态
openclaw callisto_status

# 扫描当前会话风险
openclaw callisto_scan

# 手动触发熔断
openclaw callisto_block --reason "可疑行为"
```

### 在会话中调用

```
/try
  调用 callisto_scan 扫描当前会话的安全风险
```

---

## 工具说明

### `callisto_scan`

扫描当前会话的安全风险。

**输入参数：**
- `session_id` (可选) - 会话 ID，默认使用当前会话

**输出示例：**
```json
{
  "status": "warning",
  "alerts": [
    {
      "type": "data_exfil",
      "risk": "HIGH",
      "score": 0.85,
      "explanation": "尝试读取敏感文件：/etc/passwd"
    }
  ],
  "session_id": "abc123"
}
```

### `callisto_status`

查看当前安全状态和熔断器状态。

**输出示例：**
```json
{
  "status": "ok",
  "circuit_breaker": "CLOSED",
  "consecutive_alerts": 1,
  "threshold": 3,
  "session_id": "abc123"
}
```

### `callisto_block`

手动触发熔断，阻断当前会话。

**输入参数：**
- `session_id` (可选) - 会话 ID
- `reason` (可选) - 阻断原因

**输出示例：**
```json
{
  "status": "blocked",
  "message": "Session manually blocked",
  "session_id": "abc123"
}
```

---

## 技术架构

```
┌─────────────────────────────────────────────┐
│           OpenClaw Skill Router             │
└─────────────────┬───────────────────────────┘
                  │
    ┌─────────────▼──────────────┐
    │     callisto-skill         │
    │  ┌──────────────────────┐  │
    │  │ src/index.js         │  │
    │  │ (Node.js 入口)        │  │
    │  └──────────┬───────────┘  │
    │             │ spawn()     │
    │  ┌──────────▼───────────┐  │
    │  │ python/              │  │
    │  │ callisto_agent.py    │  │
    │  │ (检测引擎)           │  │
    │  └──────────────────────┘  │
    └────────────────────────────┘
```

### 组件说明

| 文件 | 作用 |
|------|------|
| `src/index.js` | Node.js 入口，导出 `tools` 给 OpenClaw |
| `python/callisto_agent.py` | Python 检测引擎，执行实际风险分析 |
| `SKILL.md` | OpenClaw Skill 元数据定义 |

---

## 与 Plugin 的关系

```
CALLISTO OpenClaw 集成
├── Plugin (index.ts) ────── 实时拦截 (before_tool_call hook)
└── Skill (callisto-skill) ─ 手动扫描 (用户主动调用)
    └── 共用 Python 后端 (callisto_agent.py)
```

**检测逻辑一致性：**
- 两者调用同一个 Python 脚本
- 使用相同的敏感路径模式、恶意命令模式
- 返回相同格式的告警结果

---

## 安装方法

Skill 已随插件打包，无需单独安装。确保在 `~/.openclaw/openclaw.json` 中已配置：

```json
{
  "plugins": {
    "allow": ["callisto-plugin"]
  }
}
```

---

## 使用场景

### 场景 1: 会话中安全检查

```
用户：帮我检查刚才的操作是否有安全风险
助手：好的，我来调用 callisto_scan 扫描...
     [扫描完成，发现 1 个 HIGH 风险告警]
```

### 场景 2: 查看当前状态

```
用户：当前的安全状态如何？
助手：调用 callisto_status 查看...
     [熔断器：CLOSED, 连续告警数：0]
```

### 场景 3: 手动阻断可疑会话

```
用户：这个会话行为可疑，阻断它
助手：好的，调用 callisto_block...
     [会话已阻断]
```

---

## 输出格式说明

### 正常状态

```json
{
  "status": "ok",
  "message": "No security issues detected",
  "session_id": "abc123"
}
```

### 检测到风险

```json
{
  "status": "warning",
  "alerts": [
    {
      "type": "data_exfil",
      "risk": "HIGH",
      "score": 0.85,
      "explanation": "访问内网地址：192.168.1.100"
    }
  ],
  "session_id": "abc123"
}
```

### 熔断状态

```json
{
  "status": "blocked",
  "error": "Session blocked by CALLISTO circuit breaker",
  "details": {
    "circuit_breaker": "OPEN",
    "consecutive_alerts": 3
  }
}
```

---

## 故障排除

### Skill 未找到

```bash
# 检查 Skill 是否加载
openclaw skills list | grep callisto

# 重启 OpenClaw
pkill -f openclaw
openclaw gateway --force
```

### 调用超时

```bash
# 检查 Python 是否可用
python3 --version

# 测试 Python 后端
echo '{"tool_name":"exec","parameters":{"command":"ls"},"session_id":"test"}' | \
  python3 ~/.openclaw/extensions/callisto-plugin/openclaw_plugin/callisto-skill/python/callisto_agent.py detect
```

### 查看详细日志

```bash
# Skill 日志
cat /tmp/callisto-python.log

# Plugin 日志
cat /tmp/callisto-plugin.log
```

---

## 开发指南

### 本地调试

```bash
# 1. 修改 Node.js 入口
vim src/index.js

# 2. 修改 Python 后端
vim python/callisto_agent.py

# 3. 测试 Python 后端
echo '{"tool_name":"exec","parameters":{"command":"cat /etc/passwd"},"session_id":"test"}' | \
  python3 python/callisto_agent.py detect
```

### 添加新工具

在 `src/index.js` 中添加：

```javascript
export const tools = {
  // ...现有工具
  
  /**
   * 新增工具
   */
  callisto_new_tool: async (args) => {
    const result = await callCallisto('new_action', {
      session_id: args.session_id
    });
    return { status: 'ok', data: result };
  }
};
```

---

## 参考文档

- [SKILL.md](SKILL.md) - Skill 元数据定义
- [OPENCLAW_PLUGIN.md](../../OPENCLAW_PLUGIN.md) - Plugin 使用指南
- [README.md](../../README.md) - 项目总体介绍

---

**更新时间**: 2026-04-22
