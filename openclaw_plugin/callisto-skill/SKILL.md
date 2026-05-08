---
name: callisto
description: "CALLISTO 安全检测 - 实时风险操作检测和熔断阻断。用于：(1) 敏感文件读取检测 (2) 权限升级检测 (3) 数据外泄检测 (4) 熔断高风险会话"
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "requires": { "bins": ["python3"], "env": ["CALLISTO_ENABLED"] },
        "env":
          [
            {
              "name": "CALLISTO_ENABLED",
              "value": "1",
              "description": "启用 CALLISTO 安全检测",
              "required": false,
            },
            {
              "name": "CALLISTO_THRESHOLD",
              "value": "3",
              "description": "熔断阈值（HIGH 风险操作数量）",
              "required": false,
            },
          ],
      },
  }
---

# CALLISTO Security Skill

使用 CALLISTO 进行实时安全风险检测和熔断阻断。

## 当使用此 Skill

✅ **使用此 skill 当：**

- 检测 Agent 的敏感文件读取操作
- 监控权限升级行为
- 检测数据外泄风险
- 熔断高风险会话（达到阈值自动阻断）

## 不使用此 Skill

❌ **不使用此 skill 当：**

- 仅需要日志审计（使用普通日志记录）
- 已在 Agent 框架内部集成安全检测
- 不需要实时阻断（仅事后分析）

## 设置

```bash
# 环境变量配置
export CALLISTO_ENABLED=1
export CALLISTO_THRESHOLD=3  # 3 个 HIGH 告警触发熔断

# 验证安装
openclaw skills list
```

## 工具调用

### `callisto_scan`

扫描当前会话的安全风险。

```bash
# 扫描当前会话
openclaw callisto_scan
```

### `callisto_block`

手动触发熔断，阻断当前会话。

```bash
openclaw callisto_block --reason "手动触发"
```

### `callisto_status`

查看当前安全状态和熔断器状态。

```bash
openclaw callisto_status
```

## 输出示例

### 正常操作

```json
{
  "status": "ok",
  "session_id": "abc123",
  "alerts": [],
  "circuit_breaker": "CLOSED"
}
```

### 检测到风险

```json
{
  "status": "warning",
  "session_id": "abc123",
  "alerts": [
    {
      "type": "data_exfil",
      "risk_level": "HIGH",
      "score": 0.85,
      "explanation": "尝试读取敏感内容：.../etc/passwd..."
    }
  ],
  "circuit_breaker": "CLOSED"
}
```

### 熔断触发

```json
{
  "status": "blocked",
  "session_id": "abc123",
  "reason": "Circuit breaker OPEN - 3 consecutive HIGH risk operations",
  "circuit_breaker": "OPEN"
}
```

## 检测的攻击类型

| 类型 | 代码 | 说明 |
|------|------|------|
| A1 | `rate_flood` | 速率洪水检测 |
| A2 | `privilege_escalation` | 权限升级检测 |
| A3 | `data_exfil` | 数据外泄检测 |
| A4 | `behavior_drift` | 行为漂移检测 |
| A5 | `temporal_violation` | 时序违例检测 |
| A6 | `state_poison` | 状态投毒检测 |
| P1/D1 | `data_exfil` | 敏感文件读取 |
| L1/L2 | `data_exfil` | 内网访问检测 |
| L3 | `privilege_escalation` | 凭证访问检测 |

## 配置参数

在 `~/.openclaw/openclaw.json` 中添加：

```json
{
  "plugins": {
    "entries": {
      "callisto-plugin": {
        "config": {
          "threshold": 3,
          "cooldown": 60
        }
      }
    }
  }
}
```

## 故障排除

### 问题 1: Skill 未找到

```bash
# 检查 Skill 是否加载
openclaw skills list | grep callisto
```

### 问题 2: 熔断未触发

- 检查阈值设置是否过低
- 确认风险操作触发了检测规则
- 查看详细日志：`cat /tmp/callisto-plugin.log`

### 问题 3: Python 调用失败

```bash
# 检查 Python 是否安装
python3 --version

# 测试 Python 后端
echo '{"tool_name":"exec","parameters":{"command":"ls"},"session_id":"test"}' | \
  python3 ~/.openclaw/extensions/callisto-plugin/openclaw_plugin/callisto-skill/python/callisto_agent.py detect
```
