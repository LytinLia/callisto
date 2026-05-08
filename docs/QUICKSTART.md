# CALLISTO 启动监控 - 快速参考

## 三种启动方式

### 方式 1: Bash 脚本（推荐）

```bash
cd /Users/jiangqiang/Downloads/callisto

# 仅监控
./scripts/start_openclaw_with_monitor.sh

# 监控 + 自动熔断
./scripts/start_openclaw_with_monitor.sh --block

# 监控 + 熔断 + 报告
./scripts/start_openclaw_with_monitor.sh --block --report
```

**说明**: 运行后会启动监控进程，然后显示提示信息。此时：
- 在**另一个终端**运行 `openclaw` 开始使用
- 或在此终端按 `Ctrl+C` 后手动运行 `openclaw`

### 方式 2: 手动启动（最灵活）

```bash
# 终端 1：启动监控
python scripts/monitor_openclaw.py --monitor \
  --log-file "~/.openclaw/agents/main/sessions/*.jsonl"

# 终端 2：启动 OpenClaw
openclaw
```

### 方式 3: 后台运行监控

```bash
# 后台启动监控
nohup python scripts/monitor_openclaw.py --monitor \
  --log-file "~/.openclaw/agents/main/sessions/*.jsonl" &

# 然后随时启动 OpenClaw
openclaw
```

---

## 选项说明

| 选项 | 说明 |
|------|------|
| `--block` | 启用自动熔断（3 个 HIGH 告警触发） |
| `--report` | 生成检测报告 |
| `-h, --help` | 显示帮助 |

---

## 监控配置

- **日志目录**: `~/.openclaw/agents/main/sessions/`
- **扫描间隔**: 0.3 秒
- **Cooldown**: 1 秒
- **熔断阈值**: 3 个 HIGH 告警

---

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
| L3 | `data_exfil` | 凭证访问检测 |

---

## 文件位置

| 文件 | 路径 |
|------|------|
| 启动脚本 | `scripts/start_openclaw_with_monitor.sh` |
| 监控脚本 | `scripts/monitor_openclaw.py` |
| 检测引擎 | `callisto/engine.py` |
| 配置 | `callisto/config.py` |
| 文档 | `docs/openclaw_startup_guide.md` |

---

**更新时间**: 2026-04-21
