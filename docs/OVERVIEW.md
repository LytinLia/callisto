# CALLISTO 项目总体架构

**CALLISTO** (Causal And LLM-Level Invocation Sequence Temporal Observer) 是一个用于实时监控 LLM Agent API 滥用和行为异常的安全检测系统。

本文档介绍项目的完整架构、组件关系和使用场景。

---

## 项目组成

CALLISTO 项目由三个主要部分组成：

```
CALLISTO 项目
├── Python 包（核心引擎）
├── OpenClaw 插件（实时拦截）
└── OpenClaw Skill（手动扫描）
```

### 1. Python 包（核心引擎）

**位置**: `callisto/`

**功能**:
- 检测引擎 (`engine.py`)
- 实时监控器 (`monitor.py`)
- CLI 工具 (`cli.py`, `__main__.py`)
- 特征提取 (`features/`)
- 检测算法 (`detection/`)
- 响应处理 (`response/`)
- 评估框架 (`evaluation/`)
- 攻击模拟 (`attacks/`)

**使用方式**:
```bash
# 离线扫描
callisto scan ./logs/

# 实时监控
callisto monitor ./logs/ --block

# 训练指纹
callisto train ./logs/ --output fingerprints.json

# 性能评估
callisto eval --benign 100 --attacks 30
```

### 2. OpenClaw 插件（实时拦截）

**位置**: `index.ts`, `dist/index.js`

**功能**:
- `before_tool_call` hook 实时拦截
- 调用 Python 后端进行风险检测
- 根据风险级别决定是否阻止
- 熔断器状态管理

**使用方式**:
```json
// ~/.openclaw/openclaw.json
{
  "plugins": {
    "allow": ["callisto-plugin"]
  }
}
```

### 3. OpenClaw Skill（手动扫描）

**位置**: `openclaw_plugin/callisto-skill/`

**功能**:
- `callisto_scan` - 扫描会话风险
- `callisto_status` - 查看安全状态
- `callisto_block` - 手动触发熔断

**使用方式**:
```bash
openclaw callisto_scan
openclaw callisto_status
```

---

## 架构层次

CALLISTO 采用四层架构设计：

```
┌─────────────────────────────────────────────────────┐
│ Layer 4: Response (响应层)                          │
│ - AlertRanker (告警排序)                            │
│ - CircuitBreaker (熔断器)                           │
│ - Explainer (告警解释)                              │
├─────────────────────────────────────────────────────┤
│ Layer 3: Detection (检测层)                         │
│ - CausalResponsibilityScorer (因果责任评分)         │
│ - MABOCPD (变点检测)                                │
│ - CrossSessionFingerprinter (跨会话指纹)            │
├─────────────────────────────────────────────────────┤
│ Layer 2: Features (特征层)                          │
│ - TemporalExtractor (时序特征)                      │
│ - StructuralExtractor (结构特征)                    │
│ - SemanticExtractor (语义特征)                      │
├─────────────────────────────────────────────────────┤
│ Layer 1: Collector (收集层)                         │
│ - Session/CallEvent 模型                            │
│ - OpenClaw 日志解析器                                │
│ - Interceptor (拦截器)                              │
└─────────────────────────────────────────────────────┘
```

### Layer 1: Collector (收集层)

**职责**: 收集和标准化事件数据

**核心模型**:
- `Session`: 会话容器
- `CallEvent`: 单次工具调用事件
- `EventType`: 事件类型（TOOL_CALL, TOOL_RESULT）
- `RiskLevel`: 风险级别（LOW, MEDIUM, HIGH, CRITICAL）
- `AttackType`: 攻击类型枚举

**组件**:
- `openclaw_parser.py`: 解析 OpenClaw JSONL 日志
- `interceptor.py`: 工具调用拦截器

### Layer 2: Features (特征层)

**职责**: 从原始事件中提取特征

**特征提取器**:
- `TemporalExtractor`: 时序特征（调用间隔、频率、工具分布）
- `StructuralExtractor`: 结构特征（调用 DAG、依赖关系）
- `SemanticExtractor`: 语义特征（事件嵌入向量）

### Layer 3: Detection (检测层)

**职责**: 基于特征进行异常检测

**检测算法**:
- `CausalResponsibilityScorer`: 因果责任评分，识别高风险工具链
- `MABOCPD` (Meta-Adaptive Bayesian Online Changepoint Detection): 在线变点检测
- `CrossSessionFingerprinter`: 跨会话行为指纹比对

**检测规则**:
- 速率洪水检测（A1）
- 权限升级检测（A2）
- 数据外泄检测（A3）
- 行为漂移检测（A4）
- 时序违例检测（A5）
- 状态投毒检测（A6）
- 敏感文件读取（P1/D1）
- 内网访问检测（L1/L2）
- 凭证文件访问（L3）

### Layer 4: Response (响应层)

**职责**: 处理检测结果并响应

**组件**:
- `AlertRanker`: 告警排序和去重（cooldown 机制）
- `CircuitBreaker`: 熔断器（连续 HIGH 风险触发）
- `AlertExplainer`: 告警解释（生成人类可读说明）

---

## 数据流

### 实时拦截流程

```
OpenClaw 工具调用
       │
       ▼
┌─────────────────────┐
│ before_tool_call    │
│ (Plugin Hook)       │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ callisto_agent.py   │
│ (Python 检测)        │
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    │           │
    ▼           ▼
┌───────┐   ┌─────────┐
│ HIGH  │   │ MEDIUM/ │
│ 风险  │   │ LOW 风险│
└───┬───┘   └────┬────┘
    │            │
    ▼            ▼
┌────────┐   ┌────────┐
│ 阻止   │   │ 放行   │
│ +告警  │   │ +记录  │
└────────┘   └────────┘
```

### 离线扫描流程

```
JSONL 日志文件
       │
       ▼
┌─────────────────────┐
│ openclaw_parser.py  │
│ (解析日志)          │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ CallistoEngine      │
│ (检测引擎)          │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ AlertExplainer      │
│ (生成报告)          │
└─────────────────────┘
```

---

## 检测的攻击类型

### A 系列（核心检测）

| 代码 | 类型 | 说明 | 检测方式 |
|------|------|------|----------|
| A1 | `rate_flood` | 速率洪水 | 8 次调用/5 秒 |
| A2 | `privilege_escalation` | 权限升级 | 敏感工具链 ≥2 次 |
| A3 | `data_exfil` | 数据外泄 | 敏感文件/内网访问 |
| A4 | `behavior_drift` | 行为漂移 | 工具分布变化 |
| A5 | `temporal_violation` | 时序违例 | 先删除后备份 |
| A6 | `state_poison` | 状态投毒 | 修改配置文件 |

### P/D/L 系列（细化场景）

| 代码 | 类型 | 说明 | 示例 |
|------|------|------|------|
| P1/D1 | `data_exfil` | 敏感文件读取 | `/etc/passwd`, `id_rsa` |
| L1/L2 | `data_exfil` | 内网访问 | `192.168.x.x`, `.internal` |
| L3 | `privilege_escalation` | 凭证访问 | `.aws/credentials` |

---

## 使用场景对比

| 场景 | 推荐组件 | 命令/方式 |
|------|----------|----------|
| OpenClaw 实时保护 | Plugin | 自动生效 |
| 手动安全检查 | Skill | `callisto_scan` |
| 历史日志分析 | Python CLI | `callisto scan ./logs/` |
| 持续实时监控 | Python CLI | `callisto monitor ./logs/ --block` |
| 行为指纹训练 | Python CLI | `callisto train ./logs/` |
| 性能评估 | Python CLI | `callisto eval` |

---

## 项目目录结构

```
callisto-plugin/
├── callisto/                        # Python 包（核心引擎）
│   ├── __main__.py                 # CLI 入口
│   ├── cli.py                      # 命令行界面
│   ├── engine.py                   # 检测引擎主逻辑
│   ├── monitor.py                  # 实时监控器
│   ├── config.py                   # 配置管理
│   ├── openclaw.py                 # OpenClaw 集成
│   ├── collector/                  # 收集层
│   ├── features/                   # 特征层
│   ├── detection/                  # 检测层
│   ├── response/                   # 响应层
│   ├── attacks/                    # 攻击模拟
│   └── evaluation/                 # 评估框架
├── openclaw_plugin/
│   └── callisto-skill/
│       ├── SKILL.md                # Skill 元数据
│       ├── src/index.js            # Skill Node.js 入口
│       └── python/callisto_agent.py # Python 后端
├── index.ts                        # Plugin 入口（TypeScript）
├── dist/index.js                   # 编译后的 Plugin
├── openclaw.plugin.json            # Plugin 清单
├── package.json                    # npm 配置
├── pyproject.toml                  # Python 包配置
├── scripts/                        # 工具脚本
├── integration_examples/           # 集成示例
├── test_sessions/                  # 测试会话日志
├── test_reports/                   # 测试报告
├── reports/                        # 生成的报告
└── docs/                           # 文档
```

---

## 配置说明

### 环境变量

```bash
# 启用 CALLISTO
export CALLISTO_ENABLED=1

# 熔断阈值（HIGH 风险操作数量）
export CALLISTO_THRESHOLD=3

# Python 可执行文件路径
export CALLISTO_PYTHON=/path/to/python3
```

### OpenClaw 配置

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

### Python 包配置

```python
from callisto.config import CallistoConfig

config = CallistoConfig(
    circuit_breaker_threshold=3,
    crs_threshold=0.7,
    bocpd_threshold=0.5,
    burst_window=5.0,
    burst_count_threshold=8,
)
```

---

## 性能指标

### 检测性能（基于合成数据集评估）

| 指标 | 数值 |
|------|------|
| Precision | >0.95 |
| Recall | >0.90 |
| F1 Score | >0.92 |
| False Positive Rate | <0.05 |

### 处理效率

| 指标 | 数值 |
|------|------|
| 平均每会话处理时间 | <50ms |
| 实时检测延迟 | <100ms |
| 内存占用 | ~100MB |

---

## 相关文档

- [README.md](../README.md) - 项目入门指南
- [OPENCLAW_PLUGIN.md](../OPENCLAW_PLUGIN.md) - OpenClaw 插件使用
- [DETECTION_LOGIC.md](../DETECTION_LOGIC.md) - 检测逻辑详解
- [API.md](../API.md) - API 参考文档

---

**更新时间**: 2026-04-22
