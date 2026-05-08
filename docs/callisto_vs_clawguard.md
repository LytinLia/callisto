# CALLISTO vs ClawGuard 检测率对比分析

## 1. 总体对比

| 数据集/场景 | ClawGuard | CALLISTO | 差距 |
|------------|-----------|----------|------|
| **AgentDojo** | **100%** (35/35) | **88.6%** (31/35) | -11.4pp |
| **SkillInject** | 无公开数据 | **92%** (54/59) | — |
| **MCPSafeBench** | 无公开数据 | **97%** (34/35) | — |
| **内容安全审查** | sanitizer 25+ 模式 | **100%** (28/28) | 同等水平 |
| **内置工具覆盖** | ~5 个（仅 `cg_*` 封装的） | ~26 个（扩展后） | CALLISTO 更广 |

> **关键结论**：ClawGuard 的 AgentDojo 100% 不是检测引擎更强，而是**架构层面的防御纵深**——通过工具替换 + 白名单 + 人工审批把漏报风险降到 0。代价是只覆盖 5 个封装工具，且依赖人工审批。

---

## 2. ClawGuard 高于 CALLISTO 的地方

### 2.1 AgentDojo：100% vs 88.6%

**差距来源：4 个 AgentDoji workspace 场景漏报**

| 漏报用例类型 | 原因 |
|---------|------|
| 非 Exec 工具调用（隐蔽语义攻击） | 语义隐蔽，模式匹配无法识别 |

### 2.2 为什么 ClawGuard 能 100% 挡住

ClawGuard 的防护不依赖"检测恶意"，而是**默认拒绝一切不在白名单中的操作**：

```
ClawGuard:  工具调用 → 白名单匹配？→ 否 → APPROVE → 等人工 → 超时 → 拒绝 ✅
CALLISTO:   工具调用 → 黑名单匹配？→ 否 → 默认允许 → 放行 ❌
```

具体机制：

1. **L1 — Gateway Tool Block**：在 OpenClaw Gateway 层直接禁用原生 `exec`/`write`/`edit`/`apply_patch` 工具，Agent 物理上无法调用被禁用的工具
2. **工具替换**：Agent 只能通过 `cg_*` 工具（`cg_execute_command`、`cg_read_file`、`cg_write_file`、`cg_http_request`、`cg_list_directory`）执行操作
3. **APPROVE 审批回路**：对不在白名单中的操作，返回 `ActionType.APPROVE`，暂停并等待人工审批，超时自动拒绝
4. **Sanitizer 输出清洗**：过滤工具输出中的 15+ 类敏感数据，防止注入内容进入对话历史

**本质区别**：ClawGuard 不需要"检测"攻击——它通过缩小攻击面 + 人工兜底实现了 100% 防御。

---

## 3. CALLISTO 高于/优于 ClawGuard 的地方

### 3.1 内置工具覆盖

| 维度 | CALLISTO | ClawGuard |
|------|----------|-----------|
| 覆盖工具数 | **~26 个**（扩展后） | **~5 个**（仅 `cg_*` 封装的） |
| web_search / x_search | 搜索注入检测 | 不覆盖 |
| browser | 导航到 exfil 站点/元数据端点检测 | 不覆盖 |
| code_execution | 代码注入/外泄/危险系统调用检测 | 不覆盖 |
| message | 钓鱼/凭证请求/广播检测 | 不覆盖 |
| cron | 持久化/高频 DoS 检测 | 不覆盖 |
| gateway | 配置篡改/重启检测 | 不覆盖 |
| memory / sessions / nodes | 操纵/注入/隐私操作检测 | 不覆盖 |
| image_generate / video_generate | 提示词注入检测 | 不覆盖 |

**原因**：ClawGuard 只封装了 5 个工具，其他 OpenClaw 内置工具（browser、message、cron、code_execution 等）完全不经过它的引擎。CALLISTO 作为旁路检测器，对所有工具调用进行分析。

### 3.2 提示词注入检测

| 维度 | CALLISTO | ClawGuard |
|------|----------|-----------|
| 注入检测 | `_INJECTION_PATTERNS` **15+ 条**（含中文） | 无专门注入检测 |
| 覆盖类型 | ignore previous、system prompt override、jailbreak、角色操纵、URL 注入、中文注入 | 依赖 sanitizer 正则替换 |
| 输入/输出双阶段 | `analyze_text(stage="input|output")` | 仅输出 sanitization |

### 3.3 会话级分析

| 维度 | CALLISTO | ClawGuard |
|------|----------|-----------|
| 速率洪水检测 | 5 秒窗口内 ≥8 次调用 → 告警 | 无 |
| 因果图分析 | 识别工具调用之间的危险链 | 无（单点检测） |
| 操作链分析 | 读取+转发、多步收集+外发 | 无 |
| 状态投毒检测 | `StatePoison` 模块 | 无 |
| 自动熔断 | `CircuitBreaker`（连续 HIGH 告警自动阻断） | 需人工审批（APPROVE 等人工） |

### 3.4 部署方式

| 维度 | CALLISTO | ClawGuard |
|------|----------|-----------|
| 部署方式 | **旁路检测**，不修改工具链 | **中间人**，需替换工具、修改 config |
| 对 Agent 的影响 | 无（仅记录和告警） | 大（工具被替换，部分功能不可用） |
| 依赖人工 | 否（全自动） | 是（APPROVE 需人工审批） |
| 延迟 | 低（仅增加分析时间） | 高（审批回路最长 60 秒超时） |

---

## 4. 核心架构差异

| 维度 | ClawGuard | CALLISTO |
|------|-----------|----------|
| **策略** | 白名单（默认拒绝） | 黑名单（默认允许） |
| **工具控制** | Gateway 层禁用 + 替换 | 旁路检测，不阻止调用 |
| **人类回路** | 有（APPROVE 审批） | 无（全自动） |
| **检测时机** | 工具调用前拦截 | 工具调用时/后检测 |
| **检测范围** | ~5 个封装工具 | 全部 32+ 个内置工具 |
| **语义理解** | 无（纯正则/模式） | 无（纯正则/模式） |
| **会话级分析** | 无（单点检测） | 有（因果图、操作链、时序） |
| **零日免疫** | 是（白名单天然免疫） | 否（需要新增规则） |
| **误报风险** | 低（白名单越配越安全） | 中（黑名单可能漏报） |
| **部署复杂度** | 高（替换工具 + 修改 config + daemon） | 低（纯插件，无需修改配置） |

---

## 5. 漏报根因分析

### 5.1 CALLISTO 在 AgentDojo 的 4 个漏报

| 漏报类型 | 根因 | 修复难度 |
|---------|------|---------|
| 非 Exec 工具的隐蔽语义攻击 | 模式匹配无法覆盖语义层面的风险（如 `echo $PATH` 环境信息暴露） | 高（需要 LLM 语义理解） |
| workspace 场景的跨步操作 | 单步检测无法识别多步组合的危险性 | 中（需要因果图增强） |

### 5.2 ClawGuard 在未公开数据集上的潜在漏报

| 潜在漏报类型 | 原因 |
|---------|------|
| `web_search` 搜索注入 | 搜索不经过 `cg_*` 工具，直接绕过 ClawGuard |
| `browser` 导航到恶意站点 | browser 工具未被 ClawGuard 封装 |
| `message` 钓鱼/外发 | message 工具未被 ClawGuard 封装 |
| `cron` 持久化攻击 | cron 工具未被 ClawGuard 封装 |
| `code_execution` 代码注入 | code_execution 工具未被 ClawGuard 封装 |

---

## 6. 总结

### 各自适用场景

| 场景 | 推荐方案 | 原因 |
|------|---------|------|
| **需要 100% 防御保证** | ClawGuard | 白名单 + 审批回路天然免疫未知攻击 |
| **全工具覆盖，自动化检测** | CALLISTO | 旁路检测覆盖全部 32+ 个工具，无需人工 |
| **低延迟、无感部署** | CALLISTO | 不修改工具链，仅增加毫秒级分析 |
| **合规要求人工审批** | ClawGuard | APPROVE 审批回路满足审计要求 |
| **检测提示词注入** | CALLISTO | 专门的注入检测层，含中文支持 |
| **会话级行为分析** | CALLISTO | 因果图、操作链、时序分析 |

### 互补性

两者可以**组合使用**以获得最大覆盖：

- **ClawGuard** 作为 L1 防线：替换核心工具（exec、read、write、http），提供白名单 + 审批回路
- **CALLISTO** 作为 L2 防线：旁路检测所有工具调用，覆盖 ClawGuard 未封装的工具，检测提示词注入和会话级异常

```
用户输入 → CALLISTO content_analysis(stage="input") → 注入检测
              ↓
         工具调用 → ClawGuard L1（白名单 + 审批）
              ↓
         工具调用 → CALLISTO detect()（旁路检测全部工具）
              ↓
         工具输出 → CALLISTO content_analysis(stage="output") → 外泄检测
              ↓
         工具输出 → ClawGuard L3（sanitizer 清洗）
```
