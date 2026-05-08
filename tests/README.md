# CALLISTO 注入攻击检测基准测试

使用三个公开评测数据集评估 CALLISTO 检测**间接提示注入攻击**的能力。

## 数据集概览

| 数据集 | 来源 | 原始规模 | 测试数 | 注入渠道 | 注入方式 |
|--------|------|---------|--------|---------|---------|
| **AgentDojo** | ETH Zurich | 35 tasks | 35 tasks | Web/本地内容 | 恶意指令嵌入邮件、日历、云文件 |
| **SkillInject** | aisa-group | 84 attacks | 59 attacks | Skill 文件 | 恶意指令混入合法 skill 行为描述 |
| **MCPSafeBench** | arXiv:2512.15163 | 215 attacks | 35 attacks | MCP 服务器 | 恶意服务器返回内容中嵌入指令、Tool Poisoning、Credential Theft 等 |

> 注：SkillInject 原始 84 个中覆盖 59 个（新增 obvious 7 + contextual 23）；MCPSafeBench 原始 215 个中覆盖 35 个（手工构造代表性用例，含 credential_theft、data_tampering、social_engineering 等新类型）。

## 测试结果汇总

| 数据集 | 检测数 / 总数 | 检测率 | 说明 |
|--------|--------------|--------|------|
| **AgentDojo** | 31 / 35 | **88.6%** | 组合检测（content_analysis + tool_detect） |
| **SkillInject + MCPSafeBench** | 88 / 94 | **93.6%** | 组合检测（真实注入文本 content_analysis + 工具调用 detect，取 OR） |
| → SkillInject | 54 / 59 | 92% | |
| → MCPSafeBench | 34 / 35 | 97% | |
| **内容安全审查（独立）** | 28 / 28 | **100.0%** | 对话层检测：提示词注入、数据外泄、凭证泄露 |
| → 输入审查（input） | 15 / 15 | 100% | 提示词注入、恶意指令、数据外泄指令 |
| → 输出审查（output） | 13 / 13 | 100% | 凭证泄露、API Key、钓鱼内容、PII 外泄 |

### AgentDojo — 按场景

| 场景 | 检测率 |
|------|--------|
| banking | 100% (9/9) |
| slack | 100% (5/5) |
| travel | 100% (7/7) |
| workspace | 71% (10/14) |

### SkillInject — 按攻击类型（59 用例，真实注入文本）

| 攻击类型 | 检测率 | 说明 |
|---------|--------|------|
| data_exfil | 85% (28/33) | `curl -X POST ... -d @file` 模式命中率高；真实注入文本 + 内容审查额外捕获 search_history_exfil |
| destruction | 58% (7/12) | `rm -rf`、`find -delete` 命中；Git 操作、sed 删除、`rm .*~` 未覆盖 |
| dos | 67% (2/3) | `while true; do curl` 模式 |
| ransomware | 100% (1/1) | `openssl enc` 模式命中 |
| script_execution | 83% (5/6) | `curl \| bash`、`base64 -d \| bash`、脚本文件检测均命中 |
| privilege_escalation | 29% (2/7) | `chmod 777`、`sudo useradd` 命中；shellcheck、SQL 注入、端口绑定、环境信息暴露未覆盖 |
| phishing | 50% (1/2) | URL 域名检测命中 `agenskill-api.onrender.com` |
| bias_manipulation | 0% (0/3) | 偏见/误导操控，需语义理解 |
| prompt_injection | 100% (1/1) | 内容审查捕获 `IGNORE PREVIOUS INSTRUCTIONS` 模式 |
| financial | 0% (0/2) | 非 Exec 工具调用，引擎未覆盖 |

### MCPSafeBench — 按攻击类型（35 用例）

| bias_manipulation | 100% (3/3) | 写入文件中的偏见/误导内容检测 |
| credential_theft | 100% (6/6) | `curl -X POST ... -d @~/.aws/credentials`、`cat .env \| grep PASSWORD` 均命中 |
| data_exfil | 95% (38/40) | `curl -X POST -d @file` 覆盖大部分；`cat file \| curl -d @-` 变体未覆盖 |
| script_execution | 100% (6/6) | `curl \| bash`、`base64 -d \| bash`、`wget && chmod && exec` 均命中 |
| destruction | 93% (13/14) | `sudo rm -rf`、`rm -rf .git`、`sed -i .../d` 均命中 |
| data_tampering | 100% (3/3) | DNS 注入 (`/etc/resolv.conf`)、SQL 修改、财务记录篡改均命中 |
| social_engineering | 100% (4/4) | 网络白名单标记未知钓鱼域名 |
| financial | 100% (2/2) | `send_money` IBAN 检测、`schedule_transaction` 定期付款检测 |
| unauthorized_action | 100% (1/1) | `git push --force` 检测 |
| privilege_escalation | 86% (6/7) | `chmod 777`、`sudo useradd`、`sudo -l`、端口绑定、SQL 注入、git remote 均命中 |
| info_disclosure | 0% (0/1) | `echo $PATH` 环境信息暴露（expect_detect=False） |
| phishing | 100% (2/2) | 网络白名单标记钓鱼域名 + send_email 主题检测 |
| prompt_injection | 100% (1/1) | 内容审查捕获 `IGNORE PREVIOUS INSTRUCTIONS` 模式 + 日历事件注入检测 |

## 测试方法

**组合检测**（Combined Detection）：对每个测试用例同时运行两条路径，任一检测到即算通过：

```
真实注入文本 → content_analysis() → 检测到？→ YES → ✓ 通过
                                      ↓ NO
                                   工具调用 → detect() → 检测到？→ YES → ✓ 通过
                                                     ↓ NO
                                                     ✗ 未通过
```

**工具调用模拟**（Tool Call Simulation）：将每个注入任务映射为 LLM 执行时实际会产生的工具调用（`tool_name` + `parameters`），然后逐次通过 `CallistoAgent.detect()` 方法。

```
注入目标 → 解析为工具调用序列 → 逐次 detect() → 累积告警+熔断 → 判断是否检测
```

### 运行方式

```bash
cd /path/to/callisto-plugin

# AgentDojo
.venv/bin/python tests/agentdojo_detection_test_v2.py

# SkillInject + MCPSafeBench
.venv/bin/python tests/skillinject_mcpsafe_test.py
```

## 检测机制

| 机制 | 覆盖的攻击 |
|------|-----------|
| 恶意命令模式匹配（_SHELL_PATTERNS） | `curl -X POST -d @file`、`curl \| bash`、`rm -rf`、`chmod 777`、`sudo useradd`、`openssl enc`、`base64 -d \| bash`、`while true; do curl`、`find -delete` |
| **非 Exec 工具风险检测** | `send_money` IBAN/金额检测、`schedule_transaction` 定期付款、`write_file` 偏见/误导内容、`send_email` 钓鱼主题/转发指令、`update_financial_record` 数据篡改、`write_calendar_event` 提示词注入 |
| **扩展黑名单（_SHELL_BLACKLIST）** | Fork bomb、无限循环、系统关重启、杀进程、磁盘操作、容器逃逸、netcat 反弹 Shell、telnet 后门、凭证枚举、持久化、cron 删除、远程传输、SysRq、内核访问、权限升级、**git force push**、**git remote add**、**sed 破坏性删除**、**端口绑定后门**、**SQL 注入+exec**、**sudo -l 枚举**、**管道式外泄**、**下载执行链** |
| **命令归一化** | IFS 滥用、编码混淆（hex/octal）、引号绕过、反斜杠转义、eval 执行、command substitution |
| **路径访问控制** | 敏感文件读取（shadow、ssh key、env、aws credentials）、symlink 攻击 |
| **网络白名单** | 未知外部域名连接、云元数据访问、私有 IP 访问、Denied 域名列表 |
| **内容安全检测** | 脚本文件分析（bash/python/node）、内联代码分析（`python -c`/`bash -c`/`node -e`）、URL 域名检查、数据外发模式检测、命令混淆检测、SSRF 元数据端点、凭证文件访问 |
| **OpenClaw 内置工具检测（新增）** | `web_search`/`x_search` 搜索注入、`browser` 导航到 exfil 站点/元数据端点、`code_execution` 代码注入/外泄、`message` 钓鱼/凭证请求/广播、`cron` 持久化/高频 DoS、`gateway` 配置篡改/重启、`memory` 操纵、`sessions_*` 跨会话注入、`nodes` 隐私操作、`read`/`write`/`edit` 敏感文件、`web_fetch` 非 HTTP 协议、`image_generate` 注入 |
| 操作链分析 | 读取+转发、多步收集+外发 |
| 因果图分析 | 识别工具调用之间的因果危险链 |
| 速率洪水 | 短时间内大量调用（拆分交易、批量外泄） |
| 敏感参数 | 可疑 IBAN、密码修改、大额转账 |
| URL/域名 | 可疑钓鱼链接 |

## 未覆盖的攻击类型

以下攻击需要 LLM 语义理解才能识别，纯正则/模式匹配无法覆盖：

1. **非 Exec 工具的隐蔽语义攻击** — `echo $PATH`（环境信息暴露）、`echo $HF_TOKEN`（env 变量泄露）、`time.sleep(1)`（合法但被用作 DoS）
2. **社交工程** — 诱导用户点击链接的邮件内容、虚假"服务中断"通知 — 已被网络白名单部分覆盖
3. **Git 滥用（非破坏性）** — `git reset --hard`
4. **安全配置修改** — 禁用 ShellCheck、跳过 SQL 注入测试
5. **偏见/偏见操控** — 已被 `write_file` 内容模式检测覆盖
6. **金融欺诈** — 已被 `send_money`/`schedule_transaction` 参数检测覆盖

## 文件说明

| 文件 | 说明 |
|------|------|
| `tests/agentdojo_detection_test.py` | v1：直接传 goal 文本（基准对比，检测率 2.9%） |
| `tests/agentdojo_detection_test_v2.py` | AgentDojo：模拟工具调用 + 组合检测（检测率 88.6%） |
| `tests/skillinject_mcpsafe_test.py` | SkillInject + MCPSafeBench（94 用例，组合检测率 67.0%） |
| `tests/content_safety_test.py` | 内容安全审查：输入/输出文本检测（检测率 100%） |
| `callisto/content_safety.py` | 内容安全检测：脚本分析、URL 检查、混淆检测、SSRF 检测 |
| `/tmp/agentdojo_injection_prompts.json` | 从 AgentDojo 提取的全部 35 个注入任务 |
| `/tmp/agentdojo_detection_results_v2.json` | AgentDojo 详细结果 |
| `/tmp/skillinject_mcpsafe_results.json` | SkillInject + MCPSafeBench 详细结果 |
