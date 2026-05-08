# CALLISTO 启动扫描指南

**版本**: v2.0  
**更新日期**: 2026-04-23

---

## 一、直接回答

### 问：直接启动 OpenClaw 会触发配置文件和技能代码扫描吗？

**答：会！**

从 2026-04-23 的更新开始，CALLISTO 插件已在 OpenClaw 启动时自动扫描：
- ✅ 配置文件（.env, config.yaml, config.json 等）
- ✅ 技能代码（skills/*.md, skills/*.py 等）

---

## 二、工作原理

### 启动流程

```
1. 用户运行 `openclaw` 命令
   ↓
2. OpenClaw 加载插件（包括 callisto-plugin）
   ↓
3. callisto-skill 插件初始化（src/index.js）
   ↓
4. 自动调用 `initialize()` 函数
   ↓
5. 执行 `startup_scan` 动作
   ↓
6. 调用 `auto_scanner.py` 扫描配置和技能
   ↓
7. 输出扫描结果到 OpenClaw 日志
```

### 代码位置

| 文件 | 作用 |
|------|------|
| `openclaw_plugin/callisto-skill/src/index.js` | 插件初始化，调用 `startup_scan` |
| `openclaw_plugin/callisto-skill/python/callisto_agent.py` | 执行 `startup_scan` 动作 |
| `scripts/auto_scanner.py` | 实际扫描逻辑 |
| `scripts/scan_config.py` | 配置文件扫描器 |
| `scripts/scan_skills.py` | 技能代码扫描器 |

---

## 三、日志输出示例

### 正常情况

```
[CALLISTO] 启动时自动扫描配置文件和技能代码...
[CALLISTO] 引擎已初始化，脱敏器已启用
[CALLISTO] ✓ 安全检查通过（配置：0 问题，技能：0 问题）
```

### 发现问题

```
[CALLISTO] 启动时自动扫描配置文件和技能代码...
[CALLISTO] ⚠ 发现 3 个安全问题，请检查报告
```

---

## 四、扫描范围

### 配置文件

| 文件类型 | 扫描内容 |
|----------|----------|
| `.env*`, `*.env` | 敏感变量、Token、密码 |
| `config.yaml`, `config.json` | 网络配置、会话设置、调试模式 |
| `skills/**/*.md`, `skills/**/*.py` | 技能定义中的敏感信息 |

### 扫描规则（25 类）

- **Token 安全** (3 规则): API Token、AWS 凭证、GitHub Token
- **网络安全** (7 规则): 内网地址、HTTP 链接、CORS、数据库连接
- **会话安全** (3 规则): Session 过期、Cookie 标志
- **数据保护** (3 规则): 明文密码、加密设置、调试模式
- **插件安全** (3 规则): 插件源、完整性、权限
- **执行安全** (6 规则): Shell 执行、动态代码、文件操作

### 技能代码

| 类别 | 检测内容 |
|------|----------|
| 危险命令调用 | exec, eval, __import__, pickle 等 |
| 敏感文件访问 | /etc/shadow, .ssh/, .aws/credentials 等 |
| 网络 API 调用 | requests, socket, httpx 等 |
| 加密算法使用 | MD5, SHA1, DES 等弱加密 |
| 文件系统操作 | 删除、写入、权限修改 |
| 环境变量访问 | 读取、修改环境变量 |
| 技能导入 | 动态技能加载 |
| 其他风险 | sleep、多线程、原生绑定 |

---

## 五、缓存机制

为避免每次启动都重复扫描，CALLISTO 使用文件哈希缓存：

```json
// .callisto_scan_cache.json
{
  "file_hashes": {
    "/path/to/file1": "md5hash1",
    "/path/to/file2": "md5hash2"
  },
  "last_scan_time": "2026-04-23T12:00:00"
}
```

- **文件未变化**: 跳过扫描（秒级完成）
- **文件已变化**: 重新扫描并更新缓存

---

## 六、手动触发扫描

如果需要在启动后手动扫描，可以使用：

```bash
# 扫描所有（配置 + 技能）
python scripts/auto_scanner.py --scan-all

# 仅扫描配置
python scripts/auto_scanner.py --scan-config

# 仅扫描技能
python scripts/auto_scanner.py --scan-skills

# 强制扫描（忽略缓存）
python scripts/auto_scanner.py --scan-all --force

# 监控模式（持续监控文件变化）
python scripts/auto_scanner.py --watch 60
```

---

## 七、报告生成

扫描报告保存到：

```
test_reports/startup_scan_YYYYMMDD_HHMMSS.md
```

报告内容示例：

```markdown
# CALLISTO 安全扫描报告

**扫描时间**: 2026-04-23T12:00:00

## 汇总
- **配置文件问题**: 0
- **技能代码问题**: 0
- **总问题数**: 0

## 配置文件问题
（如果没有问题，此项不显示）

## 技能代码问题
（如果没有问题，此项不显示）
```

---

## 八、性能影响

| 场景 | 延迟 | 说明 |
|------|------|------|
| 文件无变化 | < 1 秒 | 读取缓存，快速完成 |
| 文件有变化 | 1-3 秒 | 扫描变化的文件 |
| 首次扫描 | 3-5 秒 | 完整扫描所有文件 |

---

## 九、禁用启动扫描（如需）

如果因特殊原因需要禁用启动扫描，可以：

1. 注释 `src/index.js` 中的 `initialize()` 调用
2. 重启 OpenClaw

但**不建议禁用**，因为启动扫描可以：
- 及时发现配置问题
- 防止技能代码风险
- 提供安全基线

---

## 十、故障排查

### 问题 1: 启动时没有看到扫描日志

**原因**: 日志级别设置或插件未加载

**解决**:
```bash
# 检查插件是否加载
grep "callisto-plugin" ~/.openclaw/openclaw.json

# 查看完整日志
tail -f ~/.openclaw/logs/openclaw.log
```

### 问题 2: 扫描失败，提示模块导入错误

**原因**: Python 虚拟环境或依赖问题

**解决**:
```bash
# 创建虚拟环境
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin
python3 -m venv .venv
source .venv/bin/activate
pip install pyyaml

# 测试扫描
python scripts/auto_scanner.py --scan-all
```

### 问题 3: 缓存文件损坏

**原因**: 非正常退出或并发写入

**解决**:
```bash
# 删除缓存文件
rm /Users/jiangqiang/.openclaw/extensions/callisto-plugin/.callisto_scan_cache.json

# 重启 OpenClaw，会自动重建缓存
```

---

## 十一、总结

### 当前状态

✅ **OpenClaw 启动时会自动触发配置文件和技能代码扫描**

- 集成位置：`openclaw_plugin/callisto-skill/src/index.js`
- 扫描逻辑：`scripts/auto_scanner.py`
- 缓存机制：`.callisto_scan_cache.json`
- 报告位置：`test_reports/startup_scan_*.md`

### 用户感知

- **无问题**: 启动日志显示 `[CALLISTO] ✓ 安全检查通过`
- **有问题**: 启动日志显示 `[CALLISTO] ⚠ 发现 X 个安全问题`

### 无需手动操作

所有功能自动运行，用户可以直接使用 OpenClaw，安全检测在后台自动完成。

---

**文档版本**: v1.0  
**最后更新**: 2026-04-23
