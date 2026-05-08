# CALLISTO 新功能快速指南

## 一、敏感信息脱敏

```python
from callisto.engine import CallistoEngine
from callisto.sanitizer import Sanitizer

# 创建脱敏器
sanitizer = Sanitizer(
    enabled=True,
    input_sanitization=True,
    output_sanitization=True,
)

# 注入到引擎
engine = CallistoEngine(sanitizer=sanitizer)
```

## 二、紧急熔断

```python
# 紧急情况下停止所有检测
engine.panic(reason="Active attack detected")

# 恢复检测
engine.resume()

# 检查状态
if engine.is_panic():
    print("System in panic mode")
```

## 三、人类监督模式

```python
# 设置监督模式
engine.set_approval_mode("supervised")  # 高风险需批准
engine.set_approval_mode("manual")      # 所有需批准
engine.set_approval_mode("auto")        # 自动处理（默认）

# 获取待批准告警
pending = engine.get_pending_approvals()

# 批准/拒绝
engine.approve_alert(alert_id)
engine.reject_alert(alert_id)
```

## 四、配置文件扫描

```bash
# 扫描项目配置
python scripts/scan_config.py /path/to/project

# 输出 Markdown 报告
python scripts/scan_config.py . -o security_report.md

# 输出 JSON
python scripts/scan_config.py . -f json
```

## 五、技能代码扫描

```bash
# 扫描技能目录
python scripts/scan_skills.py skills/

# 输出报告
python scripts/scan_skills.py skills/ -o skill_scan_report.md
```

## 六、运行测试

```bash
# 测试所有新功能
.venv/bin/python scripts/test_new_features.py
```

## 七、扩展命令模式

新增 80+ 危险命令模式已自动集成到检测引擎，无需额外配置。

支持的攻击类型：
- Ruby/Python/Node 执行注入
- Bash/Netcat 反向 Shell
- 文件窃取命令
- 代码执行（curl/wget pipe）
- 网络攻击（nmap, sqlmap 等）
- 其他危险命令（rm -rf, fork bomb 等）

## 八、模式说明

### 8.1 Auto 模式（默认）
- 所有告警自动处理
- 适合开发和测试环境

### 8.2 Supervised 模式
- 高风险（HIGH/CRITICAL）告警需批准
- 中低风险告警自动处理
- 适合准生产环境

### 8.3 Manual 模式
- 所有告警需人工批准
- 适合高安全要求的生产环境

## 九、最佳实践

1. **开发环境**: 使用 auto 模式 + 脱敏器
2. **测试环境**: 使用 supervised 模式 + 配置扫描
3. **生产环境**: 使用 manual 模式 + 熔断机制

## 十、故障排除

### Q: 脱敏器未生效？
A: 确保在创建引擎时注入脱敏器：
```python
engine = CallistoEngine(sanitizer=sanitizer)
```

### Q: 熔断后如何恢复？
A: 调用 `engine.resume()` 恢复检测

### Q: 如何自定义脱敏规则？
A: 使用 `sanitizer.add_pattern()` 添加自定义模式

### Q: 批准模式不生效？
A: 检查模式设置：
```python
print(engine.approval_mode)  # 应为 "auto", "supervised", 或 "manual"
```
