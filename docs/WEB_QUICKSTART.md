# CALLISTO Web Dashboard 快速开始

**版本**: v2.0  
**完成日期**: 2026-04-23

---

## 一、快速启动

### 方法 1: 使用启动脚本（推荐）

```bash
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin

# 基本启动
./start-web.sh

# 启动并打开浏览器
./start-web.sh --open

# 开发模式（自动重载）
./start-web.sh --reload --open

# 自定义端口
./start-web.sh --port 8766
```

### 方法 2: 直接启动

```bash
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin
source .venv/bin/activate
python -m uvicorn web_server:app --host 0.0.0.0 --port 8765
```

### 方法 3: 使用 Python 模块

```bash
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin
source .venv/bin/activate
python -m callisto.web --open
```

---

## 二、访问地址

| 服务 | URL |
|------|-----|
| **Dashboard** | http://localhost:8765 |
| **API 文档 (Swagger)** | http://localhost:8765/docs |
| **API 文档 (Redoc)** | http://localhost:8765/redoc |
| **API 状态** | http://localhost:8765/api/status |

---

## 三、主要功能

### 1. 安全扫描

- 点击"开始扫描"按钮
- 选择扫描类型（完整/配置/技能）
- 查看扫描结果

### 2. 告警监控

- 实时显示最新告警
- SSE 自动推送新告警
- 按严重性分类显示

### 3. 工具检查

- 输入工具名称（如：`exec`）
- 输入参数（JSON 格式）
- 点击"检查"查看风险

### 4. 会话管理

- 查看活跃会话
- 显示会话状态
- 显示告警计数

---

## 四、API 示例

### 获取状态

```bash
curl http://localhost:8765/api/status
```

### 运行扫描

```bash
curl -X POST http://localhost:8765/api/scan \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "all", "force": false}'
```

### 获取扫描结果

```bash
curl http://localhost:8765/api/scan/results
```

### 检查工具

```bash
curl -X POST "http://localhost:8765/api/tool/check?tool_name=exec" \
  -H "Content-Type: application/json" \
  -d '{"command": "ls -la"}'
```

### SSE 事件推送

```bash
# 保持连接接收事件
curl -N http://localhost:8765/api/events
```

---

## 五、界面预览

### Dashboard 布局

```
┌─────────────────────────────────────────────────┐
│  🛡️ CALLISTO v2.0          ● Running          │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │
│  │ 📊 统计  │  │ 🔍 扫描  │  │ 📋 扫描结果     │ │
│  │         │  │ 控制    │  │                 │ │
│  │ 总告警  │  │ 完整扫描│  │ 配置文件问题   │ │
│  │ 严重    │  │ 配置扫描│  │ 技能代码问题   │ │
│  │ 高危    │  │ 技能扫描│  │                 │ │
│  └─────────┘  └─────────┘  └─────────────────┘ │
│                                                 │
│  ┌─────────────────────────────────────────────┐│
│  │ 🚨 告警列表                                  ││
│  │ • priv_escalation [HIGH]                    ││
│  │ • data_exfil [MEDIUM]                       ││
│  └─────────────────────────────────────────────┘│
│                                                 │
│  ┌─────────┐  ┌────────────────────────────────┐│
│  │ 👥 会话  │  │ ⚡ 工具检查                    ││
│  │ session1│  │ 工具：exec                     ││
│  │ CLOSED  │  │ 参数：{"command": "ls"}        ││
│  └─────────┘  └────────────────────────────────┘│
└─────────────────────────────────────────────────┘
```

---

## 六、文件结构

```
callisto-plugin/
├── start-web.sh              # 快速启动脚本
├── web_server.py             # FastAPI 应用
├── WEB_DASHBOARD_GUIDE.md    # 详细使用指南
├── WEB_IMPLEMENTATION_SUMMARY.md  # 实现总结
├── WEB_QUICKSTART.md         # 本文件
├── callisto/
│   ├── web.py                # Web 启动模块
│   └── ...
└── web/
    ├── index.html            # Dashboard 首页
    ├── static/
    │   ├── css/
    │   │   └── style.css     # 样式
    │   └── js/
    │       └── app.js        # 前端逻辑
    └── templates/
```

---

## 七、常见问题

### Q: 端口被占用？

```bash
# 查看占用端口的进程
lsof -i :8765

# 使用其他端口
./start-web.sh --port 8766
```

### Q: 无法打开浏览器？

手动访问：http://localhost:8765

### Q: 扫描功能不可用？

确保已安装依赖：
```bash
source .venv/bin/activate
pip install pyyaml
```

### Q: 如何停止服务器？

按 `Ctrl+C`

### Q: 后台运行？

```bash
nohup ./start-web.sh > /tmp/callisto-web.log 2>&1 &
```

---

## 八、下一步

### 建议使用方式

1. **开发测试**: 使用 `--reload --open` 模式
2. **日常使用**: 基本启动即可
3. **生产部署**: 参考 `WEB_DASHBOARD_GUIDE.md`

### 扩展开发

- 添加新的 API 端点：编辑 `web_server.py`
- 修改界面样式：编辑 `web/static/css/style.css`
- 添加新功能：编辑 `web/static/js/app.js`

---

## 九、相关文档

| 文档 | 内容 |
|------|------|
| `WEB_DASHBOARD_GUIDE.md` | 完整使用指南、API 文档、部署建议 |
| `WEB_IMPLEMENTATION_SUMMARY.md` | 实现细节、技术架构、与 ClawGuard 对比 |
| `AUTO_CALL_GUIDE.md` | 自动调用指南 |
| `STARTUP_SCAN_GUIDE.md` | 启动扫描指南 |

---

## 十、技术栈

- **后端**: Python 3.11 + FastAPI + Uvicorn
- **前端**: HTML5 + CSS3 + Vanilla JavaScript
- **实时推送**: SSE (Server-Sent Events)
- **API 文档**: Swagger UI + ReDoc
- **依赖管理**: Python venv + pip

---

**开始使用**: `./start-web.sh --open`

**文档版本**: v1.0  
**最后更新**: 2026-04-23
