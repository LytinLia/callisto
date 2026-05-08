# CALLISTO Web Dashboard 使用指南

**版本**: v2.0  
**更新日期**: 2026-04-23

---

## 一、快速开始

### 启动 Web Dashboard

```bash
# 进入项目目录
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin

# 激活虚拟环境
source .venv/bin/activate

# 启动服务器 (默认端口 8765)
python -m callisto.web

# 或使用 uvicorn 直接启动
uvicorn callisto.web_server:app --host 0.0.0.0 --port 8765
```

### 访问 Dashboard

浏览器打开：http://localhost:8765

### 访问 API 文档

- Swagger UI: http://localhost:8765/docs
- Redoc: http://localhost:8765/redoc

---

## 二、功能特性

### 1. 安全扫描

- **完整扫描**: 扫描配置文件和技能代码
- **配置扫描**: 仅扫描配置文件
- **技能扫描**: 仅扫描技能代码
- **强制扫描**: 忽略缓存重新扫描

### 2. 告警监控

- 实时显示最新安全告警
- 按严重性分类（严重/高危/中危/低危）
- 告警详情展示（类型、时间、描述）
- SSE 实时推送新告警

### 3. 会话管理

- 查看活跃会话列表
- 显示会话状态（CLOSED/OPEN）
- 显示告警计数

### 4. 工具检查

- 手动检查工具调用风险
- 输入工具名称和参数
- 返回检测结果和解释

### 5. 统计面板

- 24 小时告警统计
- 按严重性分类统计
- 按类别分类统计

---

## 三、API 端点

### 状态端点

```bash
# 获取服务状态
curl http://localhost:8765/api/status

# 获取统计数据
curl http://localhost:8765/api/stats?hours=24
```

### 扫描端点

```bash
# 运行扫描
curl -X POST http://localhost:8765/api/scan \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "all", "force": false}'

# 获取扫描结果
curl http://localhost:8765/api/scan/results
```

### 告警端点

```bash
# 获取告警列表
curl http://localhost:8765/api/alerts?limit=50

# 添加告警
curl -X POST http://localhost:8765/api/alerts/add \
  -H "Content-Type: application/json" \
  -d '{"category": "test", "severity": "high", "message": "测试告警"}'

# 清空告警
curl -X DELETE http://localhost:8765/api/alerts/clear
```

### 会话端点

```bash
# 获取会话列表
curl http://localhost:8765/api/sessions

# 操作熔断器
curl -X POST http://localhost:8765/api/session/test_session/circuit-breaker \
  -H "Content-Type: application/json" \
  -d '{"session_id": "test_session", "action": "reset"}'
```

### 工具检查端点

```bash
# 检查工具调用
curl -X POST "http://localhost:8765/api/tool/check?tool_name=exec" \
  -H "Content-Type: application/json" \
  -d '{"command": "ls -la"}'
```

### SSE 事件推送

```javascript
const eventSource = new EventSource('http://localhost:8765/api/events');

eventSource.addEventListener('heartbeat', (event) => {
    const data = JSON.parse(event.data);
    console.log('心跳:', data);
});

eventSource.addEventListener('alert', (event) => {
    const data = JSON.parse(event.data);
    console.log('新告警:', data);
});
```

---

## 四、部署建议

### 开发环境

```bash
# 启用自动重载
python -m callisto.web --reload --open
```

### 生产环境

```bash
# 多工作进程
python -m callisto.web --host 0.0.0.0 --port 8765 --workers 4

# 或使用 gunicorn
gunicorn callisto.web_server:app \
  --bind 0.0.0.0:8765 \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker
```

### Systemd 服务

```ini
# /etc/systemd/system/callisto-web.service
[Unit]
Description=CALLISTO Web Dashboard
After=network.target

[Service]
Type=simple
User=callisto
WorkingDirectory=/path/to/callisto-plugin
Environment="PATH=/path/to/.venv/bin"
ExecStart=/path/to/.venv/bin/python -m callisto.web --host 0.0.0.0 --port 8765
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable callisto-web
sudo systemctl start callisto-web
```

### Docker 部署

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8765

CMD ["python", "-m", "callisto.web", "--host", "0.0.0.0", "--port", "8765"]
```

---

## 五、与 OpenClaw 集成

CALLISTO Web Dashboard 可以独立运行，也可以与 OpenClaw 集成。

### 独立运行模式

Web Dashboard 独立运行，不依赖 OpenClaw：

```bash
python -m callisto.web
```

### 与 OpenClaw 同步启动

修改 OpenClaw 启动脚本，同时启动 Web Dashboard：

```bash
#!/bin/bash

# 启动 CALLISTO Web Dashboard
cd /Users/jiangqiang/.openclaw/extensions/callisto-plugin
source .venv/bin/activate
python -m callisto.web &
WEB_PID=$!

# 启动 OpenClaw
openclaw

# 退出时清理
kill $WEB_PID
```

---

## 六、安全注意事项

### 访问控制

目前 Web Dashboard 没有身份验证，建议：

1. **本地运行**: 只监听 `127.0.0.1`
2. **内网运行**: 添加防火墙规则限制访问 IP
3. **生产环境**: 添加反向代理和身份验证

### 反向代理配置

#### Nginx

```nginx
server {
    listen 80;
    server_name callisto.example.com;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### Apache

```apache
<VirtualHost *:80>
    ServerName callisto.example.com

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8765/
    ProxyPassReverse / http://127.0.0.1:8765/
</VirtualHost>
```

---

## 七、故障排查

### 端口被占用

```bash
# 查看端口占用
lsof -i :8765

# 更换端口
python -m callisto.web --port 8766
```

### 无法访问 Dashboard

1. 检查防火墙规则
2. 确认服务器正在运行：`ps aux | grep uvicorn`
3. 查看日志：`tail -f /tmp/callisto-web.log`

### 扫描功能不可用

确保依赖已安装：

```bash
source .venv/bin/activate
pip install pyyaml fastapi uvicorn sse-starlette
```

---

## 八、界面预览

### 主要组件

1. **Header**: 服务状态指示器
2. **统计面板**: 24 小时告警统计
3. **扫描控制**: 启动安全扫描
4. **扫描结果**: 显示扫描发现的问题
5. **告警列表**: 实时告警流
6. **会话列表**: 活跃会话状态
7. **工具检查**: 手动检查工具调用

### 响应式设计

Dashboard 采用响应式设计，适配桌面和移动设备。

---

## 九、扩展开发

### 添加新端点

在 `web_server.py` 中添加：

```python
@app.get("/api/custom")
async def custom_endpoint():
    return {"status": "success", "data": "..."}
```

### 添加新页面

在 `web/` 目录下创建 HTML 文件：

```html
<!DOCTYPE html>
<html>
<head>
    <title>新页面</title>
</head>
<body>
    <h1>新页面内容</h1>
</body>
</html>
```

访问：`http://localhost:8765/新页面.html`

---

## 十、总结

CALLISTO Web Dashboard 提供了：

- ✅ 直观的安全扫描界面
- ✅ 实时告警监控
- ✅ 会话状态管理
- ✅ 工具调用检查
- ✅ RESTful API
- ✅ SSE 实时推送
- ✅ 响应式设计
- ✅ Swagger API 文档

**下一步**:
- 添加用户认证
- 添加历史记录导出
- 添加图表可视化
- 添加告警规则配置

---

**文档版本**: v1.0  
**最后更新**: 2026-04-23
