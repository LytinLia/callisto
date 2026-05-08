# CALLISTO 集成到 Agent 内部 - 完整操作指南

**目标**: 在 Agent 框架内部集成 CALLISTO，实现真正的风险操作阻断

---

## 步骤 1: 修改 `interceptor.py` 添加熔断支持

### 1.1 备份原文件

```bash
cp callisto/collector/interceptor.py callisto/collector/interceptor.py.bak
```

### 1.2 添加导入

在文件顶部添加：

```python
from typing import Any, Callable, Awaitable, Optional  # 添加 Optional
from callisto.response.circuit_breaker import CircuitBreaker  # 新增导入
```

### 1.3 修改 `Interceptor.__init__`

```python
# 修改前
def __init__(self) -> None:
    self._listeners: list[Callable[[CallEvent], Awaitable[None] | None]] = []

# 修改后
def __init__(self, circuit_breaker: Optional[CircuitBreaker] = None) -> None:
    self._listeners: list[Callable[[CallEvent], Awaitable[None] | None]] = []
    self.breaker = circuit_breaker  # 新增
```

### 1.4 添加 `should_block` 方法

在 `on_event` 方法后添加：

```python
def should_block(self) -> bool:
    """检查是否应该阻断工具调用"""
    if self.breaker is None:
        return False
    return self.breaker.should_block()
```

### 1.5 修改 `_async_wrapper`

```python
async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
    # 新增：熔断检查
    if interceptor.should_block():
        _log.warning(f"Tool call blocked by circuit breaker: {tool_name}")
        raise CircuitBreakerOpenError(f"Execution blocked: {tool_name}")
    
    call_event = CallEvent(
        timestamp=time.time(),
        event_type=EventType.TOOL_CALL,
        tool_name=tool_name,
        parameters={"args": args, "kwargs": kwargs},
    )
    await interceptor._emit(call_event)
    # ... 其余代码不变
```

### 1.6 修改 `_sync_wrapper`

```python
def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
    # 新增：熔断检查
    if interceptor.should_block():
        _log.warning(f"Tool call blocked by circuit breaker: {tool_name}")
        raise CircuitBreakerOpenError(f"Execution blocked: {tool_name}")
    
    call_event = CallEvent(
        timestamp=time.time(),
        event_type=EventType.TOOL_CALL,
        tool_name=tool_name,
        parameters={"args": args, "kwargs": kwargs},
    )
    _emit_sync_or_schedule(call_event)
    # ... 其余代码不变
```

### 1.7 添加异常类

在文件末尾添加：

```python
class CircuitBreakerOpenError(Exception):
    """当熔断器触发时阻止工具调用"""
    pass
```

---

## 步骤 2: 在 Agent 中集成 CALLISTO

### 2.1 创建 Agent 封装类

```python
from callisto.engine import CallistoEngine
from callisto.config import CallistoConfig
from callisto.collector.interceptor import Interceptor, CircuitBreakerOpenError
from callisto.collector.models import Session, CallEvent, EventType

class SafetyAwareAgent:
    def __init__(self):
        # 初始化 CALLISTO
        cfg = CallistoConfig(circuit_breaker_threshold=3)
        self.engine = CallistoEngine(cfg)
        
        # 创建拦截器（注入熔断器）
        self.interceptor = Interceptor(circuit_breaker=self.engine.breaker)
        
        # 会话追踪
        self.session = Session(session_id="agent_session")
        
        # 注册工具
        self._register_tools()
    
    def _on_event(self, event: CallEvent):
        """事件回调 - 实时检测"""
        self.session.add_event(event)
        
        if event.event_type == EventType.TOOL_CALL:
            alerts = self.engine.analyze_session(self.session)
            for alert in alerts:
                if event.event_id in alert.trigger_events:
                    print(f"🚨 [{alert.risk_level.name}] {alert.attack_type.value}")
    
    def _register_tools(self):
        """注册工具，使用拦截器包装"""
        # 示例：注册一个工具
        def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()
        
        # 关键：使用拦截器包装工具函数
        wrapped_read = self.interceptor.wrap("read_file", read_file)
        self.read_file = wrapped_read
        
        # 注册事件回调
        self.interceptor.on_event(self._on_event)
    
    async def execute(self, tool_name: str, **kwargs):
        """执行工具，支持熔断阻断"""
        try:
            # 调用被拦截器包装的工具
            result = getattr(self, tool_name)(**kwargs)
            if asyncio.iscoroutine(result):
                result = await result
            return result
        except CircuitBreakerOpenError as e:
            print(f"🚨 熔断阻断：{e}")
            return None  # 或触发 Agent 终止
```

---

## 步骤 3: 使用示例

```python
import asyncio

agent = SafetyAwareAgent()

# 正常操作
await agent.execute("read_file", path="/tmp/safe.txt")

# 危险操作 - 可能触发熔断
await agent.execute("read_file", path="/etc/passwd")
await agent.execute("read_file", path="/etc/shadow")
await agent.execute("read_file", path="/root/.ssh/id_rsa")

# 第 4 次：熔断触发，抛出 CircuitBreakerOpenError
await agent.execute("exec_command", command="rm -rf /")
# 🚨 熔断阻断：Execution blocked: exec_command
```

---

## 步骤 4: 验证熔断

```python
def test_circuit_breaker():
    from callisto.response.circuit_breaker import CircuitBreaker
    from callisto.collector.models import Alert, RiskLevel
    
    # 创建熔断器
    breaker = CircuitBreaker(threshold=3)
    
    # 模拟 3 个 HIGH 告警
    for i in range(3):
        alert = Alert(
            session_id="test",
            attack_type="data_exfil",
            risk_level=RiskLevel.HIGH,
            score=0.9,
            explanation="test",
            trigger_events=["event1"],
            source_module="test",
            timestamp=time.time()
        )
        breaker.record_alert(alert)
        print(f"告警 {i+1}: 状态 = {breaker.state}")
    
    # 验证熔断状态
    assert breaker.state == "OPEN"
    assert breaker.should_block() == True
    print("✓ 熔断测试通过")

test_circuit_breaker()
```

---

## 完整代码示例

见同目录下的 `agent_with_callisto.py`

---

## 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent 框架                                │
│                                                             │
│  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐ │
│  │   LLM Core  │ ──► │  Tool Router │ ──► │ Interceptor │ │
│  └─────────────┘     └──────────────┘     └──────┬──────┘ │
│                                                  │         │
│                    ┌─────────────────────────────┤         │
│                    │                             │         │
│              ┌─────▼──────┐              ┌──────▼──────┐  │
│              │  熔断检查   │              │ CALLISTO    │  │
│              │ should_block│ ◄─────────── │  Engine     │  │
│              └─────┬──────┘              └─────────────┘  │
│                    │                                       │
│              OPEN  │               CLOSED                  │
│                    ▼                                       │
│          ┌─────────────────┐                              │
│          │ 抛出异常/阻断执行 │                              │
│          └─────────────────┘                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 注意事项

1. **熔断阈值**: 默认 3 个 HIGH 告警触发，可在 `CallistoConfig` 中调整
2. **恢复机制**: 熔断后 60 秒自动进入 HALF_OPEN 状态
3. **异常处理**: 捕获 `CircuitBreakerOpenError` 并决定如何处理（终止 Agent 或降级）
4. **异步支持**: 拦截器同时支持同步和异步工具函数

---

**更新时间**: 2026-04-21
