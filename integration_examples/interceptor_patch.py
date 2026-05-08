#!/usr/bin/env python3
"""
CALLISTO Interceptor 熔断补丁

使用方法:
    python integration_examples/interceptor_patch.py

这个脚本会修改 callisto/collector/interceptor.py 添加熔断支持
"""

import re
from pathlib import Path

# 目标文件
INTERCEPTOR_PATH = Path(__file__).parent.parent / "callisto" / "collector" / "interceptor.py"

# 备份路径
BACKUP_PATH = INTERCEPTOR_PATH.with_suffix(".py.bak")


def create_backup():
    """创建备份"""
    if INTERCEPTOR_PATH.exists():
        content = INTERCEPTOR_PATH.read_text()
        BACKUP_PATH.write_text(content)
        print(f"✓ 备份已创建：{BACKUP_PATH}")


def apply_patch():
    """应用补丁"""
    if not INTERCEPTOR_PATH.exists():
        print(f"✗ 文件不存在：{INTERCEPTOR_PATH}")
        return False
    
    content = INTERCEPTOR_PATH.read_text()
    original = content
    
    # 1. 添加导入
    import_add = "from callisto.response.circuit_breaker import CircuitBreaker"
    if import_add not in content:
        # 在 file docstring 后添加
        content = content.replace(
            'from callisto.collector.models import CallEvent, EventType',
            f'from callisto.collector.models import CallEvent, EventType\nfrom callisto.response.circuit_breaker import CircuitBreaker'
        )
        print("✓ 添加导入语句")
    
    # 2. 添加 Optional 导入
    if "Optional" not in content:
        content = content.replace(
            'from typing import Any, Callable, Awaitable',
            'from typing import Any, Callable, Awaitable, Optional'
        )
        print("✓ 添加 Optional 导入")
    
    # 3. 修改 Interceptor.__init__ 添加 circuit_breaker 参数
    old_init = '''class Interceptor:
    """Wraps tool execution functions to capture call events in real time."""

    def __init__(self) -> None:
        self._listeners: list[Callable[[CallEvent], Awaitable[None] | None]] = []'''
    
    new_init = '''class Interceptor:
    """Wraps tool execution functions to capture call events in real time.
    
    Supports circuit breaker: blocks tool calls when breaker is OPEN.
    """

    def __init__(self, circuit_breaker: Optional[CircuitBreaker] = None) -> None:
        self._listeners: list[Callable[[CallEvent], Awaitable[None] | None]] = []
        self.breaker = circuit_breaker'''
    
    if old_init in content:
        content = content.replace(old_init, new_init)
        print("✓ 修改 __init__ 添加 circuit_breaker")
    elif "self.breaker = circuit_breaker" not in content:
        # 尝试另一种方式
        content = content.replace(
            'def __init__(self) -> None:',
            'def __init__(self, circuit_breaker: Optional[CircuitBreaker] = None) -> None:\n        self.breaker = circuit_breaker'
        )
        print("✓ 修改 __init__ (备用方案)")
    
    # 4. 添加 should_block 方法
    should_block_method = '''
    def should_block(self) -> bool:
        """Check if tool calls should be blocked by circuit breaker."""
        if self.breaker is None:
            return False
        return self.breaker.should_block()
'''
    
    # 在 on_event 方法后添加
    if 'def on_event' in content and 'def should_block' not in content:
        content = content.replace(
            'def on_event(self, callback:',
            should_block_method + '\n    def on_event(self, callback:'
        )
        print("✓ 添加 should_block 方法")
    
    # 5. 修改 _async_wrapper 添加熔断检查
    old_async = '''async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
            call_event = CallEvent(
                timestamp=time.time(),
                event_type=EventType.TOOL_CALL,
                tool_name=tool_name,
                parameters={"args": args, "kwargs": kwargs},
            )
            await interceptor._emit(call_event)
            t0 = time.time()'''
    
    new_async = '''async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Circuit breaker check
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
            t0 = time.time()'''
    
    if old_async in content:
        content = content.replace(old_async, new_async)
        print("✓ 修改 _async_wrapper 添加熔断检查")
    
    # 6. 修改 _sync_wrapper 添加熔断检查
    old_sync = '''def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            call_event = CallEvent(
                timestamp=time.time(),
                event_type=EventType.TOOL_CALL,
                tool_name=tool_name,
                parameters={"args": args, "kwargs": kwargs},
            )
            _emit_sync_or_schedule(call_event)
            t0 = time.time()'''
    
    new_sync = '''def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Circuit breaker check
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
            t0 = time.time()'''
    
    if old_sync in content:
        content = content.replace(old_sync, new_sync)
        print("✓ 修改 _sync_wrapper 添加熔断检查")
    
    # 7. 添加异常类
    exception_class = '''

class CircuitBreakerOpenError(Exception):
    """Raised when a tool call is blocked by the circuit breaker."""
    pass

'''
    
    if 'class CircuitBreakerOpenError' not in content:
        content = content + exception_class
        print("✓ 添加 CircuitBreakerOpenError 异常类")
    
    # 保存修改后的文件
    if content != original:
        INTERCEPTOR_PATH.write_text(content)
        print(f"\n✓ 补丁应用成功：{INTERCEPTOR_PATH}")
        return True
    else:
        print("\n⚠ 没有检测到需要修改的内容，可能已应用过补丁")
        return False


def restore_backup():
    """恢复备份"""
    if BACKUP_PATH.exists():
        content = BACKUP_PATH.read_text()
        INTERCEPTOR_PATH.write_text(content)
        print(f"✓ 已恢复到原始版本")
    else:
        print(f"✗ 备份文件不存在：{BACKUP_PATH}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "restore":
            restore_backup()
        else:
            print("用法：python interceptor_patch.py [restore]")
    else:
        create_backup()
        apply_patch()
