"""API call interceptor — async MITM proxy for real-time event capture.

Sits between the Agent and the tool execution layer, captures every
tool call/result as a CallEvent, and forwards it to the detection pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Awaitable

_log = logging.getLogger(__name__)

from callisto.collector.models import CallEvent, EventType


class Interceptor:
    """Wraps tool execution functions to capture call events in real time."""

    def __init__(self) -> None:
        self._listeners: list[Callable[[CallEvent], Awaitable[None] | None]] = []

    def on_event(self, callback: Callable[[CallEvent], Awaitable[None] | None]) -> None:
        self._listeners.append(callback)

    async def _emit(self, event: CallEvent) -> None:
        for listener in self._listeners:
            result = listener(event)
            if asyncio.iscoroutine(result):
                await result

    def wrap(self, tool_name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Return a wrapped version of *fn* that emits CallEvents."""
        interceptor = self

        def _log_task_exception(t: asyncio.Task) -> None:
            if not t.cancelled() and t.exception():
                _log.error("Event emission failed: %s", t.exception())

        async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
            call_event = CallEvent(
                timestamp=time.time(),
                event_type=EventType.TOOL_CALL,
                tool_name=tool_name,
                parameters={"args": args, "kwargs": kwargs},
            )
            await interceptor._emit(call_event)
            t0 = time.time()
            result = await fn(*args, **kwargs)
            call_event.duration_ms = (time.time() - t0) * 1000
            result_event = CallEvent(
                timestamp=time.time(),
                event_type=EventType.TOOL_RESULT,
                tool_name=tool_name,
                result=result,
                duration_ms=call_event.duration_ms,
            )
            await interceptor._emit(result_event)
            return result

        def _emit_sync_or_schedule(event: CallEvent) -> None:
            """Emit an event, scheduling on a running loop or falling back to sync."""
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                task = loop.create_task(interceptor._emit(event))
                task.add_done_callback(_log_task_exception)
            else:
                for listener in interceptor._listeners:
                    result = listener(event)
                    if asyncio.iscoroutine(result):
                        _log.warning(
                            "Skipping async listener %r — no running event loop",
                            listener,
                        )
                        result.close()

        def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            call_event = CallEvent(
                timestamp=time.time(),
                event_type=EventType.TOOL_CALL,
                tool_name=tool_name,
                parameters={"args": args, "kwargs": kwargs},
            )
            _emit_sync_or_schedule(call_event)
            t0 = time.time()
            result = fn(*args, **kwargs)
            call_event.duration_ms = (time.time() - t0) * 1000
            result_event = CallEvent(
                timestamp=time.time(),
                event_type=EventType.TOOL_RESULT,
                tool_name=tool_name,
                result=result,
                duration_ms=call_event.duration_ms,
            )
            _emit_sync_or_schedule(result_event)
            return result

        if asyncio.iscoroutinefunction(fn):
            return _async_wrapper
        return _sync_wrapper
