# backend/console/log_broadcaster.py
# In-memory log ring buffer + WebSocket broadcast for WS /ws/console/{source}
from __future__ import annotations
import asyncio
import logging
from collections import deque
from typing import Literal

LogSource = Literal["backend", "ollama", "all"]
MAX_HISTORY = 500   # lines kept in ring buffer

_history: deque[dict] = deque(maxlen=MAX_HISTORY)
_subscribers: list[asyncio.Queue] = []
_lock = asyncio.Lock()


def emit(source: str, line: str) -> None:
    """Append a log line from source to the ring buffer and notify subscribers."""
    entry = {"source": source, "line": line}
    _history.append(entry)
    for q in _subscribers:
        try:
            q.put_nowait(entry)
        except asyncio.QueueFull:
            pass


async def subscribe(source: LogSource) -> tuple[list[dict], asyncio.Queue]:
    """Return historical lines + a live queue for the requested source."""
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    async with _lock:
        _subscribers.append(q)
    history = [
        e for e in list(_history)
        if source == 'all' or e['source'] == source
    ]
    return history, q


async def unsubscribe(q: asyncio.Queue) -> None:
    async with _lock:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass


class WebSocketLogHandler(logging.Handler):
    """Attach to Python root logger to forward log records to broadcast."""
    def emit(self, record: logging.LogRecord) -> None:
        try:
            emit('backend', self.format(record))
        except Exception:
            pass
