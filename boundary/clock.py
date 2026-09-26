"""可注入时钟：运行时间戳与租约计时的唯一时间来源。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


class SystemClock:
    """真实时钟（UTC，含时区）。"""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class ManualClock:
    """手工时钟：确定性推进，供回归运行与测试注入。"""

    def __init__(self, start: datetime | None = None):
        self._current = start or datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        if self._current.tzinfo is None:
            raise ValueError("时钟起点必须包含时区")

    def now(self) -> datetime:
        return self._current

    def advance(self, seconds: float = 0, **kwargs) -> datetime:
        self._current += timedelta(seconds=seconds, **kwargs)
        return self._current

    def set(self, moment: datetime) -> None:
        if moment.tzinfo is None:
            raise ValueError("时钟必须包含时区")
        self._current = moment
