"""可注入时钟：运行计时与审计时间的统一来源，保证确定性重放。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def parse_iso(value: str) -> datetime:
    """解析 ISO 8601 时间，必须带时区。"""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("时间必须包含时区：" + value)
    return parsed


def iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return moment.isoformat()


class FrozenClock:
    """可推进的冻结时钟：相同起始时间与推进序列下读数完全一致。"""

    def __init__(self, start: str | datetime):
        moment = parse_iso(start) if isinstance(start, str) else start
        if moment.tzinfo is None:
            raise ValueError("FrozenClock 需要带时区的时间")
        self._now = moment

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)


class SystemClock:
    """真实时钟，仅用于未注入时钟的交互式场景。"""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def advance(self, seconds: float) -> None:
        raise NotImplementedError("系统时钟不可推进")
