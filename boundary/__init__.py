"""隔离边界回归验证平台。

版本化策略 + 可组合攻击场景 + 确定性运行 + 差异裁决 + 发布门禁。
"""
from .clock import ManualClock, SystemClock
from .platform import Platform
from .runner import InjectedFailure, LeaseError, Runner

__all__ = [
    "Platform",
    "ManualClock",
    "SystemClock",
    "Runner",
    "LeaseError",
    "InjectedFailure",
]
