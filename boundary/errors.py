"""平台异常类型。"""
from __future__ import annotations


class BoundaryError(Exception):
    """平台基础异常。"""


class NotFoundError(BoundaryError):
    """引用的对象或版本不存在。"""


class LeaseConflictError(BoundaryError):
    """运行已被其他执行器租用，且租约未过期。"""


class StaleLeaseError(BoundaryError):
    """栅栏令牌过期：租约已被其他执行器接管。"""


class DeterminismError(BoundaryError):
    """同一步骤被录入了不同结果，违反确定性约束。"""
