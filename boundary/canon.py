"""规范化序列化与摘要：所有跨运行比较的哈希都经过同一入口。"""
from __future__ import annotations

import hashlib
import json


def canonical(obj) -> str:
    """确定性 JSON：键排序、紧凑分隔、保留非 ASCII 字符。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj) -> str:
    return sha256_text(canonical(obj))
