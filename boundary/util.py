"""通用工具：规范化 JSON、内容摘要、路径 glob 匹配与词法路径规范化。"""
from __future__ import annotations

import functools
import hashlib
import json
import re
from datetime import datetime, timezone


def canonical(obj) -> str:
    """对象的规范化 JSON 表示（键排序、无空白），用于稳定摘要。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_of(obj) -> str:
    """对象规范化表示的 SHA-256 摘要。"""
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def iso(dt: datetime) -> str:
    """统一为 UTC 微秒级 ISO 8601；同格式字符串可按字典序比较。"""
    if dt.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def parse_iso(text: str) -> datetime:
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return dt


@functools.lru_cache(maxsize=512)
def _glob_regex(pattern: str) -> re.Pattern:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if pattern[i:i + 2] == "**":
                i += 2
                if pattern[i:i + 1] == "/":
                    i += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def matches(pattern: str, path: str) -> bool:
    """路径 glob：``**`` 跨目录段，``*`` 段内任意，``?`` 单字符。"""
    return _glob_regex(pattern).match(path) is not None


def normalize_path(path: str) -> tuple[str | None, bool]:
    """词法规范化绝对路径。

    返回 ``(规范化路径, 是否越出根目录)``；根之上的 ``..`` 视为越界，路径为 None。
    """
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError(f"路径必须是绝对路径：{path!r}")
    parts: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            else:
                return None, True
        else:
            parts.append(seg)
    return "/" + "/".join(parts), False
