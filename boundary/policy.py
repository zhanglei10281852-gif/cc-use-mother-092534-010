"""策略求值：文件可见性、网络出口、工具能力与持久化目录的纯函数判定。"""
from __future__ import annotations

from fnmatch import fnmatchcase


def normalize_path(raw: str, base_dir: str | None = None) -> tuple[str, bool]:
    """词法归一化路径，返回 (归一化路径, 是否逃逸 base_dir)。

    相对路径先拼到 base_dir（缺省为根）再归一化；``..`` 在根处被钳制。
    """
    if not raw:
        raise ValueError("路径不能为空")
    if raw.startswith("/"):
        combined = raw
    else:
        combined = (base_dir or "/").rstrip("/") + "/" + raw
    parts: list[str] = []
    for segment in combined.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    normalized = "/" + "/".join(parts)
    escaped = False
    if base_dir is not None:
        base, _ = normalize_path(base_dir)
        escaped = not (normalized == base or normalized.startswith(base + "/"))
    return normalized, escaped


def _match_segments(pattern: list[str], path: list[str]) -> bool:
    if not pattern:
        return not path
    head = pattern[0]
    if head == "**":
        if _match_segments(pattern[1:], path):
            return True
        return bool(path) and _match_segments(pattern, path[1:])
    if not path:
        return False
    return fnmatchcase(path[0], head) and _match_segments(pattern[1:], path[1:])


def match_pattern(pattern: str, path: str) -> bool:
    """段级匹配：``**`` 跨段，``*`` 与 ``?`` 只在段内生效。"""
    pattern_segments = [s for s in pattern.split("/") if s]
    path_segments = [s for s in path.split("/") if s]
    return _match_segments(pattern_segments, path_segments)


def decide_file(policy: dict, path: str) -> tuple[bool, str]:
    """按 file_visibility 规则顺序判定，返回 (是否允许, 命中的规则或 <default>)。"""
    visibility = policy.get("file_visibility", {})
    for rule in visibility.get("rules", []):
        if match_pattern(rule["pattern"], path):
            return rule["effect"] == "allow", rule["pattern"]
    return visibility.get("default", "deny") == "allow", "<default>"


def persistence_entry(policy: dict, path: str) -> dict | None:
    """返回覆盖 path 的最长前缀持久化目录声明，没有则 None。"""
    best = None
    for entry in policy.get("persistence_dirs", []):
        root = entry["path"].rstrip("/")
        if path == root or path.startswith(root + "/"):
            if best is None or len(root) > len(best["path"]):
                best = entry
    return best


def decide_egress(policy: dict, host: str, port: int | None) -> bool:
    egress = policy.get("network_egress", {})
    for rule in egress.get("allow", []):
        if rule.get("host") != host:
            continue
        if rule.get("port") is None or port is None or rule.get("port") == port:
            return True
    return egress.get("default", "deny") == "allow"


def decide_tool(policy: dict, tool: str) -> bool:
    capabilities = policy.get("tool_capabilities", {})
    if tool in capabilities.get("deny", []):
        return False
    if tool in capabilities.get("allow", []):
        return True
    return capabilities.get("default", "deny") == "allow"
