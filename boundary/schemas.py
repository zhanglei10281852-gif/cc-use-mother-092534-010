"""策略、场景与夹具的结构校验（注册时执行，拒绝不完整的版本化输入）。"""
from __future__ import annotations

EFFECTS = {"allow", "deny"}

#: 每个动作必需的参数
ACTION_PARAMS = {
    "read_file": ("path",),
    "write_file": ("path", "content"),
    "list_dir": ("path",),
    "follow_link": ("path",),
    "read_residue": ("path",),
    "extract_archive": ("archive", "member", "dest"),
    "net_connect": ("host", "port"),
    "use_tool": ("tool",),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_policy_body(body: dict) -> None:
    _require(isinstance(body, dict), "策略必须是对象")
    _require(isinstance(body.get("policy_id"), str) and bool(body["policy_id"]), "策略缺少 policy_id")
    fv = body.get("file_visibility", {})
    _require(isinstance(fv, dict), "file_visibility 必须是对象")
    _require(fv.get("default", "deny") in EFFECTS, "file_visibility.default 必须是 allow/deny")
    for rule in fv.get("rules", []):
        _require(rule.get("effect") in EFFECTS and isinstance(rule.get("pattern"), str),
                 "文件可见性规则需要 effect 与 pattern")
    egress = body.get("network_egress", {})
    _require(isinstance(egress, dict), "network_egress 必须是对象")
    _require(egress.get("default", "deny") in EFFECTS, "network_egress.default 必须是 allow/deny")
    for rule in egress.get("rules", []):
        _require(rule.get("effect") in EFFECTS and isinstance(rule.get("host"), str),
                 "网络出口规则需要 effect 与 host")
    _require(isinstance(body.get("tool_capabilities", []), list), "tool_capabilities 必须是列表")
    _require(isinstance(body.get("persistence_dirs", []), list), "persistence_dirs 必须是列表")


def validate_scenario_body(body: dict) -> None:
    _require(isinstance(body, dict), "场景必须是对象")
    _require(isinstance(body.get("scenario_id"), str) and bool(body["scenario_id"]), "场景缺少 scenario_id")
    steps = body.get("steps")
    _require(isinstance(steps, list) and bool(steps), "场景至少需要一步")
    for index, step in enumerate(steps):
        _require(isinstance(step, dict), f"第 {index} 步必须是对象")
        action = step.get("action")
        _require(action in ACTION_PARAMS, f"第 {index} 步未知动作：{action}")
        for param in ACTION_PARAMS[action]:
            _require(param in step, f"第 {index} 步缺少参数：{param}")
        _require(step.get("expect", "allow") in EFFECTS, f"第 {index} 步 expect 必须是 allow/deny")
        if "cost_ms" in step:
            _require(isinstance(step["cost_ms"], int) and step["cost_ms"] >= 0,
                     f"第 {index} 步 cost_ms 必须是非负整数")


def validate_fixture_body(body: dict) -> None:
    _require(isinstance(body, dict), "夹具必须是对象")
    _require(isinstance(body.get("fixture_id"), str) and bool(body["fixture_id"]), "夹具缺少 fixture_id")
    for entry in body.get("files", []):
        _require(isinstance(entry.get("path"), str) and "content" in entry, "files 成员需要 path 与 content")
    for entry in body.get("links", []):
        _require(isinstance(entry.get("path"), str) and isinstance(entry.get("target"), str),
                 "links 成员需要 path 与 target")
    for archive in body.get("archives", []):
        _require(isinstance(archive.get("path"), str), "archives 成员需要 path")
        for member in archive.get("members", []):
            _require(isinstance(member.get("name"), str) and "content" in member, "归档成员需要 name 与 content")
    for mount in body.get("mounts", []):
        _require(isinstance(mount.get("path"), str), "mounts 成员需要 path")
        _require(isinstance(mount.get("active_after_ms", 0), int), "mounts 成员 active_after_ms 必须是整数")
        for entry in mount.get("files", []):
            _require(isinstance(entry.get("path"), str) and "content" in entry, "挂载文件需要 path 与 content")
    for entry in body.get("residue", []):
        _require(isinstance(entry.get("path"), str) and "content" in entry, "residue 成员需要 path 与 content")
