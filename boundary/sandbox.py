"""确定性沙箱：在冻结策略与夹具上评估攻击场景步骤。

评估只依赖冻结输入（策略、夹具、场景）与运行起点时钟；相同输入下任意重放
（包括崩溃恢复后的续跑）都得到一致的逐步判定、文件清单与摘要。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .util import iso, matches, normalize_path, sha256_text

ALLOW = "allow"
DENY = "deny"

DEFAULT_STEP_COST_MS = 10
MAX_LINK_DEPTH = 8


@dataclass
class StepOutcome:
    decision: str
    reason_code: str
    resolved_path: str | None = None
    detail: dict = field(default_factory=dict)
    produced: list[dict] = field(default_factory=list)


def verdict_for(decision: str, expect: str) -> str:
    """ok=符合预期；exposure=应拒却放（暴露）；false_block=应放却拒（误拦截）。"""
    if decision == expect:
        return "ok"
    return "exposure" if decision == ALLOW else "false_block"


class Sandbox:
    """单次运行的确定性评估器。状态（已写文件、逻辑时钟）可快照与恢复。"""

    def __init__(self, policy: dict, fixture: dict, clock_start: datetime):
        self.policy = policy
        self.fixture = fixture
        self.clock_start = clock_start
        self.elapsed_ms = 0
        self.writes: dict[str, str] = {}
        self.files = {f["path"]: f.get("content", "") for f in fixture.get("files", [])}
        self.links = {link["path"]: link["target"] for link in fixture.get("links", [])}
        self.archives = {a["path"]: a for a in fixture.get("archives", [])}
        self.mounts = list(fixture.get("mounts", []))
        self.residue = {r["path"]: r for r in fixture.get("residue", [])}
        self.capabilities = set(policy.get("tool_capabilities", []))
        self.persistence = list(policy.get("persistence_dirs", []))

    # ---- 状态快照（安全检查点）----

    def state(self) -> dict:
        return {"writes": dict(self.writes), "elapsed_ms": self.elapsed_ms}

    def restore(self, state: dict) -> None:
        self.writes = dict(state.get("writes", {}))
        self.elapsed_ms = int(state.get("elapsed_ms", 0))

    # ---- 主入口 ----

    def run_step(self, step: dict, index: int) -> dict:
        """评估一步并推进逻辑时钟；返回完整的步骤记录。"""
        cost = int(step.get("cost_ms", DEFAULT_STEP_COST_MS))
        at = iso(self.clock_start + timedelta(milliseconds=self.elapsed_ms))
        action = step.get("action", "")
        handler = getattr(self, "_do_" + action, None)
        outcome = handler(step) if handler is not None else StepOutcome(
            DENY, "UNKNOWN_ACTION", detail={"action": action})
        self.elapsed_ms += cost
        return {
            "step_index": index,
            "action": {k: v for k, v in step.items() if k != "expect"},
            "decision": outcome.decision,
            "reason_code": outcome.reason_code,
            "verdict": verdict_for(outcome.decision, step.get("expect", ALLOW)),
            "resolved_path": outcome.resolved_path,
            "detail": outcome.detail,
            "produced": outcome.produced,
            "at": at,
            "duration_ms": cost,
        }

    # ---- 内部：通用检查 ----

    def _deny(self, reason: str, resolved: str | None = None, detail: dict | None = None):
        return StepOutcome(DENY, reason, resolved, detail or {})

    def _allow(self, reason: str, resolved: str | None = None, detail: dict | None = None,
               produced: list | None = None):
        return StepOutcome(ALLOW, reason, resolved, detail or {}, produced or [])

    def _link_prefix(self, path: str):
        best = None
        for link_path, target in self.links.items():
            if path == link_path or path.startswith(link_path + "/"):
                if best is None or len(link_path) > len(best[0]):
                    best = (link_path, target)
        return best

    def _resolve(self, raw_path: str):
        """规范化并解析符号链接组件；返回 (最终路径, 错误码, 跳转链)。"""
        path, escaped = normalize_path(raw_path)
        if escaped:
            return None, "PATH_TRAVERSAL", []
        chain: list[dict] = []
        for _ in range(MAX_LINK_DEPTH):
            hit = self._link_prefix(path)
            if hit is None:
                return path, None, chain
            link_path, target = hit
            parent = link_path.rsplit("/", 1)[0] or "/"
            suffix = path[len(link_path):]
            if target.startswith("/"):
                joined = target + suffix
            else:
                joined = parent.rstrip("/") + "/" + target + suffix
            path, escaped = normalize_path(joined)
            chain.append({"link": link_path, "target": target})
            if escaped:
                return None, "LINK_ESCAPE", chain
        return None, "LINK_LOOP", chain

    def _mount_error(self, path: str) -> str | None:
        """迟到挂载：挂载点在逻辑时间到达前不可见。"""
        for mount in self.mounts:
            mp = mount["path"].rstrip("/") or "/"
            if path == mp or path.startswith(mp + "/"):
                if self.elapsed_ms < int(mount.get("active_after_ms", 0)):
                    return "MOUNT_NOT_ACTIVE"
        return None

    def _visibility(self, path: str):
        fv = self.policy.get("file_visibility", {})
        for rule in fv.get("rules", []):
            if matches(rule["pattern"], path):
                return rule["effect"], rule.get("reason", "FILE_RULE_" + rule["effect"].upper())
        default = fv.get("default", "deny")
        return default, "FILE_DEFAULT_" + default.upper()

    def _is_persistent(self, path: str) -> bool:
        return any(matches(pattern, path) for pattern in self.persistence)

    def _lookup(self, path: str):
        """返回 (状态, 内容, 来源)；状态为 ok / purged / missing。"""
        if path in self.writes:
            return "ok", self.writes[path], "write"
        if path in self.files:
            return "ok", self.files[path], "fixture"
        for mount in self.mounts:
            mp = mount["path"].rstrip("/") or "/"
            if path == mp or path.startswith(mp + "/"):
                if self.elapsed_ms >= int(mount.get("active_after_ms", 0)):
                    for entry in mount.get("files", []):
                        if entry["path"] == path:
                            return "ok", entry.get("content", ""), "mount"
                return "missing", None, "mount"
        if path in self.residue:
            if self._is_persistent(path):
                return "ok", self.residue[path].get("content", ""), "residue"
            return "purged", None, "residue"
        return "missing", None, None

    def _prepare(self, raw_path: str, capability: str):
        """能力检查 + 链接解析 + 挂载时间门。返回 (路径, 跳转链, 错误结果)。"""
        if capability not in self.capabilities:
            return None, [], self._deny("TOOL_NOT_GRANTED", detail={"capability": capability})
        path, err, chain = self._resolve(raw_path)
        if err:
            return None, chain, self._deny(err, detail={"chain": chain})
        mount_err = self._mount_error(path)
        if mount_err:
            return path, chain, self._deny(mount_err, resolved=path)
        return path, chain, None

    def _read_prepared(self, path: str, chain: list) -> StepOutcome:
        effect, reason = self._visibility(path)
        if effect == DENY:
            return self._deny(reason, resolved=path)
        status, content, source = self._lookup(path)
        if status == "purged":
            return self._deny("RESIDUE_PURGED", resolved=path,
                              detail={"origin_task": self.residue[path].get("origin_task")})
        if status == "missing":
            return self._deny("FILE_NOT_FOUND", resolved=path)
        detail = {"source": source, "size": len((content or "").encode("utf-8"))}
        if chain:
            detail["chain"] = chain
        return self._allow(reason, resolved=path, detail=detail)

    def _all_visible_paths(self) -> list[str]:
        paths = set(self.writes) | set(self.files)
        for mount in self.mounts:
            if self.elapsed_ms >= int(mount.get("active_after_ms", 0)):
                paths.update(entry["path"] for entry in mount.get("files", []))
        paths.update(p for p in self.residue if self._is_persistent(p))
        return sorted(paths)

    # ---- 动作实现 ----

    def _do_read_file(self, step: dict) -> StepOutcome:
        path, chain, err = self._prepare(step["path"], "read_file")
        if err:
            return err
        return self._read_prepared(path, chain)

    def _do_follow_link(self, step: dict) -> StepOutcome:
        norm, escaped = normalize_path(step["path"])
        if escaped:
            return self._deny("PATH_TRAVERSAL")
        if norm not in self.links:
            return self._deny("NOT_A_LINK", resolved=norm)
        path, chain, err = self._prepare(step["path"], "read_file")
        if err:
            return err
        return self._read_prepared(path, chain)

    def _do_read_residue(self, step: dict) -> StepOutcome:
        path, chain, err = self._prepare(step["path"], "read_file")
        if err:
            return err
        entry = self.residue.get(path)
        if entry is None:
            return self._deny("FILE_NOT_FOUND", resolved=path)
        if not self._is_persistent(path):
            return self._deny("RESIDUE_PURGED", resolved=path,
                              detail={"origin_task": entry.get("origin_task")})
        effect, reason = self._visibility(path)
        if effect == DENY:
            return self._deny(reason, resolved=path)
        return self._allow(reason, resolved=path,
                           detail={"source": "residue", "origin_task": entry.get("origin_task")})

    def _do_write_file(self, step: dict) -> StepOutcome:
        path, chain, err = self._prepare(step["path"], "write_file")
        if err:
            return err
        effect, reason = self._visibility(path)
        if effect == DENY:
            return self._deny(reason, resolved=path)
        content = step.get("content", "")
        self.writes[path] = content
        entry = {"path": path, "digest": sha256_text(content),
                 "persistent": self._is_persistent(path)}
        return self._allow(reason, resolved=path,
                           detail={"bytes": len(content.encode("utf-8"))}, produced=[entry])

    def _do_list_dir(self, step: dict) -> StepOutcome:
        path, chain, err = self._prepare(step["path"], "list_dir")
        if err:
            return err
        effect, reason = self._visibility(path)
        if effect == DENY:
            return self._deny(reason, resolved=path)
        prefix = "/" if path == "/" else path + "/"
        names = set()
        for known in self._all_visible_paths():
            if known.startswith(prefix):
                rest = known[len(prefix):]
                if rest:
                    names.add(rest.split("/")[0])
        return self._allow(reason, resolved=path, detail={"entries": sorted(names)})

    def _do_extract_archive(self, step: dict) -> StepOutcome:
        if "extract_archive" not in self.capabilities:
            return self._deny("TOOL_NOT_GRANTED", detail={"capability": "extract_archive"})
        archive_path, escaped = normalize_path(step["archive"])
        if escaped:
            return self._deny("PATH_TRAVERSAL")
        mount_err = self._mount_error(archive_path)
        if mount_err:
            return self._deny(mount_err, resolved=archive_path)
        effect, reason = self._visibility(archive_path)
        if effect == DENY:
            return self._deny(reason, resolved=archive_path)
        archive = self.archives.get(archive_path)
        if archive is None:
            return self._deny("FILE_NOT_FOUND", resolved=archive_path)
        member_name = step["member"]
        member = next((m for m in archive.get("members", []) if m["name"] == member_name), None)
        if member is None:
            return self._deny("ARCHIVE_MEMBER_MISSING", resolved=archive_path)
        dest, escaped = normalize_path(step["dest"])
        if escaped:
            return self._deny("PATH_TRAVERSAL")
        detail = {"archive": archive_path, "member": member_name, "dest": dest}
        # 平台不变量：归档成员不得逃逸目标目录（zip-slip 防护）
        if member_name.startswith("/"):
            return self._deny("ARCHIVE_TRAVERSAL", resolved=dest, detail=detail)
        base = dest.rstrip("/")
        final, escaped = normalize_path(base + "/" + member_name)
        prefix = base + "/" if base else "/"
        if escaped or final is None or not (final == (base or "/") or final.startswith(prefix)):
            return self._deny("ARCHIVE_TRAVERSAL", resolved=dest, detail=detail)
        mount_err = self._mount_error(final)
        if mount_err:
            return self._deny(mount_err, resolved=final, detail=detail)
        effect, reason = self._visibility(final)
        if effect == DENY:
            return self._deny(reason, resolved=final, detail=detail)
        content = member.get("content", "")
        self.writes[final] = content
        entry = {"path": final, "digest": sha256_text(content),
                 "persistent": self._is_persistent(final)}
        return self._allow(reason, resolved=final, detail=detail, produced=[entry])

    def _do_net_connect(self, step: dict) -> StepOutcome:
        if "net_connect" not in self.capabilities:
            return self._deny("TOOL_NOT_GRANTED", detail={"capability": "net_connect"})
        host = step["host"]
        port = int(step["port"])
        egress = self.policy.get("network_egress", {})
        for rule in egress.get("rules", []):
            rule_port = rule.get("port", "*")
            if matches(rule.get("host", "*"), host) and (rule_port == "*" or int(rule_port) == port):
                effect = rule["effect"]
                return StepOutcome(effect, rule.get("reason", "EGRESS_RULE_" + effect.upper()),
                                   detail={"host": host, "port": port})
        default = egress.get("default", "deny")
        return StepOutcome(default, "EGRESS_DEFAULT_" + default.upper(),
                           detail={"host": host, "port": port})

    def _do_use_tool(self, step: dict) -> StepOutcome:
        tool = step["tool"]
        if tool in self.capabilities:
            return self._allow("TOOL_GRANTED", detail={"tool": tool})
        return self._deny("TOOL_NOT_GRANTED", detail={"tool": tool})
