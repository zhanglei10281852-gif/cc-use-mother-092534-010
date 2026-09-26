"""确定性执行引擎：按冻结策略对场景步骤逐步求值。

引擎只依赖注入的策略内容、夹具虚拟文件系统与时钟推进量，
不触碰真实文件系统与网络，因此相同输入必然得到相同结果。
"""
from __future__ import annotations

from . import models
from .canon import sha256_bytes
from .fixtures import VirtualFS
from .policy import (
    decide_egress,
    decide_file,
    decide_tool,
    normalize_path,
    persistence_entry,
)


class Engine:
    """单个运行的求值上下文；恢复运行时通过 restore_usage 重建配额用量。"""

    def __init__(self, policy: dict, vfs: VirtualFS, task_id: str,
                 default_step_ms: float = 5.0):
        self.policy = policy
        self.vfs = vfs
        self.task_id = task_id
        self.default_step_ms = float(default_step_ms)
        self.persist_usage: dict[str, int] = {}

    def restore_usage(self, manifest_entries: list[dict]) -> None:
        """从已落盘的清单重建持久化目录用量，供断点续跑使用。"""
        for entry in manifest_entries:
            root = persistence_entry(self.policy, entry["path"])
            if root is not None:
                key = root["path"].rstrip("/")
                self.persist_usage[key] = self.persist_usage.get(key, 0) + int(
                    entry["size_bytes"]
                )

    def execute_step(self, spec: dict, step_index: int) -> dict:
        kind = spec.get("kind")
        handler = getattr(self, "_step_" + str(kind), None)
        if handler is None:
            raise ValueError(f"未知步骤类型：{kind}")
        params = spec.get("params", {})
        decision, reason, detail, produced = handler(params, step_index)
        duration_ms = float(spec.get("simulated_ms", self.default_step_ms))
        payload = models.step_payload(spec, step_index, decision, reason, detail,
                                      duration_ms)
        return {"payload": payload, "produced": produced}

    # ---- 文件可见性 ----
    def _visible_or_deny(self, raw_path: str, base_dir: str | None):
        """公共前置：遍历检查 + 规则检查。返回 (normalized, deny_tuple or None)。"""
        normalized, escaped = normalize_path(raw_path, base_dir)
        if escaped:
            return normalized, (
                models.DENY,
                models.FILE_DENY_TRAVERSAL,
                {"path": raw_path, "normalized": normalized, "base_dir": base_dir},
            )
        allowed, matched = decide_file(self.policy, normalized)
        if not allowed:
            return normalized, (
                models.DENY,
                models.FILE_DENY_RULE,
                {"path": raw_path, "normalized": normalized, "matched_rule": matched},
            )
        return normalized, None

    def _late_mount_denied(self, normalized: str) -> dict | None:
        mount = self.vfs.find_mount(normalized)
        if mount is None or mount["appears_at_step"] <= 0:
            return None
        if self.policy.get("mounts", {}).get("allow_late", False):
            return None
        return mount

    def _step_read_file(self, params: dict, step_index: int):
        normalized, denied = self._visible_or_deny(params["path"],
                                                   params.get("base_dir"))
        if denied:
            return denied[0], denied[1], denied[2], []
        final, chain = self.vfs.resolve_links(normalized)
        if chain:
            allowed, _ = decide_file(self.policy, final)
            if not allowed:
                return models.DENY, models.LINK_DENY_ESCAPE, {
                    "path": params["path"], "normalized": normalized,
                    "resolved": final, "link_chain": chain,
                }, []
        mount = self._late_mount_denied(final)
        if mount is not None:
            return models.DENY, models.MOUNT_DENY_LATE, {
                "path": params["path"], "normalized": final,
                "mount": mount["path"],
                "appears_at_step": mount["appears_at_step"],
            }, []
        content = self.vfs.read(final, step_index)
        detail = {
            "path": params["path"],
            "normalized": final,
            "found": content is not None,
        }
        if content is not None:
            detail["sha256"] = sha256_bytes(content.encode("utf-8"))
        return models.ALLOW, models.FILE_ALLOW, detail, []

    def _step_list_dir(self, params: dict, step_index: int):
        normalized, denied = self._visible_or_deny(params["path"],
                                                   params.get("base_dir"))
        if denied:
            return denied[0], denied[1], denied[2], []
        entries = self.vfs.list_dir(normalized, step_index)
        return models.ALLOW, models.FILE_ALLOW, {
            "path": params["path"], "normalized": normalized, "entries": entries,
        }, []

    # ---- 链接跳转 ----
    def _step_follow_link(self, params: dict, step_index: int):
        link, _ = normalize_path(params["path"])
        target = self.vfs.links.get(link)
        if target is None:
            return models.ALLOW, models.LINK_ALLOW, {
                "link": link, "found": False,
            }, []
        resolved, chain = self.vfs.resolve_links(link)
        allowed, matched = decide_file(self.policy, resolved)
        if not allowed:
            return models.DENY, models.LINK_DENY_ESCAPE, {
                "link": link, "resolved": resolved, "link_chain": chain,
                "matched_rule": matched,
            }, []
        return models.ALLOW, models.LINK_ALLOW, {
            "link": link, "resolved": resolved, "link_chain": chain,
        }, []

    # ---- 归档成员 ----
    def _step_extract_archive(self, params: dict, step_index: int):
        archive = params["archive"]
        dest_dir, _ = normalize_path(params["dest_dir"])
        members = self.vfs.archives.get(archive)
        if members is None:
            return models.ALLOW, models.ARCHIVE_ALLOW, {
                "archive": archive, "found": False, "members": [],
            }, []
        results = []
        produced = []
        blocking = None
        for member in members:
            joined, escaped = normalize_path(dest_dir + "/" + member["name"],
                                             base_dir=dest_dir)
            if escaped:
                results.append({
                    "name": member["name"], "decision": models.DENY,
                    "reason_code": models.ARCHIVE_DENY_MEMBER_ESCAPE,
                })
                blocking = blocking or models.ARCHIVE_DENY_MEMBER_ESCAPE
                continue
            allowed, matched = decide_file(self.policy, joined)
            if not allowed:
                results.append({
                    "name": member["name"], "decision": models.DENY,
                    "reason_code": models.ARCHIVE_DENY_RULE, "path": joined,
                    "matched_rule": matched,
                })
                blocking = blocking or models.ARCHIVE_DENY_RULE
                continue
            data = member["content"].encode("utf-8")
            produced.append({
                "path": joined,
                "sha256": sha256_bytes(data),
                "size_bytes": len(data),
                "origin_step": step_index,
            })
            results.append({
                "name": member["name"], "decision": models.ALLOW,
                "reason_code": models.ARCHIVE_ALLOW, "path": joined,
            })
        decision = models.DENY if blocking else models.ALLOW
        reason = blocking or models.ARCHIVE_ALLOW
        detail = {
            "archive": archive,
            "dest_dir": dest_dir,
            "members": results,
            "produced": [entry["path"] for entry in produced],
        }
        return decision, reason, detail, produced

    # ---- 跨任务残留 ----
    def _step_read_residue(self, params: dict, step_index: int):
        directory, _ = normalize_path(params["dir"])
        owner = params["owner_task"]
        entry = persistence_entry(self.policy, directory)
        files = self.vfs.residue_files(directory, owner)
        if entry is not None and entry.get("mode") == "shared":
            return models.ALLOW, models.RESIDUE_ALLOW_SHARED, {
                "dir": directory, "owner_task": owner, "visible_files": files,
            }, []
        return models.DENY, models.RESIDUE_DENY_CROSS_TASK, {
            "dir": directory, "owner_task": owner, "visible_files": [],
        }, []

    # ---- 网络出口 ----
    def _step_egress(self, params: dict, step_index: int):
        host = params["host"]
        port = params.get("port")
        if decide_egress(self.policy, host, port):
            return models.ALLOW, models.EGRESS_ALLOW, {
                "host": host, "port": port,
            }, []
        return models.DENY, models.EGRESS_DENY_HOST, {
            "host": host, "port": port,
        }, []

    # ---- 工具能力 ----
    def _step_use_tool(self, params: dict, step_index: int):
        tool = params["tool"]
        if decide_tool(self.policy, tool):
            return models.ALLOW, models.TOOL_ALLOW, {"tool": tool}, []
        return models.DENY, models.TOOL_DENY_CAPABILITY, {"tool": tool}, []

    # ---- 持久化目录写入 ----
    def _step_write_file(self, params: dict, step_index: int):
        raw_path = params["path"]
        base_dir = params.get("base_dir")
        normalized, escaped = normalize_path(raw_path, base_dir)
        if escaped:
            return models.DENY, models.FILE_DENY_TRAVERSAL, {
                "path": raw_path, "normalized": normalized,
                "base_dir": base_dir,
            }, []
        data = params["content"].encode("utf-8")
        root = persistence_entry(self.policy, normalized)
        if root is None:
            # 非持久化路径：按普通文件可见性判定
            allowed, matched = decide_file(self.policy, normalized)
            if not allowed:
                return models.DENY, models.FILE_DENY_RULE, {
                    "path": raw_path, "normalized": normalized,
                    "matched_rule": matched,
                }, []
            entry = {
                "path": normalized,
                "sha256": sha256_bytes(data),
                "size_bytes": len(data),
                "origin_step": step_index,
            }
            return models.ALLOW, models.FILE_ALLOW, {
                "path": normalized, "size_bytes": len(data),
            }, [entry]
        # 持久化目录由专门声明管辖：模式与配额，不再走可见性规则
        key = root["path"].rstrip("/")
        used = self.persist_usage.get(key, 0)
        quota = root.get("quota_bytes")
        if quota is not None and used + len(data) > int(quota):
            return models.DENY, models.PERSIST_DENY_QUOTA, {
                "path": normalized, "quota_bytes": int(quota),
                "used_bytes": used, "requested_bytes": len(data),
            }, []
        self.persist_usage[key] = used + len(data)
        entry = {
            "path": normalized,
            "sha256": sha256_bytes(data),
            "size_bytes": len(data),
            "origin_step": step_index,
        }
        return models.ALLOW, models.PERSIST_ALLOW, {
            "path": normalized, "size_bytes": len(data),
            "persist_root": key,
        }, [entry]
