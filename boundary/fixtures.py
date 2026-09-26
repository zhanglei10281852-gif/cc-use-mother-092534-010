"""夹具：冻结的虚拟文件系统视图，运行期间只读。

夹具内容一经版本化即不可变，覆盖普通文件、符号链接、归档、
迟到挂载与持久化目录残留五类攻击面。
"""
from __future__ import annotations

from .policy import normalize_path


class VirtualFS:
    def __init__(self, content: dict):
        self.files = {
            normalize_path(path)[0]: text
            for path, text in content.get("files", {}).items()
        }
        self.links = {
            normalize_path(path)[0]: target
            for path, target in content.get("links", {}).items()
        }
        self.archives = dict(content.get("archives", {}))
        self.mounts = [
            {
                "path": normalize_path(mount["path"])[0],
                "appears_at_step": int(mount.get("appears_at_step", 0)),
                "files": dict(mount.get("files", {})),
            }
            for mount in content.get("mounts", [])
        ]
        self.persistence = {
            normalize_path(path)[0]: value
            for path, value in content.get("persistence", {}).items()
        }

    def find_mount(self, path: str) -> dict | None:
        """覆盖 path 的最长前缀挂载。"""
        best = None
        for mount in self.mounts:
            root = mount["path"]
            if path == root or path.startswith(root + "/"):
                if best is None or len(root) > len(best["path"]):
                    best = mount
        return best

    def resolve_links(self, path: str, max_hops: int = 8) -> tuple[str, list[str]]:
        """沿符号链接解析到最终路径，返回 (最终路径, 经过的链接)。"""
        chain: list[str] = []
        current = path
        for _ in range(max_hops):
            target = self.links.get(current)
            if target is None:
                return current, chain
            chain.append(current)
            if target.startswith("/"):
                current = normalize_path(target)[0]
            else:
                parent = current.rsplit("/", 1)[0] or "/"
                current = normalize_path(parent + "/" + target)[0]
        raise ValueError("链接跳数超限：" + path)

    def read(self, path: str, step_index: int) -> str | None:
        mount = self.find_mount(path)
        if mount is not None:
            if step_index < mount["appears_at_step"]:
                return None
            relative = path[len(mount["path"]):].lstrip("/")
            return mount["files"].get(relative)
        return self.files.get(path)

    def list_dir(self, directory: str, step_index: int) -> list[str]:
        prefix = directory.rstrip("/") + "/"
        entries: set[str] = set()
        for path in self.files:
            if path.startswith(prefix):
                entries.add(path[len(prefix):].split("/")[0])
        for mount in self.mounts:
            root = mount["path"]
            if root.startswith(prefix):
                entries.add(root[len(prefix):].split("/")[0])
            elif root == directory.rstrip("/") and step_index >= mount["appears_at_step"]:
                entries.update(name.split("/")[0] for name in mount["files"])
        return sorted(entries)

    def residue_files(self, directory: str, owner_task: str) -> list[str]:
        entry = self.persistence.get(directory)
        if not entry:
            return []
        prefix = owner_task + "/"
        return sorted(
            name for name in entry.get("files", {}) if name.startswith(prefix)
        )
