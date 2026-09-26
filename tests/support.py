"""测试共享的构造器：策略、夹具、场景与服务平台。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from boundary import BoundaryService, FrozenClock  # noqa: E402

START = "2026-09-26T09:00:00+08:00"


def make_service() -> BoundaryService:
    return BoundaryService(":memory:", clock=FrozenClock(START))


def lab_fixture() -> dict:
    """覆盖五类攻击链的实验夹具。"""
    return {
        "files": {
            "/workspace/a.txt": "alpha",
            "/etc/secret": "top-secret",
        },
        "links": {"/workspace/link": "/etc/secret"},
        "archives": {
            "bundle.tar": [
                {"name": "ok.txt", "content": "fine"},
                {"name": "../../etc/evil.txt", "content": "pwn"},
            ],
        },
        "mounts": [
            {
                "path": "/workspace/data",
                "appears_at_step": 1,
                "files": {"secret.txt": "mounted"},
            },
        ],
        "persistence": {
            "/var/persist": {"files": {"task-a/leftover.txt": "residue"}},
        },
    }


def strict_policy() -> dict:
    """严格隔离策略：工作区可见、其余默认拒绝、禁止迟到挂载、按任务隔离。"""
    return {
        "file_visibility": {
            "rules": [
                {"effect": "allow", "pattern": "/workspace/**"},
                {"effect": "deny", "pattern": "/etc/**"},
            ],
            "default": "deny",
        },
        "network_egress": {
            "default": "deny",
            "allow": [{"host": "pypi.org", "port": 443}],
        },
        "tool_capabilities": {
            "allow": ["read", "write"],
            "deny": ["shell"],
            "default": "deny",
        },
        "persistence_dirs": [
            {"path": "/var/persist", "mode": "per-task", "quota_bytes": 64},
        ],
        "mounts": {"allow_late": False},
        "performance_budget": {"max_step_ms": 50, "max_run_ms": 500},
    }


def attack_scenarios() -> dict:
    """五条攻击链场景：目录遍历、链接跳转、归档成员、迟到挂载、跨任务残留。"""
    return {
        "scn-traversal": {
            "name": "目录遍历读取敏感文件",
            "task_id": "task-b",
            "steps": [
                {"key": "traverse", "kind": "read_file", "expect": "deny",
                 "params": {"path": "../../etc/secret", "base_dir": "/workspace"}},
            ],
        },
        "scn-link": {
            "name": "符号链接跳出边界",
            "task_id": "task-b",
            "steps": [
                {"key": "hop", "kind": "follow_link", "expect": "deny",
                 "params": {"path": "/workspace/link"}},
            ],
        },
        "scn-archive": {
            "name": "归档成员逃逸解包目录",
            "task_id": "task-b",
            "steps": [
                {"key": "extract", "kind": "extract_archive", "expect": "deny",
                 "params": {"archive": "bundle.tar",
                            "dest_dir": "/workspace/unpacked"}},
            ],
        },
        "scn-late-mount": {
            "name": "迟到挂载注入文件",
            "task_id": "task-b",
            "steps": [
                {"key": "warmup", "kind": "read_file", "expect": "allow",
                 "params": {"path": "/workspace/a.txt"}},
                {"key": "mounted", "kind": "read_file", "expect": "deny",
                 "params": {"path": "/workspace/data/secret.txt"}},
            ],
        },
        "scn-residue": {
            "name": "跨任务残留嗅探",
            "task_id": "task-b",
            "steps": [
                {"key": "sniff", "kind": "read_residue", "expect": "deny",
                 "params": {"dir": "/var/persist", "owner_task": "task-a"}},
            ],
        },
    }


def setup_platform(service: BoundaryService, policy_content: dict | None = None,
                   scenarios: dict | None = None,
                   fixture_content: dict | None = None):
    """登记策略、夹具与场景，返回 (policy_version, fixture_version, {场景: 版本})。"""
    policy_version = service.create_policy(
        "pol-vm", policy_content or strict_policy())
    fixture_version = service.create_fixture(
        "fx-lab", fixture_content or lab_fixture())
    scenario_versions = {
        scenario_id: service.create_scenario(scenario_id, content)
        for scenario_id, content in (scenarios or attack_scenarios()).items()
    }
    return policy_version, fixture_version, scenario_versions


def run_scenario(service: BoundaryService, scenario_id: str,
                 scenario_version: int, policy_version: int,
                 fixture_version: int, *, nonce: str = "n1",
                 executor: str = "exec-1", **execute_kwargs) -> str:
    run_id = service.queue_run(
        scenario_id, scenario_version, "pol-vm", policy_version,
        "fx-lab", fixture_version, clock_start=START, nonce=nonce,
    )
    service.execute_run(run_id, executor, **execute_kwargs)
    return run_id
