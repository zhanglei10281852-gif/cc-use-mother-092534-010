"""原因码与步骤结果：差异裁决使用的稳定词汇表。

每个步骤结果都带一个原因码，说明允许或拒绝的依据。两次运行之间
即使结论相同，原因码变化也会被差异比较单独标出。
"""
from __future__ import annotations

# 文件可见性
FILE_ALLOW = "FILE_ALLOW"
FILE_DENY_RULE = "FILE_DENY_RULE"
FILE_DENY_TRAVERSAL = "FILE_DENY_TRAVERSAL"
# 链接跳转
LINK_ALLOW = "LINK_ALLOW"
LINK_DENY_ESCAPE = "LINK_DENY_ESCAPE"
# 归档成员
ARCHIVE_ALLOW = "ARCHIVE_ALLOW"
ARCHIVE_DENY_MEMBER_ESCAPE = "ARCHIVE_DENY_MEMBER_ESCAPE"
ARCHIVE_DENY_RULE = "ARCHIVE_DENY_RULE"
# 迟到挂载
MOUNT_DENY_LATE = "MOUNT_DENY_LATE"
# 跨任务残留
RESIDUE_ALLOW_SHARED = "RESIDUE_ALLOW_SHARED"
RESIDUE_DENY_CROSS_TASK = "RESIDUE_DENY_CROSS_TASK"
# 网络出口
EGRESS_ALLOW = "EGRESS_ALLOW"
EGRESS_DENY_HOST = "EGRESS_DENY_HOST"
# 工具能力
TOOL_ALLOW = "TOOL_ALLOW"
TOOL_DENY_CAPABILITY = "TOOL_DENY_CAPABILITY"
# 持久化目录
PERSIST_ALLOW = "PERSIST_ALLOW"
PERSIST_DENY_QUOTA = "PERSIST_DENY_QUOTA"

ALL_REASON_CODES = frozenset({
    FILE_ALLOW, FILE_DENY_RULE, FILE_DENY_TRAVERSAL,
    LINK_ALLOW, LINK_DENY_ESCAPE,
    ARCHIVE_ALLOW, ARCHIVE_DENY_MEMBER_ESCAPE, ARCHIVE_DENY_RULE,
    MOUNT_DENY_LATE,
    RESIDUE_ALLOW_SHARED, RESIDUE_DENY_CROSS_TASK,
    EGRESS_ALLOW, EGRESS_DENY_HOST,
    TOOL_ALLOW, TOOL_DENY_CAPABILITY,
    PERSIST_ALLOW, PERSIST_DENY_QUOTA,
})

ALLOW = "allow"
DENY = "deny"

# 场景步骤可组合的原语类型
STEP_KINDS = frozenset({
    "read_file",
    "list_dir",
    "follow_link",
    "extract_archive",
    "read_residue",
    "egress",
    "use_tool",
    "write_file",
})


def step_payload(spec: dict, step_index: int, decision: str, reason_code: str,
                 detail: dict, duration_ms: float) -> dict:
    """组装步骤结果载荷。摘要不包含任何墙钟时间，保证可重放。"""
    return {
        "step_index": step_index,
        "key": spec.get("key", f"step-{step_index}"),
        "kind": spec["kind"],
        "expect": spec.get("expect", ALLOW),
        "decision": decision,
        "reason_code": reason_code,
        "detail": detail,
        "duration_ms": duration_ms,
    }
