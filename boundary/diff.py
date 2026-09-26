"""两次运行的差异裁决：新增暴露、误拦截、原因码变化。

以步骤 key 对齐两次运行；分类时参考步骤声明的期望（expect）：
- 期望拒绝的步骤从拒绝变为允许 → 新增暴露
- 期望允许的步骤从允许变为拒绝 → 误拦截
- 结论相同但原因码不同 → 原因码变化
"""
from __future__ import annotations

from . import models


def diff_step_payloads(steps_a: list[dict], steps_b: list[dict]) -> dict:
    by_key_a = {step["key"]: step for step in steps_a}
    by_key_b = {step["key"]: step for step in steps_b}
    new_exposures = []
    false_blocks = []
    reason_changes = []
    for key in sorted(set(by_key_a) & set(by_key_b)):
        step_a = by_key_a[key]
        step_b = by_key_b[key]
        expect = step_b.get("expect") or step_a.get("expect")
        decision_a = step_a["decision"]
        decision_b = step_b["decision"]
        if decision_a == models.DENY and decision_b == models.ALLOW \
                and expect == models.DENY:
            new_exposures.append({
                "step_key": key,
                "expect": expect,
                "a": {"decision": decision_a, "reason_code": step_a["reason_code"]},
                "b": {"decision": decision_b, "reason_code": step_b["reason_code"]},
            })
        elif decision_a == models.ALLOW and decision_b == models.DENY \
                and expect == models.ALLOW:
            false_blocks.append({
                "step_key": key,
                "expect": expect,
                "a": {"decision": decision_a, "reason_code": step_a["reason_code"]},
                "b": {"decision": decision_b, "reason_code": step_b["reason_code"]},
            })
        elif decision_a == decision_b \
                and step_a["reason_code"] != step_b["reason_code"]:
            reason_changes.append({
                "step_key": key,
                "decision": decision_a,
                "a_reason_code": step_a["reason_code"],
                "b_reason_code": step_b["reason_code"],
            })
    return {
        "new_exposures": new_exposures,
        "false_blocks": false_blocks,
        "reason_changes": reason_changes,
        "added_steps": sorted(set(by_key_b) - set(by_key_a)),
        "removed_steps": sorted(set(by_key_a) - set(by_key_b)),
    }
