"""任意两次运行的差异裁决：新增暴露、误拦截、原因码变化与清单差异。"""
from __future__ import annotations

from .store import Store


def _run_brief(run: dict) -> dict:
    return {
        "run_id": run["run_id"],
        "status": run["status"],
        "digest": run["digest"],
        "policy": f"{run['policy_id']}@{run['policy_version']}",
        "scenario": f"{run['scenario_id']}@{run['scenario_version']}",
        "fixture": f"{run['fixture_id']}@{run['fixture_version']}",
        "duration_ms": run["duration_ms"],
    }


def _step_brief(step: dict | None) -> dict | None:
    if step is None:
        return None
    return {"action": step["action"], "decision": step["decision"],
            "reason_code": step["reason_code"], "verdict": step["verdict"],
            "resolved_path": step["resolved_path"], "at": step["at"]}


def compare_runs(store: Store, run_a_id: str, run_b_id: str) -> dict:
    """以 run_a 为基准、run_b 为目标比较两次运行。"""
    run_a = store.get_run(run_a_id)
    run_b = store.get_run(run_b_id)
    steps_a = {s["step_index"]: s for s in store.steps_of(run_a_id)}
    steps_b = {s["step_index"]: s for s in store.steps_of(run_b_id)}
    compared: list[dict] = []
    new_exposures: list[dict] = []
    new_false_blocks: list[dict] = []
    reason_changes: list[dict] = []
    decision_changes: list[dict] = []
    for index in sorted(set(steps_a) | set(steps_b)):
        a = steps_a.get(index)
        b = steps_b.get(index)
        changes: list[str] = []
        if a is None:
            changes.append("added_step")
        if b is None:
            changes.append("removed_step")
        if a is not None and b is not None:
            if a["action"] != b["action"]:
                changes.append("action")
            if a["decision"] != b["decision"]:
                changes.append("decision")
                decision_changes.append({
                    "step_index": index, "action": b["action"],
                    "a": a["decision"], "b": b["decision"],
                })
            if a["reason_code"] != b["reason_code"]:
                changes.append("reason_code")
                reason_changes.append({
                    "step_index": index, "action": b["action"],
                    "a": a["reason_code"], "b": b["reason_code"],
                    "decision_changed": a["decision"] != b["decision"],
                })
            if a["verdict"] != b["verdict"]:
                changes.append("verdict")
        if b is not None and b["verdict"] == "exposure" and (
                a is None or a["verdict"] != "exposure"):
            new_exposures.append({"step_index": index, "action": b["action"],
                                  "reason_code": b["reason_code"],
                                  "resolved_path": b["resolved_path"]})
        if b is not None and b["verdict"] == "false_block" and (
                a is None or a["verdict"] != "false_block"):
            new_false_blocks.append({"step_index": index, "action": b["action"],
                                     "reason_code": b["reason_code"],
                                     "resolved_path": b["resolved_path"]})
        compared.append({"step_index": index, "changes": changes,
                         "a": _step_brief(a), "b": _step_brief(b)})
    manifest_a = {m["path"]: m for m in store.manifest_of(run_a_id)}
    manifest_b = {m["path"]: m for m in store.manifest_of(run_b_id)}
    manifest = {
        "added": sorted(p for p in manifest_b if p not in manifest_a),
        "removed": sorted(p for p in manifest_a if p not in manifest_b),
        "changed": sorted(
            p for p in manifest_a
            if p in manifest_b and manifest_a[p]["digest"] != manifest_b[p]["digest"]),
    }
    return {
        "run_a": _run_brief(run_a),
        "run_b": _run_brief(run_b),
        "same_scenario": (run_a["scenario_id"], run_a["scenario_version"]) == (
            run_b["scenario_id"], run_b["scenario_version"]),
        "digest_equal": run_a["digest"] is not None and run_a["digest"] == run_b["digest"],
        "new_exposures": new_exposures,
        "new_false_blocks": new_false_blocks,
        "reason_code_changes": reason_changes,
        "decision_changes": decision_changes,
        "manifest": manifest,
        "steps": compared,
    }
