"""端到端演示：严格策略通过门禁发布，宽松策略暴露新风险并被差异裁决捕获。

用法：python3 tools/demo.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import support  # noqa: E402
from boundary import BoundaryService, FrozenClock  # noqa: E402


def show(title: str, obj) -> None:
    print(f"\n=== {title} ===")
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def main() -> None:
    service = BoundaryService(":memory:", clock=FrozenClock(support.START))
    pv1, fv, scenarios = support.setup_platform(service)
    print(f"策略 pol-vm@{pv1}、夹具 fx-lab@{fv}、场景 {sorted(scenarios)} 已版本化")

    # 1. 五条攻击链在严格策略下运行
    runs = {}
    for scenario_id, version in scenarios.items():
        runs[scenario_id] = support.run_scenario(
            service, scenario_id, version, pv1, fv, nonce=f"strict-{scenario_id}")
    show("严格策略下的运行结论", {
        sid: {
            "outcome": service.get_run(rid)["outcome"],
            "reasons": [s["reason_code"] for s in service.get_run(rid)["steps"]],
        }
        for sid, rid in runs.items()
    })

    # 2. 确定性重放：相同输入与时钟，摘要一致
    replay = support.run_scenario(
        service, "scn-archive", scenarios["scn-archive"], pv1, fv,
        nonce="replay")
    show("确定性重放", {
        "首次摘要": service.get_run(runs["scn-archive"])["digest"],
        "重放摘要": service.get_run(replay)["digest"],
        "一致": service.get_run(runs["scn-archive"])["digest"]
        == service.get_run(replay)["digest"],
    })

    # 3. 发布门禁：全部必过场景通过 → 发布
    candidate = service.create_candidate("pol-vm", pv1, [
        {"scenario_id": sid, "scenario_version": ver,
         "fixture_id": "fx-lab", "fixture_version": fv}
        for sid, ver in scenarios.items()
    ])
    evidence = service.evaluate_candidate(candidate)
    show("发布门禁评估（严格策略）", {
        "verdict": evidence["verdict"],
        "violations": evidence["violations"],
    })

    # 4. 宽松策略：共享持久化目录 + 放行 /etc → 出现新增暴露
    loose = support.strict_policy()
    loose["file_visibility"]["rules"].append(
        {"effect": "allow", "pattern": "/etc/**"})
    loose["persistence_dirs"] = [
        {"path": "/var/persist", "mode": "shared", "quota_bytes": 64}]
    pv2 = service.create_policy("pol-vm", loose)
    loose_run = support.run_scenario(
        service, "scn-residue", scenarios["scn-residue"], pv2, fv,
        nonce="loose-residue")
    diff = service.compare_runs(runs["scn-residue"], loose_run)
    show("差异裁决：宽松策略 vs 严格策略（跨任务残留链）", {
        "new_exposures": diff["new_exposures"],
        "false_blocks": diff["false_blocks"],
        "reason_changes": diff["reason_changes"],
    })

    # 5. 宽松策略的候选被门禁拦下，审批人可追溯依据
    loose_candidate = service.create_candidate("pol-vm", pv2, [
        {"scenario_id": "scn-residue",
         "scenario_version": scenarios["scn-residue"],
         "fixture_id": "fx-lab", "fixture_version": fv},
    ])
    blocked = service.evaluate_candidate(loose_candidate)
    show("发布门禁评估（宽松策略）", {
        "verdict": blocked["verdict"],
        "uncovered_violations": blocked["uncovered_violations"],
    })
    trace = service.release_evidence(candidate)
    show("发布依据追溯（已发布候选）", {
        "state": trace["candidate"]["state"],
        "policy": trace["evaluation"]["policy"],
        "runs": [
            {"scenario_id": r["scenario_id"], "run_id": r["run_id"],
             "digest": r["digest"][:16] + "…", "outcome": r["outcome"]}
            for r in trace["evaluation"]["requirements"]
        ],
    })
    service.close()


if __name__ == "__main__":
    main()
