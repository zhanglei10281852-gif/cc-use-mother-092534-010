"""端到端演示：从版本注册到发布追溯的完整流程（使用冻结时钟，结果可复现）。"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .clock import ManualClock
from .platform import Platform
from .runner import InjectedFailure

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_FILES = [
    "dir_traversal.json",
    "link_jump.json",
    "archive_member.json",
    "late_mount.json",
    "residue.json",
]


def _load(relative: str) -> dict:
    return json.loads((ROOT / "examples" / relative).read_text(encoding="utf-8"))


def run_demo() -> dict:
    clock = ManualClock(datetime(2026, 9, 26, 9, 0, 0,
                                 tzinfo=timezone(timedelta(hours=8))))
    platform = Platform(":memory:", clock=clock)
    try:
        fixture_ref = platform.register_fixture(_load("fixture_lab.json"), actor="fixture-bot")
        scenario_refs = {}
        for name in SCENARIO_FILES:
            body = _load(f"scenarios/{name}")
            scenario_refs[body["scenario_id"]] = platform.register_scenario(
                body, actor="scenario-bot")
        lax_ref = platform.register_policy(_load("policy_lax.json"), actor="policy-bot")
        strict_ref = platform.register_policy(_load("policy_strict.json"), actor="policy-bot")
        scenario_ids = list(scenario_refs)

        # 两个策略版本各跑全部场景（同一冻结时钟起点）
        runs: dict[tuple[int, str], str] = {}
        for version in (lax_ref["version"], strict_ref["version"]):
            for sid in scenario_ids:
                runs[(version, sid)] = platform.queue_run(
                    f"vm-isolation@{version}", sid, "vm-lab@1")
        platform.work("exec-demo")

        def status_of(run_id: str) -> str:
            return platform.run_info(run_id)["run"]["status"]

        def digest_of_run(run_id: str) -> str:
            return platform.run_info(run_id)["run"]["digest"]

        # 差异裁决：严格→宽松 展示新增暴露；宽松→严格 展示修复与原因码变化
        forward = platform.compare(runs[(strict_ref["version"], "dir-traversal")],
                                   runs[(lax_ref["version"], "dir-traversal")])
        backward = platform.compare(runs[(lax_ref["version"], "dir-traversal")],
                                    runs[(strict_ref["version"], "dir-traversal")])

        # 确定性：同时钟重跑，结果摘要一致
        replay = platform.queue_run("vm-isolation@2", "dir-traversal@1", "vm-lab@1")
        platform.work("exec-demo")
        determinism_ok = digest_of_run(replay) == digest_of_run(
            runs[(strict_ref["version"], "dir-traversal")])

        # 崩溃恢复：检查点续跑与一次性运行摘要一致，步骤不双计数
        crash_run = platform.queue_run("vm-isolation@2", "residue@1", "vm-lab@1")
        reference = platform.queue_run("vm-isolation@2", "residue@1", "vm-lab@1")
        steady = platform.runner("exec-steady")
        steady.lease(reference)
        steady.execute(reference)
        crashing = platform.runner("exec-crash")
        crashing.lease(crash_run, ttl_seconds=60)
        try:
            crashing.execute(crash_run, fail_after=2)
        except InjectedFailure:
            pass
        clock.advance(seconds=120)  # 租约过期
        recovery = platform.runner("exec-recovery")
        recovered = recovery.lease(crash_run)
        recovery.execute(crash_run)
        crash_info = platform.run_info(crash_run)
        resume_ok = recovered == crash_run and digest_of_run(crash_run) == digest_of_run(reference)
        no_double_count = (len(crash_info["steps"]) == 4
                           and crash_info["run"]["steps_done"] == 4)

        # 租约争用：两个执行器争领同一运行，只有一个成功
        contended = platform.queue_run("vm-isolation@2", "link-jump@1", "vm-lab@1")
        first = platform.runner("exec-1").lease(contended)
        second = platform.runner("exec-2").lease(contended)
        single_winner = (first is None) != (second is None)
        winner = "exec-1" if first else "exec-2"
        platform.runner(winner).execute(contended)

        # 发布门禁：全部必过 + 预算内 → 发布
        platform.create_candidate("CAND-STRICT", "vm-isolation@2", must_pass=scenario_ids,
                                  perf_budget={"max_run_ms": 120, "max_step_ms": 50},
                                  actor="release-manager")
        decision_strict = platform.evaluate_candidate("CAND-STRICT", actor="release-manager")

        # 预算例外：预算收紧 → 阻断；审批豁免 → 放行（可追溯）
        platform.create_candidate("CAND-TIGHT", "vm-isolation@2", must_pass=scenario_ids,
                                  perf_budget={"max_run_ms": 40, "max_step_ms": 50},
                                  actor="release-manager")
        decision_blocked = platform.evaluate_candidate("CAND-TIGHT", actor="release-manager")
        platform.approve("CAND-TIGHT", approver="release-lead", scope="perf",
                         reason="迟到挂载场景成本已纳入容量计划")
        decision_waived = platform.evaluate_candidate("CAND-TIGHT", actor="release-manager")
        basis = platform.release_basis("CAND-TIGHT")

        return {
            "策略版本": {"宽松": lax_ref, "严格": strict_ref},
            "场景版本": scenario_refs,
            "夹具版本": fixture_ref,
            "运行结果": {
                f"v{version}/{sid}": {"run_id": runs[(version, sid)],
                                      "status": status_of(runs[(version, sid)])}
                for version in (lax_ref["version"], strict_ref["version"])
                for sid in scenario_ids
            },
            "差异裁决": {
                "严格到宽松_新增暴露": len(forward["new_exposures"]),
                "宽松到严格_新增误拦截": len(backward["new_false_blocks"]),
                "宽松到严格_原因码变化": len(backward["reason_code_changes"]),
            },
            "确定性重放一致": determinism_ok,
            "崩溃恢复一致": resume_ok,
            "步骤不双计数": no_double_count,
            "租约唯一获胜者": single_winner,
            "门禁_严格候选发布": decision_strict["released"],
            "门禁_预算收紧阻断": not decision_blocked["released"],
            "门禁_例外审批放行": decision_waived["released"],
            "发布依据_审批数": len(basis["approvals"]),
            "发布依据_事件数": len(basis["events"]),
        }
    finally:
        platform.close()
