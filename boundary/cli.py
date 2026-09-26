"""命令行接口：版本注册、运行执行、差异比较与发布门禁。"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .platform import Platform


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def _load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="boundary", description="隔离边界回归验证平台")
    parser.add_argument("--db", default="boundary.db", help="SQLite 数据库路径")
    parser.add_argument("--tenant", default="default", help="租户标识")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in [("policy", "注册策略版本"), ("scenario", "注册场景版本"),
                            ("fixture", "注册夹具版本")]:
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("file", help="JSON 文件路径")
        sp.add_argument("--actor", default="cli")

    sp = sub.add_parser("queue", help="运行排队（冻结版本与时钟）")
    sp.add_argument("policy", help="策略引用，如 vm-isolation@2")
    sp.add_argument("scenario", help="场景引用，如 dir-traversal@1")
    sp.add_argument("fixture", help="夹具引用，如 vm-lab@1")

    sp = sub.add_parser("work", help="执行器循环领取并执行队列")
    sp.add_argument("--executor", default="exec-1")
    sp.add_argument("--ttl", type=int, default=300, help="租约秒数")

    sp = sub.add_parser("show", help="查看运行详情")
    sp.add_argument("run_id")

    sub.add_parser("runs", help="列出全部运行")

    sp = sub.add_parser("compare", help="比较两次运行（基准 A → 目标 B）")
    sp.add_argument("run_a")
    sp.add_argument("run_b")

    sp = sub.add_parser("candidate", help="创建发布候选")
    sp.add_argument("candidate_id")
    sp.add_argument("policy", help="策略引用，如 vm-isolation@2")
    sp.add_argument("--must-pass", required=True, help="逗号分隔的必过场景")
    sp.add_argument("--max-run-ms", type=int, default=60000)
    sp.add_argument("--max-step-ms", type=int, default=1000)

    sp = sub.add_parser("approve", help="登记例外审批")
    sp.add_argument("candidate_id")
    sp.add_argument("--scope", required=True, help="scenario:<id> 或 perf")
    sp.add_argument("--approver", required=True)
    sp.add_argument("--reason", default="")
    sp.add_argument("--reject", action="store_true")

    sp = sub.add_parser("evaluate", help="裁决发布候选")
    sp.add_argument("candidate_id")

    sp = sub.add_parser("basis", help="追溯发布依据")
    sp.add_argument("candidate_id")

    sp = sub.add_parser("events", help="查看事件流")
    sp.add_argument("aggregate_id", nargs="?")

    sub.add_parser("demo", help="端到端演示（冻结时钟，可复现）")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        from .demo import run_demo
        _print(run_demo())
        return 0
    platform = Platform(args.db, tenant=args.tenant)
    try:
        if args.command == "policy":
            _print(platform.register_policy(_load_json(args.file), actor=args.actor))
        elif args.command == "scenario":
            _print(platform.register_scenario(_load_json(args.file), actor=args.actor))
        elif args.command == "fixture":
            _print(platform.register_fixture(_load_json(args.file), actor=args.actor))
        elif args.command == "queue":
            _print({"run_id": platform.queue_run(args.policy, args.scenario, args.fixture,
                                                 actor="cli")})
        elif args.command == "work":
            _print({"completed": platform.work(args.executor, ttl_seconds=args.ttl)})
        elif args.command == "show":
            _print(platform.run_info(args.run_id))
        elif args.command == "runs":
            _print(platform.list_runs())
        elif args.command == "compare":
            _print(platform.compare(args.run_a, args.run_b))
        elif args.command == "candidate":
            _print(platform.create_candidate(
                args.candidate_id, args.policy,
                must_pass=[s for s in args.must_pass.split(",") if s],
                perf_budget={"max_run_ms": args.max_run_ms,
                             "max_step_ms": args.max_step_ms},
                actor="cli"))
        elif args.command == "approve":
            _print({"approval_id": platform.approve(
                args.candidate_id, approver=args.approver, scope=args.scope,
                decision="reject" if args.reject else "approve", reason=args.reason)})
        elif args.command == "evaluate":
            _print(platform.evaluate_candidate(args.candidate_id))
        elif args.command == "basis":
            _print(platform.release_basis(args.candidate_id))
        elif args.command == "events":
            _print(platform.events(args.aggregate_id))
    finally:
        platform.close()
    return 0
