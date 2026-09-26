"""查询接口命令行：运行列表、运行详情、运行差异、发布依据。"""
from __future__ import annotations

import argparse
import json
import sys

from .service import BoundaryService


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="boundary", description="隔离边界回归平台查询接口"
    )
    parser.add_argument("--db", default="boundary.db", help="SQLite 数据库路径")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("runs", help="列出全部运行")
    show = sub.add_parser("show-run", help="查看一次运行的步骤与清单")
    show.add_argument("run_id")
    diff = sub.add_parser("diff", help="比较两次运行：新增暴露/误拦截/原因码变化")
    diff.add_argument("run_a")
    diff.add_argument("run_b")
    evidence = sub.add_parser("evidence", help="查看发布候选的评估依据")
    evidence.add_argument("candidate_id")
    evaluate = sub.add_parser("evaluate", help="立即评估发布候选门禁")
    evaluate.add_argument("candidate_id")
    events = sub.add_parser("events", help="查看事件日志（可按聚合过滤）")
    events.add_argument("aggregate_id", nargs="?", default=None)
    args = parser.parse_args(argv)

    service = BoundaryService(args.db)
    try:
        if args.command == "runs":
            _print(service.list_runs())
        elif args.command == "show-run":
            _print(service.get_run(args.run_id))
        elif args.command == "diff":
            _print(service.compare_runs(args.run_a, args.run_b))
        elif args.command == "evidence":
            _print(service.release_evidence(args.candidate_id))
        elif args.command == "evaluate":
            _print(service.evaluate_candidate(args.candidate_id))
        elif args.command == "events":
            _print(service.events(args.aggregate_id))
    finally:
        service.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
