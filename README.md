# 隔离边界回归验证平台

把虚拟机隔离策略（文件可见性、网络出口、工具能力、持久化目录）声明为**版本化策略**，
用**可组合场景**描述目录遍历、链接跳转、归档成员、迟到挂载、跨任务残留等攻击链，
在冻结输入与可注入时钟下做**确定性运行**，逐步记录允许/拒绝原因码、文件清单与摘要；
候选策略只有在**必过场景、性能预算、例外审批**同时满足时才能发布，
查询接口可比较任意两次运行并追溯最终发布依据。

## 目录

- `boundary/`：平台实现（纯标准库，Python 3.11+）
  - `policy.py`：策略求值（可见性规则、出口、工具、持久化目录、路径归一化）
  - `fixtures.py`：夹具虚拟文件系统（文件、链接、归档、迟到挂载、残留）
  - `engine.py`：确定性步骤执行器，产出原因码与文件清单
  - `store.py`：SQLite 存储（版本化对象、运行、步骤、检查点、候选、事件日志）
  - `service.py`：门面——版本化、排队、租约、检查点恢复、发布门禁、差异查询
  - `diff.py`：差异裁决（新增暴露 / 误拦截 / 原因码变化）
  - `clock.py`：可注入时钟（`FrozenClock` / `SystemClock`）
  - `cli.py`：查询接口命令行
- `domain/contract.json`：实体、状态、事件类型和关键业务规则
- `domain/policies.json`：可被程序读取的策略样例
- `examples/events.json`：按业务发生时间排列的事件样例
- `tests/`：unittest 套件（攻击链、确定性、租约、恢复、门禁、差异）
- `tools/validate_contract.py`：领域资料一致性校验
- `tools/demo.py`：端到端演示（严格策略发布 → 宽松策略暴露 → 差异裁决）

## 核心语义

- **版本绑定**：每次运行绑定冻结的 `policy@version`、`scenario@version`、`fixture@version`；
  已登记版本不可变，任何修改产生新版本。
- **确定性**：运行摘要 = SHA-256（版本哈希 + 时钟配置 + 步骤结果 + 文件清单 + 结论）；
  相同输入与时钟重跑摘要一致，策略或夹具变化产生新摘要。
- **租约与栅栏令牌**：`claim_run` 争领租约，`fencing_token` 单调递增；
  旧令牌写入被拒绝，步骤按 `(run_id, step_index)` 幂等，两个执行器争领不会双计数。
- **安全检查点**：检查点保存步骤前缀的状态摘要；恢复时先校验最近检查点，
  不安全的检查点逐层回退，未验证的尾部一律重放。
- **发布门禁**：候选的每条必过场景需有 `passed` 运行且预算达标；
  违例可由同类型（`must_pass` / `budget`）同范围的已批准例外覆盖；
  每次评估追加保存，审批人可经 `release_evidence` 追溯发布依据。

## 构建

```bash
python3 -m compileall -q .
```

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 资料校验

```bash
python3 tools/validate_contract.py
```

## 演示

```bash
python3 tools/demo.py
```

## 查询接口

```bash
python3 -m boundary --db boundary.db runs                 # 列出运行
python3 -m boundary --db boundary.db show-run <run_id>    # 步骤与清单
python3 -m boundary --db boundary.db diff <run_a> <run_b> # 差异裁决
python3 -m boundary --db boundary.db evidence <cand_id>   # 发布依据
python3 -m boundary --db boundary.db evaluate <cand_id>   # 评估门禁
python3 -m boundary --db boundary.db events [aggregate]   # 事件日志
```

## 最小使用示例

```python
from boundary import BoundaryService, FrozenClock

service = BoundaryService(":memory:", clock=FrozenClock("2026-09-26T09:00:00+08:00"))
pv = service.create_policy("pol-vm", policy_content)      # → 版本 1
fv = service.create_fixture("fx-lab", fixture_content)    # → 版本 1
sv = service.create_scenario("scn-traversal", scenario)   # → 版本 1

run_id = service.queue_run("scn-traversal", sv, "pol-vm", pv, "fx-lab", fv,
                           clock_start="2026-09-26T09:00:00+08:00")
service.execute_run(run_id, "exec-1")                     # 租约 + 执行 + 检查点
print(service.get_run(run_id)["digest"])

candidate = service.create_candidate("pol-vm", pv, [
    {"scenario_id": "scn-traversal", "scenario_version": sv,
     "fixture_id": "fx-lab", "fixture_version": fv},
])
print(service.evaluate_candidate(candidate)["verdict"])   # released / blocked
```

所有命令都在项目根目录执行，不需要另行启动数据库、缓存或其他服务。
