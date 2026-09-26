# 隔离边界回归验证平台

把虚拟机隔离策略（文件可见性、网络出口、工具能力、持久化目录）声明为**版本化策略**，
用**可组合场景**描述目录遍历、链接跳转、归档成员、迟到挂载、跨任务残留等攻击链，
再以**确定性运行**逐步记录允许/拒绝原因、文件清单与摘要，最后由**发布门禁**裁决
候选策略是否满足必过场景、性能预算与例外审批。

仓库同时保留领域资料（`domain/`、`examples/events.json`）与完整可运行的平台实现
（`boundary/`），统一对象、状态、时间与审计语义。

## 快速开始

```bash
# 端到端演示（冻结时钟，输出可复现）
python3 -m boundary demo

# 构建与测试
python3 -m compileall -q .
python3 -m unittest discover -s tests -v

# 领域资料校验
python3 tools/validate_contract.py
```

所有命令都在项目根目录执行，仅依赖 Python 3.11+ 标准库与 SQLite，不需要外部服务。

## CLI 用法

```bash
DB=--db\ lab.db   # 默认 boundary.db
python3 -m boundary $DB fixture examples/fixture_lab.json
python3 -m boundary $DB scenario examples/scenarios/dir_traversal.json
python3 -m boundary $DB policy examples/policy_strict.json      # 注册为 vm-isolation@1
python3 -m boundary $DB policy examples/policy_lax.json         # 内容不同 → vm-isolation@2

python3 -m boundary $DB queue vm-isolation@1 dir-traversal@1 vm-lab@1
python3 -m boundary $DB work --executor exec-1                  # 循环领取并执行
python3 -m boundary $DB show run-xxxx                           # 逐步判定与清单
python3 -m boundary $DB compare run-a run-b                     # 差异裁决

python3 -m boundary $DB candidate CAND-1 vm-isolation@1 \
    --must-pass dir-traversal,link-jump,archive-member,late-mount,residue \
    --max-run-ms 120 --max-step-ms 50
python3 -m boundary $DB approve CAND-1 --scope perf --approver release-lead --reason "..."
python3 -m boundary $DB evaluate CAND-1                         # 裁决：released / blocked
python3 -m boundary $DB basis CAND-1                            # 审批人追溯发布依据
python3 -m boundary $DB events run-xxxx                         # 事件流审计
```

## 架构

| 模块 | 职责 |
| --- | --- |
| `boundary/util.py` | 规范化 JSON、SHA-256 摘要、路径 glob（`**` 跨段）、词法路径规范化 |
| `boundary/clock.py` | 可注入时钟：`ManualClock`（确定性）与 `SystemClock` |
| `boundary/schemas.py` | 策略 / 场景 / 夹具注册时的结构校验 |
| `boundary/store.py` | SQLite 持久化：版本化对象、运行、步骤、清单、检查点、事件、候选、审批 |
| `boundary/sandbox.py` | 确定性沙箱：逐步评估动作并给出决定与原因码 |
| `boundary/runner.py` | 排队、原子租约、事务化步骤+检查点、崩溃恢复、结果摘要 |
| `boundary/gate.py` | 发布门禁：必过场景 + 性能预算 + 例外审批的联合裁决 |
| `boundary/compare.py` | 任意两次运行的差异裁决 |
| `boundary/platform.py` | 门面 API；`boundary/cli.py` 为命令行入口 |

## 核心语义

### 版本化与冻结输入

- 策略、场景、夹具按内容寻址版本化：内容不变 → 幂等返回现有版本；内容变化 →
  追加新版本，历史版本永不覆盖（对应合同规则 P-10-01）。
- 每次运行在排队时冻结 `policy@version`、`scenario@version`、`fixture@version`
  与起点时钟 `clock_start`，之后不可变更。

### 确定性运行

- 步骤时间戳 = `clock_start` + 之前步骤的逻辑耗时（`cost_ms`），与真实执行时刻无关；
  相同输入和时钟下结果摘要（覆盖逐步判定、原因码、文件清单）必然一致（P-10-02）。
- 每步记录：动作、决定（allow/deny）、原因码、判定（ok/exposure/false_block）、
  解析后路径、细节、时间戳、逻辑耗时；写操作产生清单条目（路径、内容摘要、是否持久化）。
- 判定口径：应拒却放 = **暴露（exposure）**；应放却拒 = **误拦截（false_block）**；
  全部符合预期则运行 `passed`，否则 `failed`。

### 攻击链评估

- **目录遍历**：词法规范化，`..` 越出根目录 → `PATH_TRAVERSAL`（平台不变量）；
  规范后路径按策略规则判定。
- **链接跳转**：符号链接逐组件解析（限深 8 层 → `LINK_LOOP`），逃逸根目录 →
  `LINK_ESCAPE`，否则对最终目标路径执行策略判定。
- **归档成员**：成员不得逃逸目标目录（zip-slip）→ `ARCHIVE_TRAVERSAL`（不变量）；
  落点路径再按策略判定。
- **迟到挂载**：挂载点在逻辑时间 `active_after_ms` 前不可见 → `MOUNT_NOT_ACTIVE`；
  激活后按策略判定。
- **跨任务残留**：残留文件仅当路径命中策略 `persistence_dirs` 时可见，否则
  `RESIDUE_PURGED`；可见后再按文件可见性规则判定。
- 工具能力（`tool_capabilities`）与网络出口（`network_egress`）同样逐步判定，
  原因码分别形如 `TOOL_NOT_GRANTED`、`EGRESS_DEFAULT_DENY` 或规则自带代码。

### 并发与恢复

- 租约是单条原子 `UPDATE`：两个执行器争领同一运行只有一个成功；
  步骤记录以 `(run_id, step_index)` 为主键幂等写入并校验内容一致，
  任何重放都不会双计数（P-10-03）。
- 每步连同沙箱状态在同一事务中落库为**安全检查点**；执行器崩溃后，
  租约过期由其他执行器接管，从最近检查点恢复状态继续执行，
  续跑结果与一次性运行摘要一致。

### 发布门禁

候选策略只有在三个条件同时满足时才发布（P-10-04）：

1. **必过场景**：每个必过场景都有绑定该策略版本的 `passed` 运行；
   未通过可由 `scenario:<id>` 范围的批准豁免。
2. **性能预算**：运行总耗时 ≤ `max_run_ms` 且每步 ≤ `max_step_ms`；
   超支可由 `perf` 范围的批准豁免。
3. **例外审批**：上述豁免以最新审批为准，`reject` 不构成豁免。

裁决依据（使用的运行、摘要、耗时、豁免审批）完整写入候选的决定文档；
`released` 状态不可改写，审批人通过 `basis` 追溯最终发布依据。

### 差异裁决

`compare` 以 A 为基准、B 为目标比较任意两次运行，输出：

- `new_exposures`：B 中新出现的暴露（应拒却放）；
- `new_false_blocks`：B 中新出现的误拦截；
- `reason_code_changes`：原因码变化（标注决定是否同时改变）；
- `decision_changes`：允许/拒绝翻转；
- `manifest`：文件清单的新增、移除与内容变化；
- `digest_equal`：两次运行摘要是否一致。

## 目录

- `domain/contract.json`：实体、状态、事件类型和关键业务规则。
- `domain/policies.json`：可被程序读取的策略样例。
- `examples/`：策略（宽松/严格）、夹具与五个攻击链场景样例；`events.json` 为事件样例。
- `boundary/`：平台实现（见上表）。
- `tools/validate_contract.py`：使用 Python 标准库和 SQLite 内存表验证资料一致性。
- `tests/`：沙箱判定、运行编排、发布门禁、差异裁决与端到端演示的回归测试。
