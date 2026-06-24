# 搜索架构改进方案选型分析

> 基于当前项目代码实际情况，评估四个方案的 ROI、实施风险、相互依赖关系，给出推荐实施路线。

---

## 1. 代码影响面评估

### 1.1 当前代码模块依赖图

```
graph.py (641 行) — LangGraph 状态图 + 6 个节点实现
  ├── search_tree.py (364 行) — SearchNode / SearchTree / UCB1 / 剪枝 / 回溯
  │     └── 被 graph.py 的 init_tree / mcts_select / react_execute / evaluate 调用
  ├── react_executor.py (367 行) — ReactAgent 循环 + ReactExecutorPool
  │     └── 被 graph.py 的 react_execute_node 调用
  ├── reward.py (197 行) — compute_reward / estimate_branch_value / infer_vuln_types
  │     └── 被 graph.py 的 init_tree_node 和 react_executor 调用
  ├── actions.py (864 行) — 19 种动作 + Observation 结构 + 漏洞检测指标
  │     └── 被 react_executor.py 调用
  └── prompts.py (170 行) — REACT_SYSTEM_PROMPT + 模板构建函数

state.py (118 行) — Blackboard / VulnHuntState / LATSState
  └── 被 graph.py 和 agent_runner.py 引用
```

### 1.2 各方案影响的代码范围

| 方案 | 涉及文件 | 改动行数估算 | 新增文件 | 风险级别 |
|------|----------|-------------|----------|----------|
| **方案三**: 自适应选择器 | `search_tree.py` (修改 `_ucb_score` + `select_batch`) | ~80 行修改 | 0 | **低** |
| **方案二**: 动态扩展引擎 | `search_tree.py` (新方法), `graph.py` (新增 expand_node + 边), `react_executor.py` (发现提取钩子) | ~200 行修改 + ~250 行新增 | 1 (`expansion_engine.py`) | **中** |
| **方案四**: 共享知识库 | `state.py` (Blackboard 扩展), `react_executor.py` (写入钩子), `graph.py` (选择/评估读取) | ~150 行修改 + ~200 行新增 | 1 (`shared_knowledge.py`) | **中** |
| **方案一**: 分层渐进探测 | `graph.py` (seed_tree + probe_or_execute 替换两个节点), `search_tree.py` (新状态), `react_executor.py` (L0/L1 探测逻辑分离) | ~400 行修改 + ~350 行新增 | 2 (`multi_level_prober.py`, `seed_selector.py`) | **高** |

---

## 2. 各方案 ROI 分析

### 2.1 方案三: 自适应多因素节点选择器

**改动范围**: 仅 `search_tree.py` 一个文件，修改 `_ucb_score()` 和 `select_batch()`

**解决的问题**:
- ✅ UCB1 先验偏见 — 通过 `γ(s)` 衰减，50 步后先验权重降至 0.04
- ✅ 缺乏多样性 — 新增 `diversity_score` 防止连续选同类型节点
- ✅ 新发现被忽视 — 新增 `recency_score` 给予新节点暂时加成
- ✅ 冷启动无方向 — 前 2 周期使用种子得分排序

**未解决的问题**:
- ❌ 分支仍是静态的 — 不解决"无动态扩展"问题
- ❌ 信息不共享 — 不解决"跨分支知识隔离"问题
- ❌ 探测成本不可控 — 所有分支仍是等成本的 Full ReAct

**ROI 评估**:

| 维度 | 评分 (1-10) | 说明 |
|------|------------|------|
| 改进效果 | 5 | 选择更聪明了，但选择池仍是静态的，好的分支可能根本不在池中 |
| 实施成本 | 9 | 仅改一个文件的内部算法，无新增依赖 |
| 风险 | 9 | 纯算法替换，参数可调节，出问题可秒回滚 |
| **综合 ROI** | **7.0** | 性价比最高的单点改进 |

**结论**: 值得做，但**单独做效果有限**——更好的选择器从有限的静态池中挑选，如同更好的拣货员从半空的货架上拣货。

---

### 2.2 方案二: 发现驱动的动态扩展引擎

**改动范围**: `graph.py` (+1 节点), `search_tree.py` (新增方法), `react_executor.py` (钩子), 新增 `expansion_engine.py`

**解决的问题**:
- ✅ 无动态扩展 — 这是**直接修复**
- ✅ 新发现丢失 — 端点/参数/WAF 绕过自动创建分支
- ✅ 搜索空间固化 — 树可以生长，实际探索的分支数从 40-60 提升到 60-120
- ✅ 被 KILLED 的分支永不可恢复 — Graveyard + 复活机制

**未解决的问题**:
- ❌ 选择策略仍使用旧 UCB1 — 虽有更多选项但选择质量不高
- ❌ 信息不共享 — 扩展引擎本身可创建分支，但分支间仍不共享运行时发现
- ❌ 探测成本不可控 — 新分支创建后直接走 Full ReAct

**ROI 评估**:

| 维度 | 评分 (1-10) | 说明 |
|------|------------|------|
| 改进效果 | 8 | 从根本上解决了"搜索空间固化"问题 |
| 实施成本 | 6 | 需新增 LangGraph 节点 + 钩子 + 配额控制 |
| 风险 | 7 | 扩展配额控制不当可能导致分支爆炸 |
| **综合 ROI** | **7.0** | 效果最显著的单一改进，但需配合方案三 |

**结论**: 这是**最关键的单一改进**——没有动态扩展，其他改进都是锦上添花。但独立使用时有"扩展出的新分支仍用旧 UCB1 选择"的问题，建议与方案三联合实施。

---

### 2.3 方案四: 跨分支共享知识库

**改动范围**: `state.py` (Blackboard 扩展), `react_executor.py` (写入钩子), `graph.py` (选择时读取), 新增 `shared_knowledge.py`

**解决的问题**:
- ✅ 跨分支信息隔离 — WAF 规则发现一次,全局受益
- ✅ 重复探测 — 分支 B 不会再探测分支 A 已验证的死路
- ✅ 扩展质量低 — 知识库为 ExpansionEngine 提供更精准的扩展建议
- ✅ 退出决策粗糙 — Evaluate 阶段可利用知识库做更智能的覆盖率分析

**未解决的问题**:
- ❌ 不直接解决 UCB1 偏见
- ❌ 不直接解决静态搜索树
- ❌ 不直接解决探测成本

**ROI 评估**:

| 维度 | 评分 (1-10) | 说明 |
|------|------------|------|
| 改进效果 | 7 | 作为"增效器"而非独立解决方案，放大其他方案的效果 |
| 实施成本 | 5 | 需线程安全的共享数据结构 + 多处钩子 |
| 风险 | 6 | asyncio 并发写需要仔细测试 |
| **综合 ROI** | **6.0** | 最佳"催化剂"，但不适合作为独立的第一步 |

**结论**: 是一个**乘数效应**的组件——与方案二配合时，扩展引擎产出的分支质量显著提升；与方案三配合时，选择器的 `knowledge_score` 因子才有效。**应在前两个方案之后实施**。

---

### 2.4 方案一: 分层渐进式搜索树

**改动范围**: `graph.py` (两个核心节点重写), `search_tree.py` (新状态), `react_executor.py` (L0/L1 逻辑), 新增 `multi_level_prober.py`, `seed_selector.py`

**解决的问题**:
- ✅ 分支因子爆炸 — 只有 20 个种子进入系统
- ✅ 探测成本 — Level 0 零 LLM 调用即可快速筛选
- ✅ 先验偏见 — Level 0 提供实际信号替代纯先验
- ✅ LLM 调用次数 — 预计节省 27%

**未解决的问题**:
- ❌ 架构改动太大 — 这是对现有 graph.py 的最大重构

**ROI 评估**:

| 维度 | 评分 (1-10) | 说明 |
|------|------------|------|
| 改进效果 | 9 | 最全面的解决方案，同时解决三个问题 |
| 实施成本 | 2 | 改动范围最大，涉及两个核心节点重写 |
| 风险 | 3 | Level 0 规则如果过于粗糙,可能误杀有价值分支 |
| **综合 ROI** | **4.7** | 理想方案但实施代价过高 |

**结论**: 最理想的终态方案，但**单次实施风险过高**。应该将其拆分为独立组件逐步引入——先引入 Level 0 快速探测作为可选步骤，再逐步替换 init_tree。

---

## 3. 方案依赖关系

```
                    ┌─────────────┐
                    │  方案三      │
                    │  自适应选择器 │
                    │  (低风险)    │
                    └──────┬──────┘
                           │ 被依赖
              ┌────────────┼────────────┐
              ▼            ▼            │
    ┌─────────────┐ ┌───────────┐      │
    │  方案二      │ │  方案四   │      │
    │  动态扩展引擎 │─┤  共享知识库│      │
    │  (中风险)    │ │  (中风险)  │      │
    └──────┬──────┘ └───────────┘      │
           │                           │
           └───────────┬───────────────┘
                       │ 依赖
                       ▼
              ┌─────────────┐
              │  方案一      │
              │  分层渐进探测 │
              │  (高风险)    │
              └─────────────┘
```

依赖关系说明:
- **方案二依赖方案三**: 动态扩展产生的新分支需要自适应选择器来合理调度，否则新分支与旧分支用同一个有偏见的 UCB1 竞争
- **方案四增强方案二**: 知识库为 ExpansionEngine 提供更精准的扩展建议
- **方案一依赖方案二+三+四**: 分层探测需要动态扩展的 Graveyard、自适应选择的经验权重、知识库的信号积累

---

## 4. 分阶段推荐方案

### 推荐: 三阶段渐进式实施

```
Phase 1 ────▶ Phase 2 ────▶ Phase 3
(2-3周)       (2-3周)       (2-3周)
方案三+二     方案四         方案一(部分)
```

### Phase 1 (核心修复): 方案三 + 方案二

**为什么先做这两个**:
1. 方案二是**唯一能解决"无动态扩展"的方案**——这是三个缺陷中最致命的一个
2. 方案三是方案二的**必要前置**——如果没有好的选择器，扩展出的新分支无法被合理调度
3. 两者可以在不引入新 LangGraph 节点的情况下实施——方案三仅改算法，方案二新增一个 `expand` 节点（对现有节点无侵入）

**具体实施内容**:

#### 方案三实施 (搜索树内部算法替换)

修改 `search_tree.py`:
```
1. _ucb_score → _adaptive_selection_score (6 因子)
2. select_batch → 新增多样性过滤 (连续选同类型时跳过)
3. 新增 diversity_tags 到 SearchNode
4. 新增 recent_selections 到 SearchTree
```

修改 `graph.py`:
```
1. cold_start 逻辑: 前 2 周期不使用 AdaptiveSelect，直接用种子得分排序
2. lats_mcts_select_node: 替换调用 _ucb_score → _adaptive_selection_score
```

#### 方案二实施 (动态扩展引擎)

新增 `expansion_engine.py`:
```python
class ExpansionEngine:
    """发现驱动的动态扩展引擎"""
    
    def extract_discoveries(self, react_results, probe_results, shared_knowledge):
        """从执行结果中提取所有发现"""
        
    def create_expansion_branches(self, tree, discoveries, quotas):
        """基于发现创建新的搜索分支"""
        
    def check_graveyard_resurrection(self, tree, knowledge_changes):
        """检查是否有被 KILLED 的节点可以复活"""
```

修改 `graph.py`:
```
1. 新增 lats_expand_node (调用 ExpansionEngine)
2. 新增边: react_execute → expand → evaluate
3. route_from_evaluate: 新增 "continue_select" 路由（回到 adaptive_select）
```

修改 `react_executor.py`:
```
1. ReactResult 新增 discoveries 字段
2. react_agent_loop 中新增发现提取钩子
```

**Phase 1 预期效果**:

| 指标 | 当前 | Phase 1 后 |
|------|------|-----------|
| 探索分支总数 | 40-60 | 60-120 |
| 被永久错过的方向 | ~100+ | ≈0 |
| 选择偏差 (先验 vs 经验) | 0.3 固定权重 | 随经验衰减 |
| 同类型分支被连续选中的概率 | 高 (无多样性控制) | 低 (多样性过滤) |
| 实施风险 | - | 低 (核心逻辑独立的增量改动) |

---

### Phase 2 (效率放大器): 方案四

**为什么在 Phase 2**:
1. Phase 1 的动态扩展产生更多分支 → Phase 2 的知识库让扩变更精准
2. Phase 1 的自适应选择需要 `knowledge_score` 因子 → Phase 2 提供该因子
3. 知识库的实现独立性强，不改变核心执行流程

**具体实施内容**:

新增 `shared_knowledge.py`:
```python
class SharedKnowledge:
    """跨分支共享知识库"""
    endpoints: dict        # endpoint_path → EndpointInfo
    waf_profile: dict      # WAF 指纹与绕过技术
    effective_params: dict # 参数有效性记录
    vuln_signals: dict     # 漏洞信号积累
    tech_stack: dict       # 技术栈确认
    exploration_history: list  # 探索历史
    
    async def record_*(self, ...):  # 各类写入方法
    def get_*(self, ...):           # 各类读取方法
    def get_expansion_suggestions(self): # 为扩展引擎提供建议
```

修改 `state.py`:
```python
@dataclass  
class Blackboard:
    # ... existing ...
    shared_knowledge: SharedKnowledge = field(default_factory=SharedKnowledge)
```

修改 `react_executor.py`:
```
react_agent_loop: 每个 Observation 后调用 shared_knowledge.record_*()
```

修改 `search_tree.py`:
```
_adaptive_selection_score: knowledge_score 因子现在有数据可读取
```

**Phase 2 预期效果**:

| 指标 | Phase 1 | Phase 2 后 |
|------|---------|-----------|
| 跨分支重复探测 | 常见 | 基本消除 |
| 扩展分支质量 | 中等 (基于参数名匹配) | 高 (基于实际信号) |
| WAF 绕过尝试次数 | 每分支独立尝试 | 一次发现,全局复用 |
| 误报率 | 25-35% | 15-25% |

---

### Phase 3 (优化): 方案一部分引入

**为什么在 Phase 3 且只部分引入**:
1. 完整的方案一需要重写两个核心节点，风险最高
2. 但方案一中的 **Level 0 快速探测**可以独立工作，不依赖其他方案的变更
3. 可以先作为"节点探测预处理"引入，不改变整体流程

**具体实施内容**:

新增 `multi_level_prober.py`（仅 Level 0）:
```python
class QuickProber:
    """Level 0 快速探测 — 3 次 HTTP 请求, 零 LLM 调用"""
    
    async def probe(self, node, context) -> ProbeResult:
        # 基线请求 + 探测字符 + 代表性 payload
        # 返回: KILLED / PROMOTED + 经验信号
        
    def classify(self, baseline, probe, inject) -> str:
        # 基于规则的三分类
```

修改 `graph.py`:
```
lats_seed_tree_node (替代 init_tree): 种子数从 60 降到 20
lats_react_execute_node: 在执行 Full ReAct 前先 Level 0 探测, KILLED 的直接跳过
```

**为什么不实施 Level 1 (LLM Probe)**:
- Level 1 的成本（1 次 LLM 调用）与一个 ReAct 步骤相当
- 其价值（"更精准的 payload"）在 ReAct 的第一步也可以做到
- 建议先验证 Level 0 的效果，再决定是否引入 Level 1

**Phase 3 预期效果**:

| 指标 | Phase 2 | Phase 3 后 |
|------|---------|-----------|
| 初始 LLM 调用次数 | 约 350 | 约 250-300 (30% 分支在 Level 0 被筛掉) |
| 无价值分支的 LLM 消耗 | 高 | 几乎为零 |
| 平均每发现 LLM 成本 | 基线 | 降低 25-35% |

---

## 5. 推荐 vs 全方案对比

```
维度                      当前    仅方案三   方案三+二  三+二+四   全方案
                          ────    ──────    ────────   ────────   ─────
动态扩展                    ❌       ❌         ✅         ✅         ✅
选择质量                    低       中         中         高         高
先验偏见                    严重     轻         轻         极轻       极轻
跨分支知识共享               ❌       ❌         ❌         ✅         ✅
探测成本控制                 ❌       ❌         ❌         ❌         ✅
Graveyard 复活               ❌       ❌         ✅         ✅         ✅
分支覆盖率                   40-60    40-60      60-120     80-140     100-160
实施风险                    -        极低       低         中         高
实施周期                    -        1周        2-3周      4-5周      7-9周
SRC 挖掘效率提升             -        +15%       +40%       +60%       +80%
```

---

## 6. 最终推荐

### 推荐: Phase 1 (方案三 + 方案二) 立即实施

**理由**:
1. **方案二解决了最致命的问题** — "无动态扩展"使得搜索空间固化，不修这个其他改进都白费
2. **方案三提供了配套的选择质量** — 方案二的扩展引擎需要好的选择器来调度新分支
3. **实施风险可控** — 方案三仅改算法参数，方案二新增一个独立节点
4. **可验证** — 两个方案都有明确的成功指标（新分支创建数量、多样性评分、先验衰减曲线）
5. **不破坏现有架构** — 新增而非重写，出问题可快速回退

**不推荐一步到位实施全方案的原因**:
1. 方案一需要重写两个核心节点（`init_tree` → `seed_tree`，`react_execute` → `probe_or_execute`），风险过高
2. 全方案涉及 5+ 文件深度修改，协调成本高，容易引入回归 bug
3. 项目中 `actions.py` (864 行) 的 Observation 系统、14 个工具的 execute 协议都与当前 ReAct 循环深度耦合，一次性重构测试覆盖不足

### 实施优先级矩阵

```
影响力
 高 │  【方案二】     【方案一】
    │  动态扩展       分层探测
    │                  
    │  【方案三】     【方案四】
 低 │  自适应选择     共享知识库
    │
    └──────────────────────────
      低              高
              实施成本
```

**最优路径**: 方案三 → 方案二 → 方案四 → 方案一(部分)

即：先用低成本的方案三打好基础，再用高影响力的方案二解决核心问题，然后用方案四做效率放大，最后用方案一的 Level 0 探测做成本优化。
