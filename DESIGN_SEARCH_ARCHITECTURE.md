# 搜索架构缺陷修复设计方案

> 针对: 分支因子爆炸、无动态扩展、UCB1 先验偏见
> 状态: 设计阶段，不含代码实现

---

## 目录

1. [问题回顾与根因分析](#1-问题回顾与根因分析)
2. [设计目标与原则](#2-设计目标与原则)
3. [总体架构变更](#3-总体架构变更)
4. [方案一: 分层渐进式搜索树](#4-方案一分层渐进式搜索树)
5. [方案二: 发现驱动的动态扩展引擎](#5-方案二发现驱动的动态扩展引擎)
6. [方案三: 自适应多因素节点选择器](#6-方案三自适应多因素节点选择器)
7. [方案四: 跨分支共享知识库](#7-方案四跨分支共享知识库)
8. [LangGraph 图结构变更](#8-langgraph-图结构变更)
9. [数据流与状态变更](#9-数据流与状态变更)
10. [参数调优策略](#10-参数调优策略)
11. [预期效果对比](#11-预期效果对比)
12. [实施风险与缓解](#12-实施风险与缓解)

---

## 1. 问题回顾与根因分析

### 三个问题的关联性

```
                    ┌──────────────────────┐
                    │  静态单次初始化        │
                    │  (init_tree 一次性     │
                    │   创建所有分支)         │
                    └──────┬───────────────┘
                           │ 导致
              ┌────────────┼────────────┐
              ▼            ▼            ▼
    ┌─────────────┐ ┌───────────┐ ┌──────────────┐
    │ 分支因子爆炸 │ │无动态扩展  │ │UCB1 先验偏见  │
    │             │ │           │ │              │
    │ 笛卡尔积     │ │NEEDS_     │ │value_estimate│
    │ 创建数百分支  │ │EXPANSION  │ │权重固定 0.3  │
    │ 粗暴剪到 60  │ │无对应逻辑  │ │低访问量时    │
    │ 被剪掉的永   │ │新发现丢失  │ │主导选择      │
    │ 远不会重试   │ │           │ │              │
    └──────┬──────┘ └─────┬─────┘ └──────┬───────┘
           │              │              │
           └──────────────┼──────────────┘
                          │ 恶性循环
                          ▼
            ┌─────────────────────────┐
            │ 搜索空间覆盖不足         │
            │ 好的分支被永久剔除        │
            │ 偏见不断自我强化          │
            │ 发现新信息后无法调整方向   │
            └─────────────────────────┘
```

### 根因分析

| 问题 | 直接原因 | 根本原因 |
|------|----------|----------|
| 分支因子爆炸 + 粗暴剪枝 | 笛卡尔积创建 + 硬限制 60 | **缺少分层探索机制** — 无法先做廉价探测再做深度投入 |
| 无动态扩展 | `NEEDS_EXPANSION` 标记无对应逻辑 | **树模型设计缺陷** — 树是静态数据结构，无生长钩子 |
| UCB1 先验偏见 | `prior = 0.3 * value_estimate` 固定权重 | **先验与经验权重失衡** — 低访问量时先验主导，且先验来源于粗糙的启发式规则 |

---

## 2. 设计目标与原则

### 核心目标

1. **可恢复性**: 任何被暂时跳过的分支都能在后续被重新评估和激活
2. **动态性**: 搜索树随着新信息的发现而持续生长
3. **经验驱动**: 随着实际探测数据的积累，先验逐渐让位于经验
4. **预算效率**: 用廉价探测筛选方向，将昂贵的 LLM 调用集中在高价值路径上

### 设计原则

- **渐进式投入**: Level 0 (HTTP probe) → Level 1 (LLM-assisted probe) → Level 2 (Full ReAct)，成本依次递增
- **发现即分支**: 任何 Exploration 中发现的端点/参数/WAF 绕过/技术栈线索，自动触发新分支创建
- **自适应权重**: UCB 公式中各因子权重随全局步数动态调整
- **知识共享**: 分支间通过共享知识库交换关键信息，避免重复踩坑

---

## 3. 总体架构变更

### 当前架构 (AS-IS)

```
Recon → Init Tree (一次性创建≤60分支) → [MCTS Select → React Execute → Evaluate] ×15 → Reporter
```

### 目标架构 (TO-BE)

```
Recon → Seed Tree (≤20种子) 
     → [Probe → AdaptiveSelect → ProbeOrExecute → Expand → Evaluate] ×N → Reporter
```

### 关键新增组件

| 组件 | 职责 | 位置 |
|------|------|------|
| **MultiLevelProber** | 执行 Level 0/1 廉价探测 | 新节点 `probe` |
| **AdaptiveNodeSelector** | 多因素自适应节点选择 | 替换 `_ucb_score` |
| **ExpansionEngine** | 发现驱动的动态分支扩展 | 新节点 `expand` |
| **SharedKnowledgeBase** | 跨分支共享知识库 | `Blackboard` 扩展 |
| **BranchScheduler** | 分支预算分配与调度 | 新节点 `evaluate` 增强 |

### LangGraph 图变更

```
当前: Recon → InitTree → MctsSelect → ReactExecute → Evaluate → [loop] → Reporter

变更为:

Recon → SeedTree → [AdaptiveSelect → ProbeOrExecute → Expand → Evaluate] ×N → Reporter
                        ↑                                            │
                        └────────────────────────────────────────────┘
```

新增节点: `AdaptiveSelect`, `ProbeOrExecute`, `Expand`
变更节点: `SeedTree`(替代 InitTree), `Evaluate`(增强)
保持节点: `Recon`, `Reporter`

---

## 4. 方案一: 分层渐进式搜索树

### 4.1 核心理念

将原本的一次性笛卡尔积 + 硬截断替换为**三层探索深度**:

```
Level 0 (Quick Probe)        Level 1 (LLM Probe)        Level 2 (Full ReAct)
┌─────────────────┐          ┌─────────────────┐         ┌─────────────────┐
│ 成本: 1-2 HTTP   │  ──▶     │ 成本: 1 LLM call │  ──▶    │ 成本: 5-10 LLM   │
│ 无 LLM 调用      │  通过    │ + 2-4 HTTP       │  通过   │ + tool calls     │
│                  │          │                  │         │                  │
│ 作用: 快速判别   │          │ 作用: 精准探测   │         │ 作用: 深度验证   │
│ 端点可达性       │          │ 发现具体漏洞信号 │         │ 完整漏洞确认     │
│ 参数有效性       │          │ 初步 bypass      │         │ 数据提取         │
│ 过滤规则探测     │          │ 评估真实价值     │         │ 漏洞利用验证     │
└─────────────────┘          └─────────────────┘         └─────────────────┘
```

### 4.2 分支生命周期

```
                    ┌──────────┐
                    │  SEED    │  ← 初始种子，来自启发式排序 Top-20
                    │ (深度=0)  │
                    └────┬─────┘
                         │
                    ┌────▼─────┐
              ┌─────│  PROBING │  ← Level 0: 发送基线请求 + 探测请求
              │     └────┬─────┘
              │          │
              │     ┌────▼──────────┐
              │     │ 评估探测结果   │
              │     └──┬──────┬─────┘
              │        │      │
              │   ┌────▼──┐   │
              │   │KILLED │   │  ← 端点 404 / 连接失败 / 全过滤 → 归档
              │   └───────┘   │
              │               │
              │          ┌────▼──────┐
              │          │ PROMOTED  │  ← 有信号 → 进入 Level 1
              │          └────┬──────┘
              │               │
              │          ┌────▼──────┐
              │          │ LLM_PROBE │  ← Level 1: LLM 分析信号 + 生成精准 payload
              │          └────┬──────┘
              │               │
              │     ┌─────────▼──────────┐
              │     │ 评估 LLM 探测结果    │
              │     └──┬────────┬────────┘
              │        │        │
              │   ┌────▼──┐ ┌───▼───────┐
              │   │LOW_SIG│ │HIGH_SIGNAL│  ← 高置信度信号 → 进入 Full ReAct
              │   │(保留)  │ └───┬───────┘
              │   └────────┘     │
              │             ┌────▼──────┐
              └─────────────│ REACTING  │  ← Level 2: 完整 ReAct 循环
                            └────┬──────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌──────────┐ ┌─────────┐ ┌──────────┐
              │CONFIRMED │ │EXHAUSTED│ │EXPANDABLE│ ← 激发动态扩展
              └──────────┘ └─────────┘ └──────────┘
```

### 4.3 状态机定义

```
状态转换:
  SEED ──▶ PROBING ──▶ { KILLED | PROMOTED }
  PROMOTED ──▶ LLM_PROBING ──▶ { LOW_SIGNAL | HIGH_SIGNAL }
  HIGH_SIGNAL ──▶ REACTING ──▶ { CONFIRMED_VULN | EXHAUSTED | EXPANDABLE }
  EXPANDABLE ──▶ (ExpansionEngine 创建新子节点为 SEED 状态)
  LOW_SIGNAL ──▶ (保留在候选池, 随预算释放可能被重新选择)
```

### 4.4 种子选择策略

替代现有的"全部创建再截断"方式，种子阶段只创建 **≤20 个**种子节点:

**优先级排序**（每个因子加权）:
```
种子得分 = 0.35 × 端点可达性期望 
        + 0.25 × 参数注入面广度
        + 0.20 × 漏洞类型先验价值
        + 0.15 × 端点来源可信度
        + 0.05 × 多样性奖励
```

- **端点可达性期望**: 来自侦察阶段的 HTTP 状态码（200/403/302 得分不同）
- **参数注入面广度**: 端点携带的参数数量和类型丰富度
- **漏洞类型先验价值**: `estimate_branch_value` 中的值（保留但权重降低）
- **端点来源可信度**: `api_doc` > `form` > `crawl` > `js_extraction` > `dir_scan`
- **多样性奖励**: 与已选种子的漏洞类型/端点路径差异越大，奖励越高

选出的 20 个种子覆盖:
- 至少 3 种漏洞类型
- 至少覆盖 60% 的已发现端点
- 优先选择有参数注入面的端点

### 4.5 Level 0 快速探测协议

每个进入 PROBING 状态的节点自动执行:

```
探测步骤 1: 基线请求
  → 发送 method=GET, url={endpoint}（不含任何注入）
  → 记录: baseline_status, baseline_len, baseline_time, baseline_headers

探测步骤 2: 探测字符注入
  → 对节点的 param 注入一个无害探测字符（如 '）
  → 记录: probe_status, probe_len, probe_time, probe_body_preview

探测步骤 3: 通用 payload 注入
  → 根据 vuln_type 注入一个最具代表性的简单 payload
  → SQLi: "' OR '1'='1"
  → XSS: "<script>"
  → LFI: "/etc/passwd"
  → SSRF: "http://127.0.0.1:80"
  → SSTI: "{{7*7}}"
  → 记录: inject_status, inject_len, inject_time, inject_body_preview

分类规则:
  IF probe 请求超时或连接失败
    → KILLED (端点不可达)
  IF baseline_status == 404 or probe_status == 404
    → KILLED
  IF |probe_len - baseline_len| == 0 for all probes
    AND probe_status == baseline_status
    AND no anomaly detected
    → KILLED (端点对参数完全无响应)
  IF probe_status != baseline_status
    OR |probe_len - baseline_len| > threshold
    OR probe_time - baseline_time > 2000ms
    OR WAF fingerprint detected (403 / specific response patterns)
    → PROMOTED (有信号, 值得 LLM 分析)
  ELSE
    → KILLED (低概率有价值)
```

这一层**零 LLM 调用**，仅消耗 3 个 HTTP 请求 + 简单规则引擎。

### 4.6 Level 1 LLM 辅助探测协议

进入 PROMOTED 后:

```
输入给 LLM:
  - 端点 URL, 参数名, 漏洞类型
  - 基线响应摘要 (status, 关键 headers, 200 字符 body 预览)
  - Level 0 探测结果 (各请求的 status/len/time 对比)
  - WAF 指纹（如检测到）
  - 当前已知的 SharedKnowledge（过滤规则、技术栈）

LLM 输出:
  {
    "signal_analysis": "基于探测结果分析",
    "high_confidence": true/false,
    "suggested_payloads": [
      {"payload": "...", "technique": "...", "reasoning": "..."},
      ...  // 2-4 个针对性 payload
    ],
    "estimated_value": 0.0-1.0,  // LLM 重新估计的真实价值
    "should_deepen": true/false
  }

执行 LLM 建议的 2-4 个 payload:
  → 每个 payload 发送 HTTP 请求
  → 记录结果

升级规则:
  IF any payload response matches vuln indicators
    OR LLM marks should_deepen=true
    OR signal_analysis indicates high_confidence
    → 升级到 HIGH_SIGNAL (进入 Level 2 Full ReAct)
  ELSE
    → LOW_SIGNAL (保留在候选池)
```

### 4.7 整体预算分配

将总搜索预算（假设 15 个周期 × 4 并发 = 60 个执行槽位）重新分配:

```
分配策略:
  40% (24 槽) → UCB1 选择的高价值节点 (Full ReAct)
  20% (12 槽) → Level 1 LLM 探测 (晋升候选节点)
  15% (9 槽)  → Level 0 快速探测 (新种子/扩展节点)
  15% (9 槽)  → 多样性探索 (漏洞类型/端点覆盖不足的方向)
  10% (6 槽)  → LLM 推荐的探索方向 (ExpansionEngine 输出)
```

---

## 5. 方案二: 发现驱动的动态扩展引擎

### 5.1 核心理念

将 ReAct 执行过程中产生的所有"发现"自动转化为新的搜索分支。

### 5.2 发现提取器

在每个 ReAct Agent 的循环中，`Observation` 和 `ThoughtStep` 不仅仅是计算奖励，还会触发**发现提取**:

```
发现类型 & 提取规则:
┌──────────────────────┬──────────────────────────────────────┐
│ 发现类型              │ 触发条件 & 生成的新分支               │
├──────────────────────┼──────────────────────────────────────┤
│ NEW_ENDPOINT         │ crawl_page / render_page /           │
│                      │ deep_crawl 发现新 URL                │
│                      │ → 为每个新端点创建 SEED 子节点        │
│                      │   (vuln_type 由参数推断)             │
├──────────────────────┼──────────────────────────────────────┤
│ NEW_PARAM            │ discover_params / probe_filter 发现  │
│                      │ 新参数名                             │
│                      │ → 为 (当前端点, 新参数, 当前vuln_type)│
│                      │   创建兄弟 SEED 节点                  │
├──────────────────────┼──────────────────────────────────────┤
│ WAF_BYPASS_FOUND     │ probe_filter 后 mutate_payload 成功  │
│                      │ → 将 bypass 技术记录到 SharedKnowledge│
│                      │ → 为同一端点+参数的其他 vuln_type    │
│                      │   创建使用该 bypass 的新节点          │
├──────────────────────┼──────────────────────────────────────┤
│ TECH_DISCOVERY       │ fingerprint / 响应头发现新框架/技术   │
│                      │ → 更新 SharedKnowledge.tech_stack    │
│                      │ → 为新匹配的 vuln_type 创建补充节点   │
├──────────────────────┼──────────────────────────────────────┤
│ AUTH_CONTEXT_CHANGE  │ test_no_auth / forge_token 发现      │
│                      │ 新的认证上下文                       │
│                      │ → 为所有已知端点创建带新 auth 的种子  │
├──────────────────────┼──────────────────────────────────────┤
│ ERROR_LEAK           │ inject_payload 响应含错误信息        │
│                      │ → 记录到 SharedKnowledge.vuln_signals│
│                      │ → 提升该端点+参数的其他 vuln_type     │
│                      │   分支优先级                         │
├──────────────────────┼──────────────────────────────────────┤
│ VULN_TYPE_CLUE       │ 响应特征暗示特定漏洞类型              │
│                      │ (如 response_time_anomaly → SQLi)    │
│                      │ → 为该端点+参数创建新 vuln_type 子节点│
└──────────────────────┴──────────────────────────────────────┘
```

### 5.3 扩展速率控制

为防止分支爆炸，对每种发现类型设置**扩展配额**:

```
配额表:
  NEW_ENDPOINT:       每次最多 3 个新节点，累计不超过 20
  NEW_PARAM:          每端点最多 5 个参数节点
  WAF_BYPASS_FOUND:   每种 bypass 技术最多创建 5 个关联节点
  TECH_DISCOVERY:     每种技术栈最多触发 3 个新 vuln_type 节点
  AUTH_CONTEXT_CHANGE: 每个新上下文件最多 10 个端点测试
  ERROR_LEAK:         不直接创建，只提升现有节点优先级
  VULN_TYPE_CLUE:     每次最多 1 个新子节点
```

全局上限: 节点总数 ≤ 200（从当前 60 提升，但通过分层探测控制实际执行成本）

### 5.4 扩展时机

```
扩展触发点:
  1. React Execute 完成后 (graph.py:react_execute → expand 边)
     → 批量处理本轮所有发现
  2. Level 1 LLM Probe 完成后
     → 如果 LLM 建议了新的探索方向
  3. Evaluate 阶段
     → 基于 SharedKnowledge 的整体分析，由 LLM 建议新的探索方向
```

### 5.5 节点淘汰与复活

```
淘汰策略 (替换现状的粗暴剪枝):
  KILLED 节点 → 移入 graveyard 集合 (不删除，保留元数据)
  
复活机制:
  当 SharedKnowledge 发生重大变更时 (如发现 WAF bypass 技术)：
    → 扫描 graveyard 中被 KILLED 的节点
    → 如果新信息可能改变其判定 (如之前因 WAF 拦截被 KILLED, 现在有了 bypass)
    → 复活为 SEED 状态重新探测
```

---

## 6. 方案三: 自适应多因素节点选择器

### 6.1 设计目标

替换固定权重的 `_ucb_score` 函数，实现随经验积累自适应调整的选择策略。

### 6.2 新选择函数

```
AdaptiveSelectionScore(node, parent, tree, knowledge) = 

  α(s) × exploitation_score(node)
+ β(s) × exploration_score(node, parent)
+ γ(s) × prior_score(node)  
+ δ    × diversity_score(node, tree)
+ ε    × recency_score(node, tree)
+ ζ    × knowledge_score(node, knowledge)
```

### 6.3 因子详解

#### exploitation_score (利用项)

```
exploitation = node.total_reward / max(1, node.visit_count)

// 使用 Wilson Score 下限避免小样本高估
// 当 visit_count >= 5: 直接使用经验平均值
// 当 visit_count < 5: 使用 Wilson 置信区间下限 (保守估计)
if node.visit_count >= 5:
    return node.total_reward / node.visit_count
else:
    // Wilson score lower bound for 95% confidence
    n = node.visit_count
    p = node.total_reward / max(1, n)
    z = 1.96
    return (p + z²/(2n) - z*sqrt(p*(1-p)/n + z²/(4n²))) / (1 + z²/n)
```

#### exploration_score (探索项)

```
exploration = C × sqrt(ln(max(1, parent.visit_count)) / node.visit_count)

// C 不再是固定 1.414, 而是自适应:
C(s) = 2.0 × exp(-s / total_expected_steps)
// s = global_step
// 早期 C ≈ 2.0 (强探索), 后期 C → 0.2 (弱探索)
```

#### prior_score (先验项)

```
// 核心改进: 先验权重随经验积累指数衰减
γ(s) = γ₀ × exp(-s / decay_steps)

// 参数:
γ₀ = 0.3           // 初始权重 (与当前一致)
decay_steps = 50    // 约 50 轮全局步数后衰减至接近 0

// 当 s = 0: γ = 0.3
// 当 s = 25: γ ≈ 0.18
// 当 s = 50: γ ≈ 0.11
// 当 s = 100: γ ≈ 0.04
```

#### diversity_score (多样性项)

```
// 鼓励选择与最近已选节点不同的方向
diversity_score(node, tree) = 
  0.15 × (1 - similarity_to_recently_selected(node, tree.recent_selections))

similarity 计算:
  如果 vuln_type 相同: +0.3
  如果 endpoint 相同: +0.4
  如果 param 相同:   +0.3
  similarity = min(1.0, 三项之和)   // [0, 1]

δ = 0.15 (固定小权重, 确保一定程度的多样性但不会主导选择)
```

#### recency_score (新鲜度项)

```
// 新创建或新升级的节点获得暂时加成
recency_score = 0.1 × exp(-age_in_cycles / 3)

// age_in_cycles: 自节点创建/升级后经过的周期数
// 新节点立即获得 +0.1, 3 个周期后衰减至 ≈ +0.04
ε = 0.1
```

#### knowledge_score (知识关联项)

```
// 如果节点受益于 SharedKnowledge 中的新发现, 给予加成
knowledge_score = 0.0

IF node.vuln_type 匹配 knowledge.recently_discovered_vuln_types: +0.08
IF node.param 匹配 knowledge.effective_params:               +0.05
IF node 可以使用 knowledge.bypass_techniques:                +0.1

ζ = 1.0 (全权重, 因为 knowledge 是高度相关的信号)
```

### 6.4 因子权重自适应曲线

```
全局步数 s 的范围: [0, ~200]

α(s) — 经验权重:
  α(0) = 0.4, α(200) = 1.0
  曲线: α(s) = 1.0 - 0.6 × exp(-s / 80)

β(s) — 探索权重:
  β(0) = 1.0, β(200) = 0.2
  曲线: β(s) = 0.2 + 0.8 × exp(-s / 60)

γ(s) — 先验权重:
  γ(0) = 0.3, γ(100) ≈ 0.04
  曲线: γ(s) = 0.3 × exp(-s / 50)

δ — 多样性权重: 固定 0.15
ε — 新鲜度权重: 固定 0.10
ζ — 知识权重:   固定 1.00 (作用于 knowledge_score)
```

### 6.5 选择流程改进

```
当前 select_batch:
  1. 循环调用 _select_avoiding (沿树向下)
  2. 每次选 UCB1 最高的未访问节点

改进后 select_batch:
  1. 收集所有待选节点 (所有状态为 UNEXPLORED/NEEDS_EXPANSION/PROMOTED 的叶子节点)
  2. 计算每个节点的 AdaptiveSelectionScore
  3. 按分数降序排列
  4. 应用多样性过滤:
     → 连续选取中, 如果下一个最高分节点与已选节点过于相似(similarity > 0.7)
     → 跳到下一个 dissimilar 节点
  5. 返回 Top-N 节点

复杂度: O(|nodes| × log|nodes|) 排序, 对 ≤ 200 节点可忽略不计
```

### 6.6 冷启动策略

在没有任何经验数据的初始阶段（前 2 个周期）:

```
冷启动选择:
  → 不使用 AdaptiveSelect
  → 直接取种子中的 Top-4 (按种子得分排序)
  → 全部发送到 Level 0 快速探测
  → 第 3 个周期开始: AdaptiveSelect 已有探测数据支撑
```

---

## 7. 方案四: 跨分支共享知识库

### 7.1 设计理由

当前每个 ReAct Agent 完全独立——分支 A 花 5 步发现某参数被 WAF 过滤，分支 B 仍然会盲目探测同一参数。知识库让"一次发现,全局受益"。

### 7.2 数据结构

```
SharedKnowledge (存储于 Blackboard 扩展字段)

├── endpoints: dict[str, EndpointInfo]
│   └── endpoint_path → {
│         "methods": ["GET", "POST", ...],
│         "params": ["param1", "param2", ...],
│         "requires_auth": true/false/unknown,
│         "response_baseline": {status, len, time, content_type},
│         "discovery_source": "dir_scan" | "crawl" | "js_extraction" | "api_doc" | "react",
│         "last_probed_at": step_number,
│         "accessibility": "accessible" | "redirect" | "auth_required" | "not_found"
│       }
│
├── waf_profile: {
│     "detected": true/false/unknown,
│     "vendor_hint": "cloudflare" | "modsecurity" | "aws_waf" | "unknown",
│     "filtered_chars": ["<", ">", "'", ...],
│     "allowed_chars": ["a-z", "0-9", ...],
│     "blocked_payloads": ["alert(", "SLEEP(", ...],
│     "bypass_techniques": [
│       {"technique": "double_url_encode", "discovered_at_step": N, "confirmed": true},
│       ...
│     ],
│     "rate_limiting": {"triggered": true/false, "threshold_estimate": N}
│   }
│
├── effective_params: dict[str, ParamInfo]
│   └── param_name → {
│         "found_on_endpoints": ["/api/x", "/api/y"],
│         "injection_context": "query" | "body" | "header" | "path",
│         "reflected": true/false,
│         "filtered": true/false,
│         "vuln_signals": {
│           "sqli": {"signal": "error_leaked", "confidence": 0.7},
│           "xss": {"signal": "reflected", "confidence": 0.5}
│         }
│       }
│
├── vuln_signals: dict[str, list[VulnSignal]]
│   └── endpoint_path → [
│         {"param": "q", "vuln_type": "sqli", "signal_type": "time_anomaly",
│          "confidence": 0.6, "evidence": "3000ms delay", "step": N}
│       ]
│
├── auth_contexts: list[AuthContext]
│   └── {
│         "type": "bearer" | "cookie" | "basic" | "none",
│         "validity": "valid" | "expired" | "unknown",
│         "privilege_level": "admin" | "user" | "guest" | "unknown",
│         "token": "(reference to ExecutionContext, not stored in plain)"
│       }
│
├── tech_stack: {
│     "confirmed": ["nginx/1.18", "PHP/7.4"],
│     "suspected": ["Laravel"],
│     "discovery_sources": {"nginx/1.18": "response_header", "PHP/7.4": "error_leak"}
│   }
│
└── exploration_history: list[ExplorationRecord]
    └── {
          "node_id": "...", "vuln_type": "...", "endpoint": "...", "param": "...",
          "result": "exhausted" | "confirmed" | "killed",
          "key_findings": ["WAF blocked < and >", "error message leaked"],
          "timestamp": step_number
        }
```

### 7.3 读写接口

```
写入接口 (在 ReAct 循环中自动调用):
  knowledge.record_endpoint(path, info)
  knowledge.record_waf_rule(filtered_char, bypass_technique)
  knowledge.record_vuln_signal(endpoint, param, vuln_type, signal_type, confidence)
  knowledge.record_param(param_name, endpoint, context)
  knowledge.record_auth_context(context)
  knowledge.record_tech_discovery(tech_name, source)
  knowledge.record_exploration_result(node_id, result)

读取接口 (供选择器和扩展引擎使用):
  knowledge.get_bypass_techniques() → list[str]
  knowledge.get_effective_params() → list[str]
  knowledge.get_high_signal_endpoints(min_confidence=0.5) → list[EndpointInfo]
  knowledge.get_unexplored_combinations() → list[(endpoint, param, vuln_type)]
  knowledge.is_waf_detected() → bool
  knowledge.get_waf_vendor_hint() → str | None
```

### 7.4 线程安全

SharedKnowledge 位于 `Blackboard` 内，通过 LangGraph 状态管理机制保证节点间的顺序一致性。在 ReAct 并发池内部（多 Agent 同时写），使用 `asyncio.Lock` 保护写操作:

```
class SharedKnowledge:
    def __init__(self):
        self._lock = asyncio.Lock()
        ...
    
    async def record_endpoint(self, ...):
        async with self._lock:
            ...
```

### 7.5 知识驱动的剪枝复活

```
evaluate 阶段新增逻辑:
  → 检查 SharedKnowledge 自上次 evaluate 以来的变更
  → 对于 graveyard 中被 KILLED 的节点:
      IF 节点因 WAF 拦截被 KILLED 
         AND knowledge.waf_profile.bypass_techniques 新增
         → 复活该节点为 SEED 状态
      IF 节点因 needs_auth 被 KILLED
         AND knowledge.auth_contexts 新增有效 token
         → 复活该节点为 SEED 状态
```

---

## 8. LangGraph 图结构变更

### 8.1 新节点定义

```python
# 新 LATS 状态 (扩展)
class LATSState(TypedDict):
    blackboard: Blackboard           # 扩展: 包含 SharedKnowledge
    search_tree: SearchTree          # 扩展: 支持 SEED/PROBING 等新状态
    shared_knowledge: SharedKnowledge  # 新增
    current_cycle: int
    max_cycles: int
    task_id: str
    task_config: dict
    events: Annotated[list, operator.add]
    dry_cycles: int
    selected_nodes: list             # 当前轮选中的节点 ID
    probe_results: list              # 新增: Level 0/1 探测结果
    react_results: list
    expansion_candidates: list       # 新增: 待扩展节点
    budget: ExplorationBudget        # 新增: 预算追踪
```

### 8.2 新图构建

```python
def build_lats_v2_graph():
    graph = StateGraph(LATSState)

    # 原有节点 (保留)
    graph.add_node("recon", lats_recon_node)

    # 新/变更节点
    graph.add_node("seed_tree", lats_seed_tree_node)          # 替代 init_tree
    graph.add_node("adaptive_select", lats_adaptive_select_node)  # 替代 mcts_select
    graph.add_node("probe_or_execute", lats_probe_or_execute_node) # 替代 react_execute
    graph.add_node("expand", lats_expand_node)                # 新增
    graph.add_node("evaluate", lats_evaluate_v2_node)         # 增强版
    graph.add_node("reporter", reporter_node)                 # 不变

    graph.set_entry_point("recon")

    # 边
    graph.add_edge("recon", "seed_tree")
    graph.add_edge("seed_tree", "adaptive_select")
    graph.add_edge("adaptive_select", "probe_or_execute")
    graph.add_edge("probe_or_execute", "expand")        # ★ execute → expand
    graph.add_edge("expand", "evaluate")

    # 条件路由
    graph.add_conditional_edges(
        "evaluate",
        route_from_evaluate_v2,
        {
            "continue_select": "adaptive_select",        # 继续选择+执行
            "continue_probe": "adaptive_select",         # 继续探测 (Level 0/1)
            "reporter": "reporter",
        },
    )

    graph.add_edge("reporter", END)
    return graph.compile()
```

### 8.3 新节点职责

#### seed_tree_node

```
输入: blackboard (含 attack_surface), shared_knowledge
输出: search_tree (≤20 种子节点, 全部标记为 SEED), shared_knowledge 初始化

逻辑:
  1. 创建根节点 (同 init_tree)
  2. 调用 SeedSelector 选出 ≤20 个种子组合
  3. 为每个种子创建 SearchNode (status=SEED)
  4. 初始化 SharedKnowledge (提取 base_url, 初始 tech_stack 等)
  5. 将所有种子加入待探测队列
```

#### adaptive_select_node

```
输入: search_tree, shared_knowledge, budget, current_cycle
输出: selected_nodes (本轮选中节点的 ID 列表)

逻辑:
  1. 收集所有候选节点 (状态: SEED, PROMOTED, HIGH_SIGNAL, NEEDS_EXPANSION, LOW_SIGNAL)
  2. 如果当前周期 ≤ 2: 冷启动模式, 选 Top-4 种子
  3. 否则: 对每个候选计算 AdaptiveSelectionScore
  4. 按分数排序 + 多样性过滤
  5. 根据 Budget 分配决定选中数量
  6. 返回选中节点
```

#### probe_or_execute_node

```
输入: selected_nodes, search_tree, shared_knowledge, context
输出: probe_results, react_results, updated tree/knowledge

逻辑:
  FOR each selected_node:
    CASE node.status == SEED:
      → Level 0 快速探测 (MultiLevelProber.probe_level_0)
      → 根据结果: KILLED | PROMOTED
    CASE node.status == PROMOTED:
      → Level 1 LLM 辅助探测 (MultiLevelProber.probe_level_1)
      → 根据结果: LOW_SIGNAL | HIGH_SIGNAL
    CASE node.status in (HIGH_SIGNAL, NEEDS_EXPANSION):
      → Level 2 Full ReAct 执行
      → 根据结果: CONFIRMED_VULN | EXHAUSTED | EXPANDABLE
    CASE node.status == LOW_SIGNAL:
      → 如果 budget 允许且无更高优先级节点: 尝试 Level 1 重新评估
      → 否则: 保持 LOW_SIGNAL (留在候选池)
```

#### expand_node (新增核心)

```
输入: probe_results, react_results, shared_knowledge, search_tree
输出: search_tree (含新分支), expansion_candidates, updated shared_knowledge

逻辑:
  1. 遍历本轮所有执行结果, 提取发现 (DiscoveryExtractor)
  2. 按发现类型分类: NEW_ENDPOINT, NEW_PARAM, WAF_BYPASS_FOUND, etc.
  3. 对每类发现, 在配额内创建新的 SEED 子节点
  4. 处理 LLM 建议的探索方向 (如果有)
  5. 检查 Graveyard 复活条件
  6. 更新 SharedKnowledge
  7. 记录 expansion_candidates 供前端展示
```

#### evaluate_v2_node (增强版)

```
输入: search_tree, shared_knowledge, budget, current_cycle, expansion_candidates
输出: 路由决策 + 剪枝/复活指令

新增逻辑:
  - 基于 SharedKnowledge 的整体分析 (非仅树统计)
  - Graveyard 复活检查
  - 多样性覆盖度评估 (各 vuln_type / endpoint 的探索覆盖率)
  - 预算消耗速率 vs 漏洞发现速率分析
  - 如果覆盖率 > 80% 且无新发现 → 建议进入 report
```

---

## 9. 数据流与状态变更

### 9.1 Blackboard 扩展

```python
@dataclass
class Blackboard:
    # ... 现有字段 ...

    # 新增
    shared_knowledge: SharedKnowledge = field(default_factory=SharedKnowledge)
    exploration_budget: ExplorationBudget = field(default_factory=ExplorationBudget)
    expansion_history: list = field(default_factory=list)  # 扩展记录
```

### 9.2 SearchNode 扩展

```python
@dataclass
class SearchNode:
    # ... 现有字段 ...

    # 新增
    probe_level: int = 0                    # 0=未探测, 1=Level0, 2=Level1, 3=Level2
    probe_results: list[dict] = field(default_factory=list)  # 探测历史
    empirical_value: float = 0.0            # 基于探测的经验价值估计
    created_at_cycle: int = 0               # 创建时的周期
    promoted_at_cycle: int | None = None    # 升级时的周期
    diversity_tags: list[str] = field(default_factory=list)  # [vuln_type, endpoint_hash, param]
```

### 9.3 ExplorationBudget

```python
@dataclass
class ExplorationBudget:
    total_slots: int = 60          # 总执行槽位 (15 cycle × 4 concurrent)
    slots_used: int = 0
    allocations: dict = field(default_factory=lambda: {
        "level_2_react": 0.40,     # Full ReAct
        "level_1_probe": 0.20,     # LLM Probe
        "level_0_probe": 0.15,     # Quick Probe
        "diversity": 0.15,         # Diversity exploration
        "llm_suggested": 0.10,     # LLM-suggested directions
    })

    def allocate(self, category: str) -> bool:
        """检查是否还有该类别的预算"""
        ...

    def remaining_slots(self) -> int:
        return self.total_slots - self.slots_used
```

---

## 10. 参数调优策略

### 10.1 关键超参数

| 参数 | 推荐值 | 调节方向 | 说明 |
|------|--------|----------|------|
| 初始种子数 | 20 | 增加→更广覆盖/更慢收敛 | 平衡覆盖度和执行效率 |
| UCB `γ₀` (先验初始权重) | 0.3 | 增加→更依赖规则/减少→更快数据驱动 | 当前值保留,加衰减 |
| UCB `decay_steps` | 50 | 增加→先验影响更持久 | 50 约等于 12 个周期 |
| Level 0 探测数/节点 | 3 | 增加→更精准/更多请求 | 基线+探测字符+payload |
| Level 1 LLM payload 数 | 2-4 | 增加→更全面/更多成本 | LLM 生成针对性 payload |
| 扩展配额 NEW_ENDPOINT | 3×20 | 增加→更广覆盖/分支更多 | 平衡分支数和搜索深度 |
| 多样性过滤阈值 | 0.7 | 降低→更多样化/可能效率低 | 相似度 > 阈值则跳过 |
| Graveyard 复活检查间隔 | 每 3 周期 | - | 避免频繁复活 |

### 10.2 自适应调参策略

```
动态周期数:
  如果连续3轮有 Level 2 Full ReAct 的执行结果 reward > 0 → 延长 max_cycles (+2)
  如果连续3轮无任何 Level 2 产出 → 触发 LLM 策略审查 (是否应切换目标/扩大范围)

动态 concurrent:
  如果目标的平均响应时间 < 500ms → 提高并发到 5-6
  如果出现 429/503 错误 → 降低并发到 2-3
```

---

## 11. 预期效果对比

### 11.1 定量对比 (估算)

| 指标 | 当前架构 | 新架构 | 改进 |
|------|----------|--------|------|
| 初始创建分支数 | 60-200 (截断到60) | 20 | 减少初期噪音 |
| 实际探索分支数* | 约 40-60 (被截断后) | 60-120 (动态扩展) | 1.5-2× 覆盖面 |
| LLM 调用次数* | 约 480 (60槽 × 8步) | 约 350 (24槽×8步 + 12槽×2步) | 节省 27% |
| HTTP 请求次数* | 约 400-600 | 约 500-700 (Level 0 探测) | 增加廉价探测, 减少昂贵探测 |
| 误报发现率 | 估计 30-50% | 估计 15-25% | 显著降低 |
| 被永久错过的分支 | 约 100+ | ≈ 0 (Graveyard 复活机制) | 根本性改进 |
| 跨分支信息利用率 | 0% | 100% (SharedKnowledge) | 根本性改进 |

*基于 15 周期 × 4 并发的假设

### 11.2 定性改进

| 方面 | 当前 | 新架构 |
|------|------|--------|
| 分支管理 | 一次性全创建, 永不可恢复 | 渐进式创建, 支持复活 |
| 探测成本控制 | 所有分支等成本 (Full ReAct) | 三层分级, 按信号投入 |
| 信息共享 | 完全隔离 | SharedKnowledge 全局共享 |
| 选择策略 | 固定权重的 UCB1 | 自适应多因素选择 |
| 搜索方向调整 | 无法调整 | 发现驱动 + LLM 建议 |
| 多样性保证 | 无 | 多样性因子 + 配额约束 |

---

## 12. 实施风险与缓解

| 风险 | 严重度 | 缓解措施 |
|------|--------|----------|
| Level 0 探测规则过于粗糙，误杀好分支 | 中 | KILLED 节点进入 Graveyard 而非删除; 知识变更时复活; 后续可引入 ML 分类器替代规则 |
| 动态扩展导致分支爆炸 | 高 | 严格的扩展配额机制; 全局 200 节点硬上限; 低价值节点及时降级 |
| SharedKnowledge 并发写入竞争 | 低 | asyncio.Lock 串行化写操作; 写操作量小 (每节点完成才写一次) |
| 自适应参数调节过拟合 | 中 | 保留手动 override; 所有自适应参数有上下界; 记录完整调参日志 |
| LLM 建议的扩展方向质量低 | 中 | 扩展配额中 LLM 方向仅占 10%; 人工审核可选 |
| 多层探测增加单周期耗时 | 低 | Level 0 无需 LLM, 可在同一周期内批量完成; Level 1 仅需 1 次 LLM 调用 |

---

## 附录: 分阶段实施路线

### Phase 1: 最小可行改进 (1-2 周)
- 实现 `AdaptiveNodeSelector` (方案三核心) — 替换 `_ucb_score`
- 添加 `diversity_score` 和 `recency_score`
- 先验衰减 `γ(s)`

### Phase 2: 动态扩展 (2-3 周)
- 实现 `ExpansionEngine` (方案二)
- 扩展配额控制
- `expand_node` 加入 LangGraph 图

### Phase 3: 分层探测 (2-3 周)
- 实现 `MultiLevelProber` (方案一)
- Level 0 快速探测规则
- Level 1 LLM 辅助探测
- 分支状态机 (SEED → PROBING → PROMOTED → ...)

### Phase 4: 知识库 (1-2 周)
- 实现 `SharedKnowledge` (方案四)
- 知识驱动的发现提取
- Graveyard 与复活机制

### Phase 5: 调优与集成测试 (1 周)
- 参数调优
- 端到端测试
- 与当前架构的 A/B 对比
