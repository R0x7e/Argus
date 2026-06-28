"""
Token 预算管理模块

跟踪每个任务的 Token 消耗，支持分 Agent 统计和预算告警。
当消耗达到 50%/80%/95% 时发出告警，超限后阻止进一步调用。
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TokenBudget:
    """
    Token 预算管理器

    追踪单个任务的 Token 用量，支持：
    - 分 Agent 用量统计
    - 阶梯式预算告警 (50%, 80%, 95%)
    - 预算超限检测
    """

    task_id: str                                    # 关联任务 ID
    total_budget: int = 500_000                     # 总预算（Token 数）
    spent: int = 0                                  # 已消耗 Token 数
    per_agent: dict[str, dict[str, int]] = field(   # 分 Agent 用量统计
        default_factory=dict
    )

    # 内部状态：已触发的告警阈值集合，避免重复告警
    _alerted_thresholds: set[float] = field(
        default_factory=set, repr=False
    )

    def consume(self, agent: str, tokens_in: int, tokens_out: int) -> None:
        """
        记录 Token 消耗

        Args:
            agent: Agent 名称
            tokens_in: 输入 Token 数（prompt tokens）
            tokens_out: 输出 Token 数（completion tokens）
        """
        total_tokens = tokens_in + tokens_out
        self.spent += total_tokens

        # 更新分 Agent 统计
        if agent not in self.per_agent:
            self.per_agent[agent] = {"tokens_in": 0, "tokens_out": 0, "total": 0}
        self.per_agent[agent]["tokens_in"] += tokens_in
        self.per_agent[agent]["tokens_out"] += tokens_out
        self.per_agent[agent]["total"] += total_tokens

        # 检查告警阈值
        self._check_alerts()

        logger.info(
            "任务 [%s] Agent [%s] 消耗 %d tokens (输入: %d, 输出: %d)，"
            "累计: %d / %d (%.1f%%)",
            self.task_id,
            agent,
            total_tokens,
            tokens_in,
            tokens_out,
            self.spent,
            self.total_budget,
            (self.spent / self.total_budget * 100) if self.total_budget > 0 else 0,
        )

    def _check_alerts(self) -> None:
        """检查并触发阶梯式预算告警"""
        if self.total_budget <= 0:
            return

        usage_ratio = self.spent / self.total_budget
        thresholds = [0.50, 0.80, 0.95]

        for threshold in thresholds:
            if usage_ratio >= threshold and threshold not in self._alerted_thresholds:
                self._alerted_thresholds.add(threshold)
                logger.warning(
                    "⚠️ 任务 [%s] Token 预算告警：已使用 %.1f%% (%d / %d)，阈值 %.0f%%",
                    self.task_id,
                    usage_ratio * 100,
                    self.spent,
                    self.total_budget,
                    threshold * 100,
                )

    def remaining(self) -> int:
        """返回剩余 Token 数"""
        return max(0, self.total_budget - self.spent)

    def remaining_ratio(self) -> float:
        """返回预算剩余比例 (0.0 ~ 1.0)"""
        if self.total_budget <= 0:
            return 0.0
        return max(0.0, (self.total_budget - self.spent) / self.total_budget)

    def is_exceeded(self) -> bool:
        """判断预算是否已超限"""
        return self.spent >= self.total_budget

    def get_summary(self) -> dict:
        """
        获取预算使用摘要

        Returns:
            包含总预算、已消耗、剩余、分 Agent 统计等信息的字典
        """
        return {
            "task_id": self.task_id,
            "total_budget": self.total_budget,
            "spent": self.spent,
            "remaining": self.remaining(),
            "remaining_ratio": round(self.remaining_ratio(), 4),
            "is_exceeded": self.is_exceeded(),
            "per_agent": dict(self.per_agent),
        }


# ──── v3: 分级预算管理器 ────

from enum import Enum


class BudgetTier(str, Enum):
    """预算优先级层级"""
    TIER_1_PROMOTED = "tier_1_promoted"    # 已晋升有信号的节点深度探索
    TIER_2_HIGH_SIG = "tier_2_high_sig"    # 高置信度信号→Full ReAct
    TIER_3_SEED = "tier_3_seed"            # 新种子节点Level 0/1探测
    TIER_4_RESERVE = "tier_4_reserve"      # 预留: 发现新参数/复活节点


# 默认预算分配比例
DEFAULT_TIER_ALLOCATIONS: dict[BudgetTier, float] = {
    BudgetTier.TIER_1_PROMOTED: 0.50,
    BudgetTier.TIER_2_HIGH_SIG: 0.25,
    BudgetTier.TIER_3_SEED: 0.15,
    BudgetTier.TIER_4_RESERVE: 0.10,
}

# 每个Tier的每节点最大Token消耗（防止单个节点吞噬整个Tier）
TIER_PER_NODE_MAX_TOKENS: dict[BudgetTier, int] = {
    BudgetTier.TIER_1_PROMOTED: 80_000,
    BudgetTier.TIER_2_HIGH_SIG: 120_000,
    BudgetTier.TIER_3_SEED: 20_000,
    BudgetTier.TIER_4_RESERVE: 40_000,
}


@dataclass
class TieredBudgetManager:
    """
    分级预算管理器 (v3)

    将总Token预算按优先级分为四个层级:
    ┌─────────────────┬──────────┬─────────────────────────────┐
    │ 层级             │ 占比     │ 用途                        │
    ├─────────────────┼──────────┼─────────────────────────────┤
    │ TIER_1(PROMOTED) │   50%    │ 已验证有信号的节点深度探索   │
    │ TIER_2(HIGH_SIG) │   25%    │ 高置信度信号→Full ReAct     │
    │ TIER_3(SEED)     │   15%    │ 新种子节点Level 0/1探测     │
    │ TIER_4(RESERVE)  │   10%    │ 预留: 新参数/复活节点       │
    └─────────────────┴──────────┴─────────────────────────────┘

    每个Tier独立追踪消耗，超限则暂停该Tier的LLM调用。
    未使用的Tier配额可向下兼容(next_tier_can_borrow)。
    """

    task_id: str
    total_budget: int = 500_000
    allocations: dict[BudgetTier, float] = field(
        default_factory=lambda: dict(DEFAULT_TIER_ALLOCATIONS)
    )

    # 每个Tier的已消耗Token
    tier_spent: dict[BudgetTier, int] = field(default_factory=dict)
    # 每个节点的Token消耗追踪
    per_node_spent: dict[str, int] = field(default_factory=dict)
    # 全局已消耗(向后兼容)
    total_spent: int = 0

    def __post_init__(self):
        for tier in BudgetTier:
            if tier not in self.tier_spent:
                self.tier_spent[tier] = 0

    def tier_budget(self, tier: BudgetTier) -> int:
        """获取指定Tier的分配预算"""
        ratio = self.allocations.get(tier, 0.0)
        return int(self.total_budget * ratio)

    def tier_remaining(self, tier: BudgetTier) -> int:
        """获取指定Tier的剩余预算"""
        return max(0, self.tier_budget(tier) - self.tier_spent.get(tier, 0))

    def tier_ratio(self, tier: BudgetTier) -> float:
        """获取指定Tier的剩余比例"""
        budget = self.tier_budget(tier)
        if budget <= 0:
            return 0.0
        return self.tier_remaining(tier) / budget

    def total_remaining(self) -> int:
        """获取全局剩余预算"""
        return max(0, self.total_budget - self.total_spent)

    def total_ratio(self) -> float:
        """获取全局剩余比例"""
        if self.total_budget <= 0:
            return 0.0
        return self.total_remaining() / self.total_budget

    def is_exceeded(self) -> bool:
        """全局预算是否超限"""
        return self.total_spent >= self.total_budget

    def tier_is_exceeded(self, tier: BudgetTier) -> bool:
        """指定Tier预算是否超限"""
        return self.tier_spent.get(tier, 0) >= self.tier_budget(tier)

    def can_allocate(self, tier: BudgetTier, estimated_tokens: int,
                     node_id: str = "") -> bool:
        """
        检查是否可以分配指定数量的Token给指定Tier。

        检查顺序:
        1. 全局预算未超限
        2. Tier预算未超限(或可以从下级Tier借用)
        3. 单个节点未超限
        """
        if self.is_exceeded():
            return False

        tier_rem = self.tier_remaining(tier)
        if tier_rem >= estimated_tokens:
            # 检查单节点限制
            if node_id:
                node_max = TIER_PER_NODE_MAX_TOKENS.get(tier, 20_000)
                if self.per_node_spent.get(node_id, 0) + estimated_tokens > node_max:
                    return False
            return True

        # Tier不足, 尝试从下级Tier借用
        borrowed = self._borrow_from_lower_tiers(tier, estimated_tokens - tier_rem)
        return tier_rem + borrowed >= estimated_tokens

    def allocate(self, tier: BudgetTier, tokens: int, node_id: str = "") -> bool:
        """
        分配Token给指定Tier。返回是否成功。
        """
        if self.is_exceeded():
            return False

        tier_rem = self.tier_remaining(tier)
        if tier_rem >= tokens:
            self.tier_spent[tier] = self.tier_spent.get(tier, 0) + tokens
            self.total_spent += tokens
            if node_id:
                self.per_node_spent[node_id] = self.per_node_spent.get(node_id, 0) + tokens
            return True

        # Tier不足, 从下级借用
        borrowed = self._borrow_from_lower_tiers(tier, tokens - tier_rem)
        if tier_rem + borrowed >= tokens:
            self.tier_spent[tier] = self.tier_spent.get(tier, 0) + tier_rem + borrowed
            self.total_spent += tokens
            if node_id:
                self.per_node_spent[node_id] = self.per_node_spent.get(node_id, 0) + tokens
            return True
        return False

    def _borrow_from_lower_tiers(self, requesting_tier: BudgetTier,
                                  needed: int) -> int:
        """
        从更低优先级的Tier借用预算。
        Tier优先级: TIER_1 > TIER_2 > TIER_3 > TIER_4
        只从比requesting_tier优先级低的Tier借用。
        """
        tier_order = [
            BudgetTier.TIER_1_PROMOTED,
            BudgetTier.TIER_2_HIGH_SIG,
            BudgetTier.TIER_3_SEED,
            BudgetTier.TIER_4_RESERVE,
        ]
        try:
            req_idx = tier_order.index(requesting_tier)
        except ValueError:
            return 0

        borrowed = 0
        for lower_tier in tier_order[req_idx + 1:]:
            if borrowed >= needed:
                break
            remaining = self.tier_remaining(lower_tier)
            take = min(needed - borrowed, remaining)
            # 只借RESERVE的50%, 或SEED的30%
            max_borrow_ratio = 0.5 if lower_tier == BudgetTier.TIER_4_RESERVE else 0.3
            take = min(take, int(self.tier_budget(lower_tier) * max_borrow_ratio))
            self.tier_spent[lower_tier] = self.tier_spent.get(lower_tier, 0) + take
            borrowed += take
        return borrowed

    def resolve_tier(self, node_status: str, node_visits: int = 0) -> BudgetTier:
        """
        根据节点状态解析应使用的预算Tier。

        映射规则:
        - PROMOTED/HIGH_SIGNAL → TIER_1 (信号最强, 优先保障)
        - SEED/LOW_SIGNAL/UNEXPLORED → TIER_3 (需要廉价探测)
        - 复活节点(visits=0, from graveyard) → TIER_4 (预留预算)
        - confirmed_vuln → TIER_2 (深度利用)
        - 默认 → TIER_3
        """
        if node_status in ("promoted", "high_signal", "probing"):
            return BudgetTier.TIER_1_PROMOTED
        if node_status in ("confirmed_vuln",):
            return BudgetTier.TIER_2_HIGH_SIG
        if node_status in ("seed", "low_signal", "unexplored", "needs_expansion"):
            return BudgetTier.TIER_3_SEED
        return BudgetTier.TIER_3_SEED

    def get_summary(self) -> dict:
        """获取分级预算摘要"""
        return {
            "task_id": self.task_id,
            "total_budget": self.total_budget,
            "total_spent": self.total_spent,
            "total_ratio": round(self.total_ratio(), 4),
            "is_exceeded": self.is_exceeded(),
            "tiers": {
                tier.value: {
                    "budget": self.tier_budget(tier),
                    "spent": self.tier_spent.get(tier, 0),
                    "remaining": self.tier_remaining(tier),
                    "ratio": round(self.tier_ratio(tier), 4),
                    "exceeded": self.tier_is_exceeded(tier),
                }
                for tier in BudgetTier
            },
            "per_node": dict(list(self.per_node_spent.items())[:20]),
        }
