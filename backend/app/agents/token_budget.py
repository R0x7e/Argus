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
