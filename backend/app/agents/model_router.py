"""
模型路由模块

根据 Agent 角色和剩余预算，动态选择合适的 LLM 模型。
MVP 阶段默认使用 Sonnet 以控制成本，预算紧张时降级到 Haiku。
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 默认路由表：每个 Agent 角色对应主模型和降级模型
# MVP 阶段统一使用 Sonnet 作为主力模型，Haiku 作为降级模型
DEFAULT_ROUTING_TABLE: dict[str, dict[str, str]] = {
    "orchestrator": {
        "primary": "claude-sonnet-4-6",
        "fallback": "claude-haiku-4-5",
    },
    "hypothesizer": {
        "primary": "claude-sonnet-4-6",
        "fallback": "claude-haiku-4-5",
    },
    "verifier": {
        "primary": "claude-sonnet-4-6",
        "fallback": "claude-haiku-4-5",
    },
}


@dataclass
class ModelRouter:
    """
    模型路由器

    根据 Agent 名称和当前预算余量选择合适的模型。
    当预算剩余不足 20% 时自动降级到 fallback 模型。
    """

    routing_table: dict[str, dict[str, str]] = field(
        default_factory=lambda: dict(DEFAULT_ROUTING_TABLE)
    )

    def update_default_model(self, model_id: str) -> None:
        """用数据库配置的默认模型替换路由表中所有 primary 模型"""
        for agent_name in self.routing_table:
            self.routing_table[agent_name]["primary"] = model_id

    def select_model(self, agent: str, budget_remaining_ratio: float = 1.0) -> str:
        """
        为指定 Agent 选择模型

        Args:
            agent: Agent 名称（orchestrator / hypothesizer / verifier）
            budget_remaining_ratio: 预算剩余比例 (0.0 ~ 1.0)

        Returns:
            模型 ID 字符串

        选择策略：
        - 预算剩余 >= 20%: 使用主模型
        - 预算剩余 < 20%: 降级到 fallback 模型
        - Agent 不在路由表中: 使用 orchestrator 的配置作为默认值
        """
        # 获取该 Agent 的路由配置，不存在则用 orchestrator 的作为兜底
        route = self.routing_table.get(
            agent,
            self.routing_table.get("orchestrator", {
                "primary": "claude-sonnet-4-6",
                "fallback": "claude-haiku-4-5",
            }),
        )

        # 预算不足 20% 时降级
        if budget_remaining_ratio < 0.2:
            model = route["fallback"]
            logger.warning(
                "预算紧张 (剩余 %.1f%%)，Agent [%s] 降级使用 %s",
                budget_remaining_ratio * 100,
                agent,
                model,
            )
        else:
            model = route["primary"]
            logger.debug(
                "Agent [%s] 使用模型 %s (预算剩余 %.1f%%)",
                agent,
                model,
                budget_remaining_ratio * 100,
            )

        return model
