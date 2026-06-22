"""
Agent 路由模块

基于黑板状态的条件路由逻辑，决定 LangGraph 图中下一步执行哪个 Agent 节点。
路由规则遵循 Argus 多 Agent 协作的核心调度策略。
"""

import logging

from app.agents.state import VulnHuntState

logger = logging.getLogger(__name__)


def route_from_orchestrator(state: VulnHuntState) -> str:
    """
    从 Orchestrator 出发的条件路由

    路由逻辑（按优先级排列）：
    1. 达到最大迭代次数 → Reporter（生成报告）
    2. 当前阶段为 reporting → Reporter
    3. 当前阶段为 hypothesizing → Hypothesizer
    4. 默认 → Hypothesizer（生成新假设）
    """
    bb = state["blackboard"]
    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", 5)
    phase = state.get("current_phase", "")

    logger.debug(
        "路由决策: iteration=%d/%d, phase=%s, hypotheses=%d, findings=%d",
        iteration,
        max_iter,
        phase,
        len(bb.hypotheses),
        len(bb.findings),
    )

    # 规则 1: 达到最大迭代次数 → 生成报告
    if iteration >= max_iter:
        logger.info("已达最大迭代次数 (%d/%d)，路由到 reporter", iteration, max_iter)
        return "reporter"

    # 规则 2: Orchestrator 决定进入报告阶段
    if phase == "reporting":
        logger.info("进入报告阶段，路由到 reporter")
        return "reporter"

    # 规则 3: 默认继续生成假设
    logger.info("路由到 hypothesizer（第 %d 轮）", iteration + 1)
    return "hypothesizer"
