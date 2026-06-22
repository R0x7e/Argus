"""
LangGraph 状态图构建模块

构建 Argus 多 Agent 协作的核心引擎：一个基于 LangGraph 的状态图，
实现 Orchestrator → Hypothesizer → Verifier → Orchestrator 循环 + Reporter 终结。
"""

import logging

from langgraph.graph import END, StateGraph

from app.agents.nodes import (
    hypothesizer_node,
    orchestrator_node,
    reporter_node,
    verifier_node,
)
from app.agents.routing import route_from_orchestrator
from app.agents.state import Blackboard, VulnHuntState

logger = logging.getLogger(__name__)


def build_vuln_hunt_graph():
    """
    构建漏洞挖掘状态图

    图结构：

        ┌──────────────┐
        │  orchestrator │
        └──────┬───────┘
               │ (条件路由)
          ┌────┼────────┐
          │    │        │
          ▼    ▼        ▼
    hypothesizer reporter  (不再直接到 END)
          │         │
          ▼         ▼
      verifier    __end__
          │
          └──► orchestrator (反馈循环)

    - Orchestrator 调用侦察工具分析目标，决定继续或结束
    - Hypothesizer 生成漏洞假设
    - Verifier 使用工具验证假设并记录结果
    - Reporter 汇总所有 findings，渲染 Markdown 报告
    - Reporter 完成后图结束

    Returns:
        编译后的 LangGraph 可执行图
    """
    graph = StateGraph(VulnHuntState)

    # 添加节点
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("hypothesizer", hypothesizer_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("reporter", reporter_node)

    # 设置入口点
    graph.set_entry_point("orchestrator")

    # Orchestrator 出口：条件路由 → hypothesizer 或 reporter
    graph.add_conditional_edges(
        "orchestrator",
        route_from_orchestrator,
        {
            "hypothesizer": "hypothesizer",
            "reporter": "reporter",
        },
    )

    # Hypothesizer → Verifier（固定边）
    graph.add_edge("hypothesizer", "verifier")

    # Verifier → Orchestrator（反馈循环）
    graph.add_edge("verifier", "orchestrator")

    # Reporter → END（最终节点）
    graph.add_edge("reporter", END)

    compiled = graph.compile()
    logger.info("漏洞挖掘状态图构建完成（含 Reporter 节点）")
    return compiled


def create_initial_state(
    task_id: str,
    task_config: dict,
    max_iterations: int = 8,
) -> VulnHuntState:
    """
    创建任务的初始状态

    根据任务配置初始化黑板和 LangGraph 状态，作为状态图的起始输入。

    Args:
        task_id: 任务唯一标识
        task_config: 任务配置字典，包含 target_url、task_type 等
        max_iterations: 最大迭代次数（默认 3 轮）

    Returns:
        初始化完成的 VulnHuntState
    """
    bb = Blackboard(task_id=task_id)

    # target_profile 初始为空 → Orchestrator 首次运行时调用侦察工具填充
    # 仅在 task_config 提供了 base_url 时预填，否则让 orchestrator 做完整画像
    base_url = task_config.get("target_url") or task_config.get("base_url", "")
    if base_url:
        bb.target_profile = {}  # 留空让 orchestrator 通过工具填充

    initial_state: VulnHuntState = {
        "blackboard": bb,
        "current_phase": "initializing",
        "iteration_count": 0,
        "max_iterations": max_iterations,
        "task_id": task_id,
        "task_config": task_config,
        "events": [],
    }

    logger.info(
        "初始状态创建完成: task_id=%s, target=%s, max_iterations=%d",
        task_id,
        base_url,
        max_iterations,
    )

    return initial_state
