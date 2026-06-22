"""
Argus Agent 系统 - 多 Agent 协作漏洞挖掘引擎

核心组件：
- graph: LangGraph 状态图，定义 Agent 协作流程
- state: 共享黑板和状态类型定义
- nodes: 各 Agent 节点的执行逻辑
- prompts: Agent 系统提示词
- llm: LLM 客户端封装
- model_router: 模型路由策略
- token_budget: Token 预算管理
- routing: 条件路由逻辑
"""

from app.agents.graph import build_vuln_hunt_graph, create_initial_state

__all__ = [
    "build_vuln_hunt_graph",
    "create_initial_state",
]
