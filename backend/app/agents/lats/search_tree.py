"""
LATS 搜索树核心数据结构

实现蒙特卡洛树搜索 (MCTS) 的节点、树结构和核心算法：
- SearchNode: 搜索树节点（含 MCTS 统计量）
- NodeState: 节点状态快照（支持回溯）
- SearchTree: 搜索树管理器（选择、扩展、回传、剪枝）
"""

import math
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeStatus(str, Enum):
    UNEXPLORED = "unexplored"
    EXPLORING = "exploring"
    NEEDS_EXPANSION = "needs_expansion"
    EXHAUSTED = "exhausted"
    CONFIRMED_VULN = "confirmed_vuln"
    PRUNED = "pruned"


@dataclass
class ThoughtStep:
    """ReAct 执行过程中的一步 Thought-Action-Observation"""
    thought: str
    action: str
    action_params: dict
    observation: str
    reward: float = 0.0


@dataclass
class ToolCall:
    """工具调用记录"""
    tool_name: str
    params: dict
    result: dict
    success: bool = False


@dataclass
class NodeState:
    """节点状态快照 — 完整描述了搜索树中一个节点的探索状态"""
    target_url: str
    current_endpoint: str
    current_param: str | None
    vuln_type: str

    known_facts: list[str] = field(default_factory=list)
    tried_actions: list[str] = field(default_factory=list)
    reasoning_chain: list[ThoughtStep] = field(default_factory=list)
    tool_history: list[ToolCall] = field(default_factory=list)

    def copy(self) -> "NodeState":
        """深拷贝状态用于子节点创建"""
        return NodeState(
            target_url=self.target_url,
            current_endpoint=self.current_endpoint,
            current_param=self.current_param,
            vuln_type=self.vuln_type,
            known_facts=list(self.known_facts),
            tried_actions=list(self.tried_actions),
            reasoning_chain=list(self.reasoning_chain),
            tool_history=list(self.tool_history),
        )


@dataclass
class SearchNode:
    """搜索树节点"""
    id: str
    parent_id: str | None
    depth: int

    state: NodeState

    # MCTS 统计
    visit_count: int = 0
    total_reward: float = 0.0

    # 节点元信息
    action_taken: str | None = None
    action_params: dict = field(default_factory=dict)
    observation_summary: str = ""

    # 控制
    status: NodeStatus = NodeStatus.UNEXPLORED
    children: list[str] = field(default_factory=list)

    # 评估
    value_estimate: float = 0.0
    last_visit_step: int = 0

    @property
    def average_reward(self) -> float:
        if self.visit_count == 0:
            return 0.0
        return self.total_reward / self.visit_count


class SearchTree:
    """
    搜索树管理器

    管理搜索树的生命周期和 MCTS 核心算法。
    """

    def __init__(self):
        self.nodes: dict[str, SearchNode] = {}
        self.root_id: str | None = None
        self.global_step: int = 0
        self.findings: list[dict] = []

    def set_root(self, node: SearchNode) -> None:
        self.root_id = node.id
        self.nodes[node.id] = node

    def add_child(self, parent: SearchNode, child: SearchNode) -> None:
        child.parent_id = parent.id
        self.nodes[child.id] = child
        if child.id not in parent.children:
            parent.children.append(child.id)

    def add_children(self, parent: SearchNode, children: list[SearchNode]) -> None:
        for child in children:
            self.add_child(parent, child)
        parent.status = NodeStatus.NEEDS_EXPANSION

    def get_node(self, node_id: str) -> SearchNode | None:
        return self.nodes.get(node_id)

    def get_root(self) -> SearchNode | None:
        return self.nodes.get(self.root_id) if self.root_id else None

    # ──── MCTS: SELECT ────

    def select_best_leaf(self, exploration_weight: float = 1.414) -> SearchNode | None:
        """
        从根节点沿 UCB1 最优路径向下，选择一个待探索的叶节点。
        """
        root = self.get_root()
        if root is None:
            return None

        current = root
        while current.children:
            unexplored = [
                self.nodes[cid] for cid in current.children
                if self.nodes[cid].status in (NodeStatus.UNEXPLORED, NodeStatus.NEEDS_EXPANSION)
            ]
            if unexplored:
                return max(unexplored, key=lambda n: self._ucb_score(n, current, exploration_weight))

            explorable = [
                self.nodes[cid] for cid in current.children
                if self.nodes[cid].status not in (NodeStatus.EXHAUSTED, NodeStatus.PRUNED, NodeStatus.CONFIRMED_VULN)
            ]
            if not explorable:
                return None

            current = max(explorable, key=lambda n: self._ucb_score(n, current, exploration_weight))

        if current.status in (NodeStatus.EXHAUSTED, NodeStatus.PRUNED):
            return None
        return current

    def select_batch(self, batch_size: int, exploration_weight: float = 1.414) -> list[SearchNode]:
        """选择一批待探索的节点（用于并发执行）"""
        selected = []
        visited_ids = set()

        for _ in range(batch_size * 3):
            node = self._select_avoiding(visited_ids, exploration_weight)
            if node is None:
                break
            if node.id not in visited_ids:
                selected.append(node)
                visited_ids.add(node.id)
            if len(selected) >= batch_size:
                break

        return selected

    def _select_avoiding(self, avoid: set[str], exploration_weight: float) -> SearchNode | None:
        """选择不在 avoid 集合中的最优叶节点"""
        root = self.get_root()
        if root is None:
            return None

        current = root
        while current.children:
            candidates = [
                self.nodes[cid] for cid in current.children
                if cid not in avoid and self.nodes[cid].status not in (
                    NodeStatus.EXHAUSTED, NodeStatus.PRUNED, NodeStatus.CONFIRMED_VULN
                )
            ]
            if not candidates:
                return None
            current = max(candidates, key=lambda n: self._ucb_score(n, current, exploration_weight))

        if current.id in avoid:
            return None
        return current

    def _ucb_score(self, node: SearchNode, parent: SearchNode, C: float) -> float:
        """UCB1 + 领域先验"""
        if node.visit_count == 0:
            return float('inf')

        exploitation = node.total_reward / node.visit_count
        exploration = C * math.sqrt(math.log(max(1, parent.visit_count)) / node.visit_count)
        prior = 0.3 * node.value_estimate
        freshness = 1.0 / (1.0 + 0.01 * (self.global_step - node.last_visit_step))

        return (exploitation + exploration + prior) * freshness

    # ──── MCTS: BACKPROPAGATE ────

    def backpropagate(self, node_id: str, reward: float) -> None:
        """将 reward 从节点反向传播到根"""
        self.global_step += 1
        current = self.nodes.get(node_id)
        decay = 1.0

        while current:
            current.visit_count += 1
            current.total_reward += reward * decay
            current.last_visit_step = self.global_step
            decay *= 0.85
            current = self.nodes.get(current.parent_id) if current.parent_id else None

    # ──── MCTS: PRUNING ────

    def should_prune(self, node: SearchNode, budget_ratio: float = 1.0) -> bool:
        """判断是否应该剪枝"""
        if node.visit_count >= 5 and node.total_reward <= 0:
            return True
        if node.depth >= 15:
            return True
        if node.children and all(
            self.nodes[cid].status in (NodeStatus.EXHAUSTED, NodeStatus.PRUNED)
            for cid in node.children
        ):
            return True
        if budget_ratio < 0.3 and node.value_estimate < 0.3:
            return True
        return False

    def prune_node(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.PRUNED

    # ──── 回溯 ────

    def backtrack(self, from_node_id: str) -> SearchNode | None:
        """从指定节点回溯到最近的有未探索子节点的祖先"""
        current = self.nodes.get(from_node_id)
        if current is None:
            return None

        current.status = NodeStatus.EXHAUSTED

        while current.parent_id:
            parent = self.nodes[current.parent_id]
            unexplored_siblings = [
                self.nodes[cid] for cid in parent.children
                if self.nodes[cid].status in (NodeStatus.UNEXPLORED, NodeStatus.NEEDS_EXPANSION)
            ]
            if unexplored_siblings:
                return max(unexplored_siblings, key=lambda n: n.value_estimate)

            parent.status = NodeStatus.EXHAUSTED
            current = parent

        return None

    # ──── 辅助方法 ────

    def mark_exhausted(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.EXHAUSTED

    def mark_confirmed(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.CONFIRMED_VULN

    def record_finding(self, finding: dict) -> None:
        self.findings.append(finding)

    def all_explored(self) -> bool:
        """检查搜索树是否已全部探索完毕"""
        root = self.get_root()
        if root is None:
            return True
        return root.status in (NodeStatus.EXHAUSTED, NodeStatus.PRUNED)

    def max_unexplored_value(self) -> float:
        """返回未探索节点中的最高价值估计"""
        max_val = 0.0
        for node in self.nodes.values():
            if node.status in (NodeStatus.UNEXPLORED, NodeStatus.NEEDS_EXPANSION):
                max_val = max(max_val, node.value_estimate)
        return max_val

    def get_unexplored_children(self, node: SearchNode) -> list[SearchNode]:
        """获取节点的未探索子节点"""
        return [
            self.nodes[cid] for cid in node.children
            if self.nodes[cid].status == NodeStatus.UNEXPLORED
        ]

    def stats(self) -> dict:
        """返回搜索树统计信息"""
        total = len(self.nodes)
        explored = sum(1 for n in self.nodes.values() if n.visit_count > 0)
        pruned = sum(1 for n in self.nodes.values() if n.status == NodeStatus.PRUNED)
        confirmed = sum(1 for n in self.nodes.values() if n.status == NodeStatus.CONFIRMED_VULN)
        return {
            "total_nodes": total,
            "explored": explored,
            "pruned": pruned,
            "confirmed_vulns": confirmed,
            "findings": len(self.findings),
            "global_step": self.global_step,
        }

    def create_child_node(
        self,
        parent: SearchNode,
        action: str,
        action_params: dict,
        vuln_type: str | None = None,
        endpoint: str | None = None,
        param: str | None = None,
        value_estimate: float = 0.5,
    ) -> SearchNode:
        """便捷方法：创建子节点"""
        child_state = parent.state.copy()
        if vuln_type:
            child_state.vuln_type = vuln_type
        if endpoint:
            child_state.current_endpoint = endpoint
        if param:
            child_state.current_param = param

        child = SearchNode(
            id=str(uuid.uuid4()),
            parent_id=parent.id,
            depth=parent.depth + 1,
            state=child_state,
            action_taken=action,
            action_params=action_params,
            value_estimate=value_estimate,
        )
        self.add_child(parent, child)
        return child
