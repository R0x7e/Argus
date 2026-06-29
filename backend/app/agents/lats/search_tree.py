"""
LATS 搜索树核心数据结构 v2

实现蒙特卡洛树搜索 (MCTS) 的节点、树结构和核心算法：
- SearchNode: 搜索树节点（含 MCTS 统计量 + v2 扩展字段）
- NodeState: 节点状态快照（支持回溯）
- SearchTree: 搜索树管理器（v2 自适应选择、Graveyard、扩展）

v2 新增:
- 自适应多因素节点选择器 (6-factor)
- 节点分层状态机 (SEED/PROBING/PROMOTED/HIGH_SIGNAL/LOW_SIGNAL/KILLED)
- Graveyard 与节点复活机制
- 多样性过滤与冷启动策略
"""

import hashlib
import math
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeStatus(str, Enum):
    """节点状态 (v2 扩展)"""
    UNEXPLORED = "unexplored"
    EXPLORING = "exploring"
    EXHAUSTED = "exhausted"
    CONFIRMED_VULN = "confirmed_vuln"
    PRUNED = "pruned"
    SEED = "seed"
    PROBING = "probing"
    PROMOTED = "promoted"
    HIGH_SIGNAL = "high_signal"
    LOW_SIGNAL = "low_signal"
    KILLED = "killed"
    NEEDS_EXPANSION = "needs_expansion"


@dataclass
class ThoughtStep:
    thought: str
    action: str
    action_params: dict
    observation: str
    reward: float = 0.0


@dataclass
class ToolCall:
    tool_name: str
    params: dict
    result: dict
    success: bool = False


@dataclass
class NodeState:
    target_url: str
    current_endpoint: str
    current_param: str | None
    vuln_type: str
    known_facts: list[str] = field(default_factory=list)
    tried_actions: list[str] = field(default_factory=list)
    reasoning_chain: list[ThoughtStep] = field(default_factory=list)
    tool_history: list[ToolCall] = field(default_factory=list)

    def copy(self) -> "NodeState":
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
    """搜索树节点 (v2 扩展)"""
    id: str
    parent_id: str | None
    depth: int
    state: NodeState
    visit_count: int = 0
    total_reward: float = 0.0
    action_taken: str | None = None
    action_params: dict = field(default_factory=dict)
    observation_summary: str = ""
    status: NodeStatus = NodeStatus.UNEXPLORED
    children: list[str] = field(default_factory=list)
    value_estimate: float = 0.0
    empirical_value: float = 0.0
    last_visit_step: int = 0
    probe_level: int = 0
    probe_results: list[dict] = field(default_factory=list)
    created_at_cycle: int = 0
    promoted_at_cycle: int | None = None
    diversity_tags: list[str] = field(default_factory=list)
    # P1: 端点预验证元数据
    endpoint_metadata: dict = field(default_factory=dict)
    #   {"accessibility": "accessible"|"redirect"|"auth_required"|...,
    #    "is_config_path": bool, "status": int, "response_time_ms": int,
    #    "content_type": str, "has_forms": bool}
    # v2: 估值衰减因子 (每次 backprop 乘以 0.85, <0.1 时标记 exhausted)
    value_decay_factor: float = 1.0
    @property
    def average_reward(self) -> float:
        if self.visit_count == 0:
            return 0.0
        return self.total_reward / self.visit_count


class SearchTree:
    """搜索树管理器 (v2: 自适应选择 + Graveyard)"""

    PRIOR_INITIAL_WEIGHT: float = 0.3
    PRIOR_DECAY_STEPS: float = 50.0
    EXPLORATION_DECAY_STEPS: float = 60.0
    DIVERSITY_WEIGHT: float = 0.15
    RECENCY_WEIGHT: float = 0.10
    KNOWLEDGE_WEIGHT: float = 1.0
    DIVERSITY_SIMILARITY_THRESHOLD: float = 0.7
    WILSON_CONFIDENCE_Z: float = 1.96
    FOCUS_BONUS: float = 0.15      # v14: 任务目标对齐 bonus

    def __init__(self):
        self.focus_vuln_types: list[str] = []  # v14
        self.nodes: dict[str, SearchNode] = {}
        self.root_id: str | None = None
        self.global_step: int = 0
        self.findings: list[dict] = []
        self.recent_selections: list[str] = []
        self.graveyard: dict[str, SearchNode] = {}
        self.total_expected_steps: int = 200

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

    # ──── v2: 自适应选择 ────

    def _exploitation_weight(self, s: int) -> float:
        return 1.0 - 0.6 * math.exp(-s / 80.0)

    def _exploration_weight(self, s: int) -> float:
        return 0.2 + 0.8 * math.exp(-s / self.EXPLORATION_DECAY_STEPS)

    def _prior_weight(self, s: int) -> float:
        return self.PRIOR_INITIAL_WEIGHT * math.exp(-s / self.PRIOR_DECAY_STEPS)

    def _wilson_score_lower_bound(self, node: SearchNode) -> float:
        """Wilson 分数下界估计
        
        将节点的平均奖励映射到 [0, 1] 概率空间，计算置信下界。
        当平均奖励为负时，下界为 0（表示该节点不可靠）。
        """
        n = node.visit_count
        if n == 0:
            return 0.0
        
        # 计算平均奖励并映射到 [0, 1] 范围
        # 奖励范围通常是 [-0.5, 1.0]，需要线性映射
        avg_reward = node.total_reward / n
        # 使用 sigmoid 映射：将任意实数映射到 (0, 1)
        # 或者简单线性映射：假设奖励范围 [-0.5, 1.0] -> [0, 1]
        p = max(0.0, min(1.0, (avg_reward + 0.5) / 1.5))  # 线性映射 [-0.5, 1.0] -> [0, 1]
        
        z = self.WILSON_CONFIDENCE_Z
        z2 = z * z
        denominator = 1.0 + z2 / n
        mean = (p + z2 / (2.0 * n)) / denominator
        # p 已在 [0, 1] 范围内，p * (1 - p) >= 0，sqrt 不会报 domain error
        variance = p * (1.0 - p) / n + z2 / (4.0 * n * n)
        std = z * math.sqrt(max(0.0, variance)) / denominator  # max(0,...) 防御性保护
        return max(0.0, mean - std)

    def _node_similarity(self, a: SearchNode, b: SearchNode) -> float:
        score = 0.0
        if a.state.vuln_type == b.state.vuln_type:
            score += 0.3
        if a.state.current_endpoint == b.state.current_endpoint:
            score += 0.4
        if a.state.current_param == b.state.current_param:
            score += 0.3
        return min(1.0, score)

    def _diversity_score(self, node: SearchNode) -> float:
        if not self.recent_selections:
            return 1.0
        similarities = []
        for rid in self.recent_selections[-10:]:
            recent = self.nodes.get(rid)
            if recent is None:
                continue
            similarities.append(self._node_similarity(node, recent))
        if not similarities:
            return 1.0
        return 1.0 - sum(similarities) / len(similarities)

    def _recency_score(self, node: SearchNode) -> float:
        age = max(1, node.created_at_cycle)
        return math.exp(-age / 3.0)

    def _knowledge_score(self, node: SearchNode, knowledge: Any) -> float:
        score = 0.0
        try:
            if hasattr(knowledge, 'waf_profile') and knowledge.waf_profile:
                bypasses = knowledge.waf_profile.get("bypass_techniques", [])
                if bypasses:
                    score += 0.1
            if hasattr(knowledge, 'effective_params') and knowledge.effective_params:
                if node.state.current_param in knowledge.effective_params:
                    score += 0.05
        except Exception:
            pass
        return min(0.5, score)

    def _accessibility_score(self, node: SearchNode) -> float:
        """P1: 端点可访问性因子 — 403/404 端点直接归零"""
        metadata = node.endpoint_metadata or {}
        accessibility = metadata.get("accessibility", "unknown")
        weight_map = {
            "accessible": 1.0, "redirect": 0.7, "auth_required": 0.5,
            "server_error": 0.3, "unknown": 0.3,
            "forbidden": 0.0, "not_found": 0.0, "timeout": 0.0,
        }
        return weight_map.get(accessibility, 0.3)

    def _adaptive_selection_score(self, node: SearchNode, parent: SearchNode | None = None, knowledge: Any = None) -> float:
        s = self.global_step
        parent_visits = parent.visit_count if parent else max(1, node.visit_count)
        alpha_val = self._exploitation_weight(s)
        exploitation = self._wilson_score_lower_bound(node)
        beta_val = self._exploration_weight(s)
        if node.visit_count > 0:
            exploration_c = 2.0 * math.exp(-s / self.total_expected_steps)
            exploration = exploration_c * math.sqrt(math.log(max(1, parent_visits)) / node.visit_count)
        else:
            exploration = float('inf')
        gamma_val = self._prior_weight(s)
        prior = node.value_estimate
        diversity = self._diversity_score(node)
        recency = self._recency_score(node)
        knowledge_score = self._knowledge_score(node, knowledge) if knowledge else 0.0
        # P1: 端点可访问性乘数
        accessibility = self._accessibility_score(node)
        # v14: 任务目标对齐 — focus bonus
        focus_bonus = self.FOCUS_BONUS if (self.focus_vuln_types and node.state.vuln_type in self.focus_vuln_types) else 0.0
        # v17: vuln_type 失败惩罚
        vuln_penalty = 0.0
        if knowledge and hasattr(knowledge, 'get_vuln_type_penalty'):
            vuln_penalty = knowledge.get_vuln_type_penalty(node.state.vuln_type)
        if node.visit_count == 0:
            return (alpha_val * exploitation + gamma_val * prior + self.DIVERSITY_WEIGHT * diversity + self.RECENCY_WEIGHT * recency + self.KNOWLEDGE_WEIGHT * knowledge_score + focus_bonus - vuln_penalty) * accessibility
        freshness = 1.0 / (1.0 + 0.01 * (s - node.last_visit_step))
        return (alpha_val * exploitation + beta_val * exploration + gamma_val * prior + self.DIVERSITY_WEIGHT * diversity + self.RECENCY_WEIGHT * recency + self.KNOWLEDGE_WEIGHT * knowledge_score + focus_bonus - vuln_penalty) * freshness * accessibility

    def _is_too_similar(self, node: SearchNode, selected: list[SearchNode]) -> bool:
        for sel in selected:
            if self._node_similarity(node, sel) > self.DIVERSITY_SIMILARITY_THRESHOLD:
                return True
        return False

    def _record_selections(self, selected: list[SearchNode]) -> None:
        for n in selected:
            self.recent_selections.append(n.id)
        if len(self.recent_selections) > 30:
            self.recent_selections = self.recent_selections[-30:]

    def _collect_candidates(self) -> list[SearchNode]:
        candidates = []
        for node in self.nodes.values():
            # v5: 根节点不应被选中执行
            if node.id == self.root_id:
                continue
            if node.status in (NodeStatus.SEED, NodeStatus.PROMOTED, NodeStatus.HIGH_SIGNAL, NodeStatus.UNEXPLORED, NodeStatus.NEEDS_EXPANSION, NodeStatus.LOW_SIGNAL):
                candidates.append(node)
        return candidates

    def select_batch(self, batch_size: int = 4, exploration_weight: float = 1.414, current_cycle: int = 0, cold_start_until_cycle: int = 1, knowledge: Any = None) -> list[SearchNode]:
        candidates = self._collect_candidates()
        if not candidates:
            return []
        # v5: Cold start with endpoint diversity
        if current_cycle <= cold_start_until_cycle:
            candidates.sort(key=lambda n: n.value_estimate, reverse=True)
            selected = []
            seen_eps = set()
            for n in candidates:
                if len(selected) >= batch_size:
                    break
                # v5: 冷启动多样性 — 跳过与已选节点 endpoint 前缀重叠的
                ep_prefix = n.state.current_endpoint.rsplit("/", 1)[0] if n.state.current_endpoint else ""
                if ep_prefix and ep_prefix in seen_eps:
                    continue
                selected.append(n)
                if ep_prefix:
                    seen_eps.add(ep_prefix)
            if not selected:
                selected = [n for n in candidates if n.status == NodeStatus.SEED][:batch_size]
            # v20-fix: 如果多样性过滤后只选出了1个但有多个候选(vuln_type不同), 回退到按vuln_type多样性选取
            if len(selected) == 1 and len(candidates) > 1:
                remaining = [n for n in candidates if n not in selected]
                remaining.sort(key=lambda n: n.value_estimate, reverse=True)
                seen_types = {selected[0].state.vuln_type}
                for n in remaining:
                    if len(selected) >= batch_size:
                        break
                    if n.state.vuln_type not in seen_types:
                        selected.append(n)
                        seen_types.add(n.state.vuln_type)
            if selected:
                self._record_selections(selected)
                return selected
        # Normal: adaptive scoring + diversity filter (P1-1: 传入 knowledge 参数)
        scored = [(n, self._adaptive_selection_score(n, self.nodes.get(n.parent_id) if n.parent_id else n, knowledge)) for n in candidates]
        scored.sort(key=lambda x: x[1], reverse=True)
        selected = []
        for node, score in scored:
            if len(selected) >= batch_size:
                break
            if self._is_too_similar(node, selected):
                continue
            selected.append(node)
        self._record_selections(selected)
        return selected

    def select_best_leaf(self, exploration_weight: float = 1.414) -> SearchNode | None:
        root = self.get_root()
        if root is None:
            return None
        current = root
        while current.children:
            unexplored = [self.nodes[cid] for cid in current.children if self.nodes[cid].status in (NodeStatus.UNEXPLORED, NodeStatus.NEEDS_EXPANSION, NodeStatus.SEED, NodeStatus.PROMOTED, NodeStatus.HIGH_SIGNAL, NodeStatus.LOW_SIGNAL)]
            if unexplored:
                return max(unexplored, key=lambda n: self._adaptive_selection_score(n, current))
            explorable = [self.nodes[cid] for cid in current.children if self.nodes[cid].status not in (NodeStatus.EXHAUSTED, NodeStatus.PRUNED, NodeStatus.CONFIRMED_VULN, NodeStatus.KILLED)]
            if not explorable:
                return None
            current = max(explorable, key=lambda n: self._adaptive_selection_score(n, current))
        if current.status in (NodeStatus.EXHAUSTED, NodeStatus.PRUNED, NodeStatus.KILLED):
            return None
        return current

    def _ucb_score(self, node: SearchNode, parent: SearchNode, C: float) -> float:
        return self._adaptive_selection_score(node, parent)

    # ──── Backpropagate ────

    def backpropagate(self, node_id: str, reward: float) -> None:
        self.global_step += 1
        current = self.nodes.get(node_id)
        decay = 1.0
        while current:
            current.visit_count += 1
            current.total_reward += reward * decay
            current.last_visit_step = self.global_step
            if current.visit_count > 0:
                current.empirical_value = current.total_reward / current.visit_count
            # v2: 每次访问衰减 value_estimate, 低于阈值标记 exhausted
            current.value_decay_factor *= 0.85
            if current.value_decay_factor < 0.1 and current.status not in (
                NodeStatus.CONFIRMED_VULN, NodeStatus.EXHAUSTED, NodeStatus.PRUNED, NodeStatus.KILLED,
            ):
                current.status = NodeStatus.EXHAUSTED
            decay *= 0.85
            current = self.nodes.get(current.parent_id) if current.parent_id else None

    # ──── Pruning + Graveyard ────

    def should_prune(self, node: SearchNode, budget_ratio: float = 1.0) -> bool:
        # L3-fix: 根节点永不被剪 — 旧实现 root 在子节点全 killed 时也会被
        # 标 PRUNED, 导致 all_explored() 第 1 个 dry cycle 即 true, 任务直接
        # 转报告, max_cycles 预算只用 1 轮。
        if node.id == self.root_id:
            return False
        if node.visit_count >= 5 and node.total_reward <= 0:
            return True
        if node.depth >= 15:
            return True
        if node.children and all(self.nodes[cid].status in (NodeStatus.EXHAUSTED, NodeStatus.PRUNED, NodeStatus.KILLED) for cid in node.children):
            return True
        if budget_ratio < 0.3 and node.value_estimate < 0.3:
            return True
        return False

    def prune_node(self, node_id: str) -> None:
        # L3-fix: 根节点不可剪
        if node_id == self.root_id:
            return
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.PRUNED

    def kill_node(self, node_id: str, reason: str = "") -> None:
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.KILLED
            node.observation_summary = f"KILLED: {reason}" if reason else "KILLED"
            self.graveyard[node_id] = node

    def resurrect_from_graveyard(self, knowledge_changes: list[str]) -> list[SearchNode]:
        resurrected = []
        for node_id, node in list(self.graveyard.items()):
            reason = (node.observation_summary or "").lower()
            should_resurrect = False
            if "waf" in reason and "bypass_technique" in knowledge_changes:
                should_resurrect = True
            if "auth" in reason and "auth_context" in knowledge_changes:
                should_resurrect = True
            if ("filtered" in reason or "blocked" in reason) and "bypass_technique" in knowledge_changes:
                should_resurrect = True
            if "404" in reason and "new_endpoint" in knowledge_changes:
                should_resurrect = True
            if should_resurrect:
                node.status = NodeStatus.SEED
                node.probe_level = 0
                node.probe_results = []
                node.created_at_cycle = max(1, self.global_step // 4)
                del self.graveyard[node_id]
                resurrected.append(node)
        return resurrected

    def get_graveyard_stats(self) -> dict:
        return {"total_killed": len(self.graveyard), "killed_reasons": {rid: node.observation_summary for rid, node in list(self.graveyard.items())[:10]}}

    # ──── Backtrack + Helpers ────

    def backtrack(self, from_node_id: str) -> SearchNode | None:
        current = self.nodes.get(from_node_id)
        if current is None:
            return None
        current.status = NodeStatus.EXHAUSTED
        while current.parent_id:
            parent = self.nodes[current.parent_id]
            unexplored_siblings = [self.nodes[cid] for cid in parent.children if self.nodes[cid].status in (NodeStatus.UNEXPLORED, NodeStatus.NEEDS_EXPANSION, NodeStatus.SEED, NodeStatus.PROMOTED, NodeStatus.HIGH_SIGNAL)]
            if unexplored_siblings:
                return max(unexplored_siblings, key=lambda n: self._adaptive_selection_score(n, parent))
            parent.status = NodeStatus.EXHAUSTED
            current = parent
        return None

    def mark_exhausted(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.EXHAUSTED

    def mark_confirmed(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.CONFIRMED_VULN

    def mark_killed(self, node_id: str, reason: str = "") -> None:
        self.kill_node(node_id, reason)

    def mark_promoted(self, node_id: str, cycle: int = 0) -> None:
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.PROMOTED
            node.probe_level = 1
            node.promoted_at_cycle = cycle

    def mark_high_signal(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node:
            node.status = NodeStatus.HIGH_SIGNAL
            node.probe_level = 2

    def record_finding(self, finding: dict) -> None:
        self.findings.append(finding)

    def all_explored(self) -> bool:
        root = self.get_root()
        if root is None:
            return True
        active = (NodeStatus.UNEXPLORED, NodeStatus.NEEDS_EXPANSION, NodeStatus.EXPLORING, NodeStatus.SEED, NodeStatus.PROBING, NodeStatus.PROMOTED, NodeStatus.HIGH_SIGNAL, NodeStatus.LOW_SIGNAL)
        for node in self.nodes.values():
            if node.status in active:
                return False
        return True

    def max_unexplored_value(self) -> float:
        max_val = 0.0
        for node in self.nodes.values():
            if node.status in (NodeStatus.UNEXPLORED, NodeStatus.NEEDS_EXPANSION, NodeStatus.SEED, NodeStatus.PROMOTED, NodeStatus.HIGH_SIGNAL, NodeStatus.LOW_SIGNAL):
                val = node.empirical_value if node.empirical_value > 0 else node.value_estimate
                max_val = max(max_val, val)
        return max_val

    def get_unexplored_children(self, node: SearchNode) -> list[SearchNode]:
        active = (NodeStatus.UNEXPLORED, NodeStatus.SEED, NodeStatus.PROMOTED, NodeStatus.HIGH_SIGNAL, NodeStatus.LOW_SIGNAL)
        return [self.nodes[cid] for cid in node.children if self.nodes[cid].status in active]

    def stats(self) -> dict:
        total = len(self.nodes)
        explored = sum(1 for n in self.nodes.values() if n.visit_count > 0)
        pruned = sum(1 for n in self.nodes.values() if n.status == NodeStatus.PRUNED)
        killed = sum(1 for n in self.nodes.values() if n.status == NodeStatus.KILLED)
        confirmed = sum(1 for n in self.nodes.values() if n.status == NodeStatus.CONFIRMED_VULN)
        seeds = sum(1 for n in self.nodes.values() if n.status == NodeStatus.SEED)
        promoted = sum(1 for n in self.nodes.values() if n.status == NodeStatus.PROMOTED)
        high_signal = sum(1 for n in self.nodes.values() if n.status == NodeStatus.HIGH_SIGNAL)
        return {
            "total_nodes": total, "explored": explored, "pruned": pruned, "killed": killed,
            "graveyard_size": len(self.graveyard), "confirmed_vulns": confirmed,
            "seeds": seeds, "promoted": promoted, "high_signal": high_signal,
            "findings": len(self.findings), "global_step": self.global_step,
            "prior_weight": round(self._prior_weight(self.global_step), 4),
            "exploration_weight": round(self._exploration_weight(self.global_step), 4),
        }

    def create_child_node(self, parent: SearchNode, action: str, action_params: dict, vuln_type: str | None = None, endpoint: str | None = None, param: str | None = None, value_estimate: float = 0.5, created_at_cycle: int = 0) -> SearchNode:
        child_state = parent.state.copy()
        if vuln_type:
            child_state.vuln_type = vuln_type
        if endpoint:
            child_state.current_endpoint = endpoint
        if param:
            child_state.current_param = param
        ep_hash = hashlib.md5((endpoint or child_state.current_endpoint).encode()).hexdigest()[:8] if (endpoint or child_state.current_endpoint) else "unknown"
        child = SearchNode(id=str(uuid.uuid4()), parent_id=parent.id, depth=parent.depth + 1, state=child_state, action_taken=action, action_params=action_params, value_estimate=value_estimate, created_at_cycle=created_at_cycle, diversity_tags=[vuln_type or child_state.vuln_type or "unknown", ep_hash, (param or child_state.current_param or "no_param")])
        self.add_child(parent, child)
        return child
