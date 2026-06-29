"""
节点复活引擎 (v3)

解决搜索树中"正确参数在错误节点被耗尽后永不复活"的问题。

核心场景 (来自 c30cb533 实际案例):
- Graveyard 中有: vuln_type=rce, param=cmd, endpoint=rce_ping.php, status=exhausted
- SharedKnowledge 新发现: param=ipaddress 来自表单解析
- 复活: 创建 vuln_type=rce, param=ipaddress, endpoint=rce_ping.php 新节点
- 原 exhausted 节点标记为 KILLED_WRONG_PARAM 不再尝试复活

触发时机:
- Expand 阶段: ExpansionEngine 输出新发现后立即检查 Graveyard
- SharedKnowledge 更新后: 新端点/参数/WAF绕过信号进入知识库后触发
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from .search_tree import NodeStatus, SearchNode, SearchTree

logger = logging.getLogger(__name__)


@dataclass
class ResurrectionCandidate:
    """复活候选项"""
    dead_node: SearchNode
    new_param: str | None = None
    new_endpoint: str | None = None
    new_vuln_type: str | None = None
    reason: str = ""
    confidence: float = 0.0


class NodeResurrectionEngine:
    """
    节点复活引擎

    当 SharedKnowledge 出现新信息时，检查 Graveyard 中被错误KILL/EXHAUSTED
    的节点是否可以复活。复活不是原节点恢复，而是创建新子节点挂回原父节点。

    复活规则优先级:
    1. 同 endpoint + 同 vuln_type → 新参数被发现 → 复活(更换参数)     [最高置信]
    2. 同 endpoint + 同参数 → 新 vuln_type 信号 → 复活(追加类型)     [高置信]
    3. 同 endpoint → 技术栈/WAF绕过被发现 → 复活(附带绕过)           [中置信]
    4. 同 vuln_type → 新 endpoint 有相似特征 → 复活(跨端点)          [低置信]
    """

    # 可以被复活的死因状态
    RESURRECTABLE_STATUSES: set[NodeStatus] = {
        NodeStatus.EXHAUSTED,
        NodeStatus.KILLED,
        NodeStatus.PRUNED,
    }

    # 不可复活的死因关键词
    NON_RESURRECTABLE_REASONS: set[str] = {
        "endpoint_404",
        "permanently_patched",
        "out_of_scope",
        "killed_wrong_param",  # 已经复活过一次的错误参数节点
    }

    def __init__(self, max_resurrections_per_cycle: int = 3):
        self._max_per_cycle = max_resurrections_per_cycle
        self._resurrection_history: dict[str, int] = {}  # node_id → resurrection count

    def check_resurrection(
        self,
        tree: SearchTree,
        new_discoveries: list[Any],
        shared_knowledge: Any = None,
        current_cycle: int = 0,
    ) -> list[SearchNode]:
        """
        检查 Graveyard 节点是否可以复活。

        Args:
            tree: 搜索树(含 graveyard)
            new_discoveries: 本轮 ExpansionEngine 输出的发现列表
            shared_knowledge: SharedKnowledge 实例
            current_cycle: 当前周期

        Returns:
            复活创建的新节点列表(已添加到树中)
        """
        if not tree.graveyard:
            return []

        candidates = self._find_candidates(
            tree, new_discoveries, shared_knowledge
        )
        if not candidates:
            return []

        # 按置信度排序, 最多复活 max_per_cycle 个
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        resurrected = []

        for candidate in candidates[:self._max_per_cycle]:
            new_node = self._execute_resurrection(tree, candidate, current_cycle)
            if new_node:
                resurrected.append(new_node)
                # 标记原节点为"已复活过"防止重复
                candidate.dead_node.observation_summary = (
                    f"{candidate.dead_node.observation_summary} "
                    f"[RESURRECTED→{candidate.new_vuln_type or 'new_param'}:"
                    f"{candidate.new_param or ''}]"
                )

        if resurrected:
            logger.info(
                "节点复活: %d 个节点从 Graveyard 复活 (总Graveyard: %d)",
                len(resurrected), len(tree.graveyard),
            )

        return resurrected

    def _find_candidates(
        self,
        tree: SearchTree,
        new_discoveries: list[Any],
        shared_knowledge: Any = None,
    ) -> list[ResurrectionCandidate]:
        """扫描 Graveyard 找到复活候选"""
        candidates: list[ResurrectionCandidate] = []

        # 提取本轮新发现的参数和端点
        new_params_by_endpoint: dict[str, list[str]] = {}
        new_endpoints: set[str] = set()

        for disc in new_discoveries:
            if hasattr(disc, 'discovery_type') and hasattr(disc, 'data'):
                disc_type = str(disc.discovery_type)
                disc_data = disc.data if isinstance(disc.data, dict) else {}
            elif hasattr(disc, 'type') and hasattr(disc, 'data'):
                disc_type = str(disc.type)
                disc_data = disc.data if isinstance(disc.data, dict) else {}
            elif isinstance(disc, dict):
                disc_type = disc.get("type", "")
                disc_data = disc.get("data", {})
            else:
                continue

            endpoint = disc_data.get("endpoint", "") or disc_data.get("url", "")
            param = disc_data.get("param", "") or disc_data.get("param_name", "")

            if endpoint:
                new_endpoints.add(endpoint)
            if endpoint and param:
                if endpoint not in new_params_by_endpoint:
                    new_params_by_endpoint[endpoint] = []
                if param not in new_params_by_endpoint[endpoint]:
                    new_params_by_endpoint[endpoint].append(param)

        # 从 SharedKnowledge 补充已知参数
        if shared_knowledge and hasattr(shared_knowledge, 'endpoints'):
            for ep_key, ep_info in shared_knowledge.endpoints.items():
                if hasattr(ep_info, 'params') and ep_info.params:
                    ep_url = getattr(ep_info, 'path', ep_key)
                    if ep_url not in new_params_by_endpoint:
                        new_params_by_endpoint[ep_url] = []
                    for p in ep_info.params:
                        if isinstance(p, str) and p not in new_params_by_endpoint[ep_url]:
                            new_params_by_endpoint[ep_url].append(p)

        # 遍历 Graveyard
        for node_id, dead_node in list(tree.graveyard.items()):
            # 跳过不可复活状态
            if dead_node.status not in self.RESURRECTABLE_STATUSES:
                continue

            # 跳过已复活过的
            if "[RESURRECTED→" in (dead_node.observation_summary or ""):
                continue

            # 跳过明确不可复活的
            for keyword in self.NON_RESURRECTABLE_REASONS:
                if keyword in (dead_node.observation_summary or "").lower():
                    continue

            dead_endpoint = dead_node.state.current_endpoint or ""
            dead_vuln = dead_node.state.vuln_type or ""
            dead_param = dead_node.state.current_param or ""

            # 规则1: 同endpoint + 同vuln_type → 新参数
            if dead_endpoint and dead_vuln:
                params = new_params_by_endpoint.get(dead_endpoint, [])
                for new_param in params:
                    if new_param and new_param != dead_param:
                        # 使用快速分类检查新参数是否匹配该漏洞类型
                        vt_match = self._quick_param_vuln_match(new_param, dead_vuln)
                        if vt_match > 0.5:
                            candidates.append(ResurrectionCandidate(
                                dead_node=dead_node,
                                new_param=new_param,
                                new_vuln_type=dead_vuln,
                                reason=f"端点 {dead_endpoint} 发现新参数 {new_param} 匹配 {dead_vuln}",
                                confidence=vt_match,
                            ))

            # 规则2: 同endpoint + 同参数 → 新漏洞类型信号
            if dead_endpoint and dead_param:
                for ep_key, ep_info in (shared_knowledge.endpoints if shared_knowledge and hasattr(shared_knowledge, 'endpoints') else {}).items():
                    ep_url = getattr(ep_info, 'path', ep_key) if hasattr(ep_info, 'path') else ep_key
                    if ep_url != dead_endpoint:
                        continue
                    if hasattr(ep_info, 'vuln_signals') and ep_info.vuln_signals:
                        for vt, signal in ep_info.vuln_signals.items():
                            if vt != dead_vuln and isinstance(signal, dict):
                                conf = signal.get("confidence", 0)
                                if conf > 0.5:
                                    candidates.append(ResurrectionCandidate(
                                        dead_node=dead_node,
                                        new_param=dead_param,
                                        new_vuln_type=vt,
                                        reason=f"SharedKnowledge 新信号: {vt} @ {dead_endpoint}",
                                        confidence=conf,
                                    ))

            # 规则3: 同endpoint → 新WAF绕过/技术栈
            if dead_endpoint and shared_knowledge:
                if hasattr(shared_knowledge, 'waf_profile') and shared_knowledge.waf_profile:
                    bypasses = shared_knowledge.waf_profile.get("bypass_techniques", [])
                    if bypasses and "waf" in (dead_node.observation_summary or "").lower():
                        candidates.append(ResurrectionCandidate(
                            dead_node=dead_node,
                            new_param=dead_param,
                            new_vuln_type=dead_vuln,
                            reason=f"WAF绕过技术发现: {bypasses[:2]}",
                            confidence=0.7,
                        ))

        return candidates

    def _quick_param_vuln_match(self, param_name: str, vuln_type: str) -> float:
        """
        快速参数名→漏洞类型匹配(Phase 1 简化版, Phase 3 替换为完整的
        ContextAwareVulnClassifier)。

        这是一个内联的轻量级匹配表, 避免 Phase 1 就引入完整分类器依赖。
        """
        param_lower = param_name.lower().strip()

        # 强信号映射: 参数名→漏洞类型→置信度
        SIGNAL_MAP: dict[str, dict[str, float]] = {
            "ipaddress": {"rce": 0.9, "ssrf": 0.8, "command_injection": 0.7},
            "ip": {"rce": 0.8, "ssrf": 0.9},
            "host": {"rce": 0.7, "ssrf": 0.8},
            "target": {"rce": 0.6, "ssrf": 0.7},
            "cmd": {"rce": 0.95},
            "command": {"rce": 0.95},
            "exec": {"rce": 0.9},
            "code": {"rce": 0.5, "ssti": 0.7},
            "file": {"lfi": 0.9, "path_traversal": 0.9, "file_upload": 0.8},
            "filename": {"lfi": 0.8, "path_traversal": 0.8},
            "path": {"lfi": 0.8, "path_traversal": 0.9},
            "url": {"ssrf": 0.9, "open_redirect": 0.8},
            "link": {"ssrf": 0.7, "open_redirect": 0.8},
            "redirect": {"open_redirect": 0.9},
            "next": {"open_redirect": 0.8},
            "id": {"idor": 0.7, "sql_injection": 0.6},
            "uid": {"idor": 0.8},
            "user_id": {"idor": 0.8},
            "username": {"auth_bypass": 0.6, "sql_injection": 0.5},
            "password": {"auth_bypass": 0.7},
            "q": {"xss": 0.7, "sql_injection": 0.6},
            "query": {"xss": 0.6, "sql_injection": 0.7},
            "search": {"xss": 0.8, "sql_injection": 0.7},
            "keyword": {"xss": 0.7, "sql_injection": 0.6},
            "name": {"xss": 0.6, "sql_injection": 0.5},
            "page": {"lfi": 0.7, "path_traversal": 0.7},
        }

        if param_lower in SIGNAL_MAP:
            return SIGNAL_MAP[param_lower].get(vuln_type, 0.0)

        # 模糊匹配: 参数名包含已知关键词
        for known_param, type_scores in SIGNAL_MAP.items():
            if known_param in param_lower or param_lower in known_param:
                return type_scores.get(vuln_type, 0.0) * 0.7  # 降权

        return 0.0

    def _execute_resurrection(
        self,
        tree: SearchTree,
        candidate: ResurrectionCandidate,
        current_cycle: int,
    ) -> SearchNode | None:
        """
        执行复活: 在原父节点下创建新子节点。
        """
        dead_node = candidate.dead_node
        parent = tree.nodes.get(dead_node.parent_id) if dead_node.parent_id else None

        if parent is None:
            # 父节点不存在(可能已被清理) → 挂到 root
            parent = tree.get_root()
            if parent is None:
                return None

        # 创建复活节点
        from .search_tree import NodeState
        import uuid

        child_state = dead_node.state.copy()
        child_state.vuln_type = candidate.new_vuln_type or dead_node.state.vuln_type
        child_state.current_param = candidate.new_param or dead_node.state.current_param
        if candidate.new_endpoint:
            child_state.current_endpoint = candidate.new_endpoint

        new_node = SearchNode(
            id=str(uuid.uuid4()),
            parent_id=parent.id,
            depth=parent.depth + 1,
            state=child_state,
            status=NodeStatus.SEED,
            value_estimate=candidate.confidence * 0.7,  # 分类器得分→先验价值
            created_at_cycle=current_cycle,
            diversity_tags=[
                child_state.vuln_type or "unknown",
                (child_state.current_endpoint or "")[:8],
                child_state.current_param or "no_param",
                "resurrected",
            ],
        )

        tree.add_child(parent, new_node)

        # 记录复活历史
        self._resurrection_history[dead_node.id] = (
            self._resurrection_history.get(dead_node.id, 0) + 1
        )

        logger.info(
            "节点复活成功: %s (原节点: %s, 原因: %s, 置信度: %.2f)",
            new_node.id[:8],
            dead_node.id[:8],
            candidate.reason,
            candidate.confidence,
        )

        return new_node
