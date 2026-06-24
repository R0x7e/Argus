"""
用户干预处理器

处理前端通过 WebSocket 下行的用户干预指令:
- create_branch: 创建自定义搜索分支
- mark_false_positive: 标记误报
- inject_payload: 注入自定义 payload
- steer_direction: 搜索方向引导
- promote_node / kill_node: 节点优先级调整
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class UserActionHandler:
    """处理前端下行用户干预指令"""

    def __init__(self):
        self._action_log: list[dict] = []

    async def handle(
        self,
        action: str,
        params: dict,
        state: dict,
    ) -> dict:
        """
        处理用户干预指令

        Args:
            action: 指令类型
            params: 指令参数
            state: 当前 LATSState

        Returns:
            {"status": "applied"|"rejected", "reason": "...", "data": {...}}
        """
        handler_map = {
            "create_branch": self._handle_create_branch,
            "mark_false_positive": self._handle_mark_false_positive,
            "inject_payload": self._handle_inject_payload,
            "steer_direction": self._handle_steer_direction,
            "promote_node": self._handle_promote_node,
            "kill_node": self._handle_kill_node,
            "add_custom_payload": self._handle_add_custom_payload,
        }

        handler = handler_map.get(action)
        if handler is None:
            return {"status": "rejected", "reason": f"Unknown action: {action}"}

        try:
            result = await handler(params, state)
            self._action_log.append({
                "action": action, "params": params, "result": result.get("status"),
            })
            return result
        except Exception as e:
            logger.error("UserActionHandler 异常 [%s]: %s", action, str(e))
            return {"status": "rejected", "reason": str(e)}

    async def _handle_create_branch(self, params: dict, state: dict) -> dict:
        """创建自定义搜索分支"""
        tree = state.get("search_tree")
        if tree is None:
            return {"status": "rejected", "reason": "搜索树未初始化"}

        from app.agents.lats.search_tree import NodeStatus, SearchNode, NodeState
        import uuid

        endpoint = params.get("endpoint", "")
        param = params.get("param") or None
        vuln_type = params.get("vuln_type", "xss")
        payload = params.get("payload", "")
        reason = params.get("reason", "用户手动创建")

        if not endpoint:
            return {"status": "rejected", "reason": "endpoint 不能为空"}

        root = tree.get_root()
        if root is None:
            return {"status": "rejected", "reason": "根节点不存在"}

        from app.agents.lats.reward import estimate_branch_value
        bb = state.get("blackboard")
        tech_stack = bb.target_profile.get("tech_stack", []) if bb and bb.target_profile else []

        value = estimate_branch_value(vuln_type, param or "", endpoint, tech_stack, "manual")
        child = tree.create_child_node(
            parent=root,
            action="explore_manual",
            action_params={
                "endpoint": endpoint, "param": param, "vuln_type": vuln_type,
                "payload": payload, "reason": reason,
            },
            vuln_type=vuln_type, endpoint=endpoint, param=param,
            value_estimate=max(0.5, value),
            created_at_cycle=state.get("current_cycle", 0),
        )
        child.status = NodeStatus.HIGH_SIGNAL  # 人工创建的节点直接进入 HIGH_SIGNAL
        child.observation_summary = f"用户手动创建: {reason}"

        logger.info("用户创建分支: %s @ %s (%s)", vuln_type, endpoint, param)
        return {
            "status": "applied",
            "data": {"node_id": child.id, "vuln_type": vuln_type, "endpoint": endpoint},
        }

    async def _handle_mark_false_positive(self, params: dict, state: dict) -> dict:
        """标记误报"""
        bb = state.get("blackboard")
        if bb is None:
            return {"status": "rejected", "reason": "黑板未初始化"}

        finding_id = params.get("finding_id", "")
        reason = params.get("reason", "用户标记为误报")

        # 在 findings 中查找并移除
        matching = [f for f in bb.findings if getattr(f, "id", "") == finding_id]
        if not matching:
            return {"status": "rejected", "reason": f"未找到 finding: {finding_id}"}

        finding = matching[0]
        bb.findings.remove(finding)
        bb.false_positives.append({
            "finding_id": finding_id,
            "type": getattr(finding, "type", "unknown"),
            "title": getattr(finding, "title", ""),
            "reason": reason,
        })

        logger.info("用户标记误报: %s - %s", finding_id, reason)
        return {"status": "applied", "data": {"finding_id": finding_id}}

    async def _handle_inject_payload(self, params: dict, state: dict) -> dict:
        """注入自定义 payload"""
        tree = state.get("search_tree")
        if tree is None:
            return {"status": "rejected", "reason": "搜索树未初始化"}

        node_id = params.get("node_id", "")
        payload = params.get("payload", "")

        if not node_id or not payload:
            return {"status": "rejected", "reason": "node_id 和 payload 不能为空"}

        node = tree.get_node(node_id)
        if node is None:
            return {"status": "rejected", "reason": f"节点不存在: {node_id}"}

        # 将 payload 追加到节点的 action_params 中
        if not hasattr(node, 'user_payloads'):
            node.user_payloads = []
        node.user_payloads.append(payload)

        logger.info("用户注入 payload: node=%s, payload=%s", node_id[:8], payload[:80])
        return {"status": "applied", "data": {"node_id": node_id, "payload": payload}}

    async def _handle_steer_direction(self, params: dict, state: dict) -> dict:
        """搜索方向引导"""
        bb = state.get("blackboard")
        if bb is None:
            return {"status": "rejected", "reason": "黑板未初始化"}

        directive = params.get("directive", "")
        focus_types = params.get("focus_types", [])
        strategy = params.get("strategy", "")

        if directive:
            if not hasattr(bb, 'steering_directives') or bb.steering_directives is None:
                bb.steering_directives = []
            bb.steering_directives.append(directive)

        if focus_types:
            # 存储到 blackboard 供选择器使用
            if not hasattr(bb, 'focus_vuln_types'):
                bb.focus_vuln_types = []
            bb.focus_vuln_types = focus_types

        logger.info("用户引导搜索方向: directive=%s, focus=%s, strategy=%s",
                    directive[:80] if directive else "", focus_types, strategy)
        return {"status": "applied", "data": {"directive": directive, "focus_types": focus_types}}

    async def _handle_promote_node(self, params: dict, state: dict) -> dict:
        """提升节点优先级"""
        tree = state.get("search_tree")
        if tree is None:
            return {"status": "rejected", "reason": "搜索树未初始化"}

        node_id = params.get("node_id", "")
        node = tree.get_node(node_id) if node_id else None
        if node is None:
            return {"status": "rejected", "reason": f"节点不存在: {node_id}"}

        from app.agents.lats.search_tree import NodeStatus
        node.status = NodeStatus.HIGH_SIGNAL
        node.value_estimate = max(node.value_estimate, 0.7)
        node.empirical_value = max(node.empirical_value, 0.6)

        logger.info("用户提升节点: %s → HIGH_SIGNAL", node_id[:8])
        return {"status": "applied", "data": {"node_id": node_id}}

    async def _handle_kill_node(self, params: dict, state: dict) -> dict:
        """终止节点"""
        tree = state.get("search_tree")
        if tree is None:
            return {"status": "rejected", "reason": "搜索树未初始化"}

        node_id = params.get("node_id", "")
        reason = params.get("reason", "用户手动终止")

        tree.mark_killed(node_id, reason=f"user: {reason}")

        logger.info("用户终止节点: %s - %s", node_id[:8], reason)
        return {"status": "applied", "data": {"node_id": node_id}}

    async def _handle_add_custom_payload(self, params: dict, state: dict) -> dict:
        """添加自定义 payload 到全局库"""
        bb = state.get("blackboard")
        if bb is None:
            return {"status": "rejected", "reason": "黑板未初始化"}

        payload = params.get("payload", "")
        vuln_type = params.get("vuln_type", "sql_injection")
        technique = params.get("technique", "custom")

        if not payload:
            return {"status": "rejected", "reason": "payload 不能为空"}

        if not hasattr(bb, 'custom_payloads'):
            bb.custom_payloads = {}
        if vuln_type not in bb.custom_payloads:
            bb.custom_payloads[vuln_type] = []
        bb.custom_payloads[vuln_type].append({
            "payload": payload, "technique": technique, "source": "user",
        })

        logger.info("用户添加自定义 payload: [%s] %s", vuln_type, payload[:80])
        return {"status": "applied", "data": {"vuln_type": vuln_type, "payload": payload}}
