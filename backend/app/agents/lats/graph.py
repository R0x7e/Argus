"""
LATS LangGraph 图构建

构建 LATS + ReAct 混合架构的状态图：
Recon → Init Tree → [MCTS Select → Expand → React Execute → Backprop → Evaluate] (循环) → Reporter

替换原有的固定管线循环，实现真正的搜索驱动漏洞挖掘。
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, TypedDict
from urllib.parse import urlparse

import operator
from langgraph.graph import END, StateGraph

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.agents.lats.react_executor import ReactExecutorPool, ReactResult
from app.agents.lats.reward import compute_reward, estimate_branch_value, infer_vuln_types
from app.agents.lats.search_tree import NodeState, NodeStatus, SearchNode, SearchTree
from app.agents.state import Blackboard, VulnFinding
from app.tools.base import ExecutionContext

logger = logging.getLogger(__name__)

_llm_client: LLMClient | None = None
_executor_pool: ReactExecutorPool | None = None


def _get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def _get_executor_pool() -> ReactExecutorPool:
    global _executor_pool
    if _executor_pool is None:
        _executor_pool = ReactExecutorPool(max_concurrent=4)
    return _executor_pool


# ──── LATS State Definition ────

class LATSState(TypedDict):
    """LATS 架构的状态定义（LangGraph TypedDict）"""
    blackboard: Blackboard
    search_tree: Any
    current_cycle: int
    max_cycles: int
    iteration_count: int
    task_id: str
    task_config: dict
    events: Annotated[list, operator.add]
    dry_cycles: int
    selected_nodes: list
    react_results: list


# ──── Node: Recon ────

async def lats_recon_node(state: dict) -> dict:
    """侦察节点 — 复用原有侦察逻辑"""
    from app.agents.nodes.orchestrator import _run_reconnaissance, _build_execution_context, _get_llm_client as _get_orch_llm
    from app.agents.prompts.orchestrator import ORCHESTRATOR_SYSTEM_PROMPT

    task_id = state["task_id"]
    task_config = state.get("task_config", {}) or {}
    target_url = task_config.get("target_url", "")
    bb = state["blackboard"]

    await emit(task_id, "lats_recon", "agent_started", {"node": "recon"})

    # 执行侦察
    recon_results = await _run_reconnaissance(state)

    await emit(task_id, "lats_recon", "recon_complete", {
        "dirs_found": len(recon_results.get("directories", [])),
        "pages_crawled": len(recon_results.get("crawled_pages", [])),
        "params_found": len(recon_results.get("parameters", [])),
        "forms_found": len(recon_results.get("forms", [])),
    })

    # LLM 分析生成画像
    llm = _get_llm_client()
    messages = [
        {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"SRC 漏洞挖掘任务。目标: {target_url}\n\n"
            f"侦察结果：\n"
            f"- 目录/路径: {json.dumps(recon_results['directories'][:30], ensure_ascii=False)}\n"
            f"- 页面链接: {json.dumps(recon_results['homepage_info'].get('links', [])[:40], ensure_ascii=False)}\n"
            f"- 响应头: {json.dumps(dict(list(recon_results['homepage_info'].get('headers', {}).items())[:15]), ensure_ascii=False)}\n"
            f"- 首页预览: {recon_results['homepage_info'].get('body_preview', '')[:1000]}\n"
            f"- 参数: {json.dumps(recon_results.get('parameters', [])[:30], ensure_ascii=False)}\n"
            f"- 表单: {json.dumps(recon_results.get('forms', [])[:15], ensure_ascii=False)}\n\n"
            f"输出 JSON: {{target_profile, attack_surface, strategy}}"
        )},
    ]

    response_text = await llm.call(agent="orchestrator", messages=messages)

    # 解析
    try:
        decision = json.loads(response_text)
    except json.JSONDecodeError:
        try:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            decision = json.loads(response_text[start:end]) if start >= 0 else {}
        except Exception:
            decision = {}

    # 构建 blackboard
    target_profile = decision.get("target_profile", {})
    target_profile["base_url"] = target_url
    bb.target_profile = target_profile

    attack_surface = decision.get("attack_surface", {})
    # 合并工具发现的端点
    tool_endpoints = [{"path": d, "source": "dir_scan"} for d in recon_results.get("directories", [])[:20]]
    param_endpoints = []
    for p in recon_results.get("parameters", [])[:30]:
        if isinstance(p, dict) and p.get("url"):
            param_endpoints.append({"path": p["url"], "params": [p.get("name", "")], "source": "crawl"})
        elif isinstance(p, str):
            param_endpoints.append({"path": p, "params": [], "source": "crawl"})
    form_endpoints = []
    for f in recon_results.get("forms", [])[:15]:
        if isinstance(f, dict) and f.get("action"):
            form_endpoints.append({"path": f["action"], "method": f.get("method", "POST"), "params": f.get("params", []), "source": "form"})
    attack_surface["endpoints"] = attack_surface.get("endpoints", []) + tool_endpoints + param_endpoints + form_endpoints
    attack_surface["parameters"] = recon_results.get("parameters", [])[:50]
    attack_surface["forms"] = recon_results.get("forms", [])[:20]
    bb.attack_surface = attack_surface

    await emit(task_id, "lats_recon", "agent_stopped", {"node": "recon"})

    return {
        "blackboard": bb,
        "events": [{
            "id": str(uuid.uuid4()),
            "agent": "lats_recon",
            "type": "recon_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"endpoints": len(attack_surface.get("endpoints", []))},
        }],
    }


# ──── Node: Init Tree ────

async def lats_init_tree_node(state: dict) -> dict:
    """初始化搜索树 — 将攻击面转换为初始分支"""
    bb = state["blackboard"]
    task_id = state["task_id"]
    attack_surface = bb.attack_surface or {}
    target_url = bb.target_profile.get("base_url", "")
    tech_stack = bb.target_profile.get("tech_stack", [])

    await emit(task_id, "lats_init", "agent_started", {"node": "init_tree"})

    tree = SearchTree()

    # 创建根节点
    root = SearchNode(
        id="root",
        parent_id=None,
        depth=0,
        state=NodeState(
            target_url=target_url,
            current_endpoint="/",
            current_param=None,
            vuln_type="",
        ),
        status=NodeStatus.NEEDS_EXPANSION,
    )
    tree.set_root(root)

    # 为每个 (端点, 参数, 漏洞类型) 组合创建分支
    branches_created = 0
    seen_branches = set()

    for endpoint in attack_surface.get("endpoints", []):
        # 兼容字符串格式的端点（LLM 可能返回纯路径字符串）
        if isinstance(endpoint, str):
            endpoint = {"path": endpoint, "params": [], "source": "llm"}
        path = endpoint.get("path", "")
        params = endpoint.get("params", [])
        source = endpoint.get("source", "")

        if not path:
            continue

        # 没有参数的端点 → 尝试 info_disclosure / auth_bypass
        if not params:
            for vtype in ["info_disclosure", "auth_bypass"]:
                branch_key = f"{vtype}@{path}"
                if branch_key in seen_branches:
                    continue
                seen_branches.add(branch_key)

                value = estimate_branch_value(vtype, "", path, tech_stack, source)
                tree.create_child_node(
                    parent=root,
                    action="explore",
                    action_params={"endpoint": path, "vuln_type": vtype},
                    vuln_type=vtype,
                    endpoint=path,
                    param=None,
                    value_estimate=value,
                )
                branches_created += 1

        # 有参数的端点 → 推断漏洞类型
        for param in params:
            param_name = param if isinstance(param, str) else param.get("name", "")
            vuln_types = infer_vuln_types(param_name, endpoint, tech_stack)

            for vtype in vuln_types:
                branch_key = f"{vtype}@{path}:{param_name}"
                if branch_key in seen_branches:
                    continue
                seen_branches.add(branch_key)

                value = estimate_branch_value(vtype, param_name, path, tech_stack, source)
                tree.create_child_node(
                    parent=root,
                    action="explore",
                    action_params={"endpoint": path, "param": param_name, "vuln_type": vtype},
                    vuln_type=vtype,
                    endpoint=path,
                    param=param_name,
                    value_estimate=value,
                )
                branches_created += 1

    # 限制初始分支数量（优先高价值分支）
    if branches_created > 60:
        children_nodes = [tree.get_node(cid) for cid in root.children]
        children_nodes.sort(key=lambda n: n.value_estimate, reverse=True)
        for node in children_nodes[60:]:
            tree.prune_node(node.id)

    await emit(task_id, "lats_init", "tree_initialized", {
        "branches": branches_created,
        "pruned_to": min(branches_created, 60),
    })

    await emit(task_id, "lats_init", "agent_stopped", {"node": "init_tree"})

    logger.info("搜索树初始化完成: %d 分支", branches_created)

    return {
        "search_tree": tree,
        "current_cycle": 0,
        "events": [{
            "id": str(uuid.uuid4()),
            "agent": "lats_init",
            "type": "tree_initialized",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"branches": branches_created},
        }],
    }


# ──── Node: MCTS Select ────

async def lats_mcts_select_node(state: dict) -> dict:
    """MCTS 选择 — 用 UCB1 选择最有价值的叶节点"""
    tree: SearchTree = state["search_tree"]
    task_id = state["task_id"]
    pool = _get_executor_pool()

    await emit(task_id, "lats_mcts", "agent_started", {"node": "mcts_select"})

    batch_size = pool.max_concurrent
    selected = tree.select_batch(batch_size)

    selected_info = [
        {"id": n.id[:8], "type": n.state.vuln_type, "endpoint": n.state.current_endpoint, "value": round(n.value_estimate, 2)}
        for n in selected
    ]

    await emit(task_id, "lats_mcts", "nodes_selected", {
        "count": len(selected),
        "nodes": selected_info,
        "selection_path": [n.id for n in selected],
    })

    await emit(task_id, "lats_mcts", "agent_stopped", {"node": "mcts_select"})

    return {
        "selected_nodes": [n.id for n in selected],
        "events": [{
            "id": str(uuid.uuid4()),
            "agent": "lats_mcts",
            "type": "nodes_selected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"count": len(selected), "nodes": selected_info},
        }],
    }


# ──── Node: React Execute ────

async def lats_react_execute_node(state: dict) -> dict:
    """ReAct 执行 — 并发运行 ReAct Agents 在选中的节点上"""
    tree: SearchTree = state["search_tree"]
    task_id = state["task_id"]
    bb = state["blackboard"]
    selected_ids = state.get("selected_nodes", [])

    await emit(task_id, "lats_react", "agent_started", {"node": "react_execute", "batch_size": len(selected_ids)})

    if not selected_ids:
        await emit(task_id, "lats_react", "agent_stopped", {"node": "react_execute"})
        return {"react_results": [], "events": []}

    # 构建执行上下文
    target_profile = bb.target_profile or {}
    base_url = target_profile.get("base_url", "")
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"

    context = ExecutionContext(
        task_id=task_id,
        target_host=host,
        timeout=30,
        max_retries=2,
        allowed_hosts=[host],
    )

    # 获取选中的节点
    nodes = [tree.get_node(nid) for nid in selected_ids if tree.get_node(nid)]
    nodes = [n for n in nodes if n and n.status != NodeStatus.EXHAUSTED]

    if not nodes:
        await emit(task_id, "lats_react", "agent_stopped", {"node": "react_execute"})
        return {"react_results": [], "events": []}

    # 动态决定每条路径的步数
    cycle = state.get("current_cycle", 0)
    max_cycles = state.get("max_cycles", 15)
    remaining_ratio = 1.0 - (cycle / max(1, max_cycles))

    if remaining_ratio > 0.7:
        max_steps = 10
    elif remaining_ratio > 0.4:
        max_steps = 7
    elif remaining_ratio > 0.2:
        max_steps = 5
    else:
        max_steps = 3

    # 并发执行
    pool = _get_executor_pool()
    llm = _get_llm_client()
    results = await pool.execute_batch(nodes, context, llm, max_steps)

    # 处理结果
    events = []
    findings_this_round = []

    for result in results:
        node = tree.get_node(result.node_id)
        if not node:
            continue

        # 反向传播奖励
        tree.backpropagate(result.node_id, result.reward)

        if result.status == "finding" and result.finding:
            # 确认漏洞
            tree.mark_confirmed(result.node_id)
            tree.record_finding(result.finding)

            finding = VulnFinding(
                id=str(uuid.uuid4()),
                hypothesis_id=result.node_id,
                type=result.finding.get("type", "unknown"),
                severity=result.finding.get("severity", "medium"),
                title=f"[{result.finding.get('severity', 'medium').upper()}] {result.finding.get('type', '')} - {node.state.current_endpoint}",
                description=result.finding.get("evidence", ""),
                trigger_path=[node.state.current_endpoint] + ([node.state.current_param] if node.state.current_param else []),
                payload=result.finding.get("payload", ""),
                reproduction_steps=[s.observation for s in result.steps if s.observation],
                evidence={"tool_verified": True, "steps": len(result.steps), "finding": result.finding},
                verified=True,
            )
            bb.findings.append(finding)
            findings_this_round.append(finding)

            await emit(task_id, "lats_react", "finding_confirmed", {
                "type": finding.type,
                "severity": finding.severity,
                "endpoint": node.state.current_endpoint,
                "param": node.state.current_param,
                "steps": len(result.steps),
            })

            events.append({
                "id": str(uuid.uuid4()),
                "agent": "lats_react",
                "type": "finding_confirmed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": {"type": finding.type, "severity": finding.severity},
            })

        elif result.status in ("exhausted", "backtrack"):
            tree.mark_exhausted(result.node_id)
            await emit(task_id, "lats_react", "path_exhausted", {
                "node": result.node_id[:8],
                "vuln_type": node.state.vuln_type,
                "endpoint": node.state.current_endpoint,
                "steps": len(result.steps),
                "reason": result.status,
            })

        elif result.status == "step_limit":
            # 步数耗尽但未确认 → 标记为需要扩展（下轮可能继续或放弃）
            if result.reward > 0.2:
                node.status = NodeStatus.NEEDS_EXPANSION
            else:
                tree.mark_exhausted(result.node_id)

    await emit(task_id, "lats_react", "agent_stopped", {
        "node": "react_execute",
        "findings": len(findings_this_round),
        "exhausted": sum(1 for r in results if r.status in ("exhausted", "backtrack")),
    })

    return {
        "blackboard": bb,
        "search_tree": tree,
        "react_results": results,
        "events": events,
    }


# ──── Node: Evaluate ────

async def lats_evaluate_node(state: dict) -> dict:
    """评估节点 — 决定继续搜索还是生成报告"""
    tree: SearchTree = state["search_tree"]
    bb = state["blackboard"]
    task_id = state["task_id"]
    cycle = state.get("current_cycle", 0)
    max_cycles = state.get("max_cycles", 15)
    results = state.get("react_results", [])

    await emit(task_id, "lats_eval", "agent_started", {"node": "evaluate"})

    # 计算本轮发现数
    findings_this_round = sum(1 for r in results if r.status == "finding")
    total_findings = len(bb.findings)

    # 更新 dry_cycles
    dry_cycles = state.get("dry_cycles", 0)
    if findings_this_round > 0:
        dry_cycles = 0
    else:
        dry_cycles += 1

    # 剪枝低价值节点
    pruned = 0
    budget_ratio = 1.0 - (cycle / max(1, max_cycles))
    for node in list(tree.nodes.values()):
        if node.status not in (NodeStatus.EXHAUSTED, NodeStatus.PRUNED, NodeStatus.CONFIRMED_VULN):
            if tree.should_prune(node, budget_ratio):
                tree.prune_node(node.id)
                pruned += 1

    tree_stats = tree.stats()

    tree_snapshot = []
    for nid, n in tree.nodes.items():
        tree_snapshot.append({
            "id": n.id,
            "parent": n.parent_id,
            "endpoint": n.state.current_endpoint,
            "vuln_type": n.state.vuln_type,
            "param": n.state.current_param,
            "value": round(n.average_reward, 3),
            "visits": n.visit_count,
            "status": n.status.value,
            "depth": n.depth,
        })

    await emit(task_id, "lats_eval", "cycle_summary", {
        "cycle": cycle + 1,
        "max_cycles": max_cycles,
        "findings_this_round": findings_this_round,
        "total_findings": total_findings,
        "dry_cycles": dry_cycles,
        "pruned": pruned,
        "tree_stats": tree_stats,
        "tree_snapshot": tree_snapshot,
    })

    await emit(task_id, "lats_eval", "agent_stopped", {"node": "evaluate"})

    return {
        "current_cycle": cycle + 1,
        "dry_cycles": dry_cycles,
        "search_tree": tree,
        "blackboard": bb,
        "events": [{
            "id": str(uuid.uuid4()),
            "agent": "lats_eval",
            "type": "cycle_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"cycle": cycle + 1, "findings": total_findings, "tree": tree_stats},
        }],
    }


# ──── Routing ────

def route_from_evaluate(state: dict) -> str:
    """评估节点的路由决策"""
    tree: SearchTree = state.get("search_tree")
    cycle = state.get("current_cycle", 0)
    max_cycles = state.get("max_cycles", 15)
    dry_cycles = state.get("dry_cycles", 0)
    bb = state.get("blackboard")

    # 条件 1：达到最大周期
    if cycle >= max_cycles:
        logger.info("达到最大搜索周期 (%d)，进入报告", max_cycles)
        return "reporter"

    # 条件 2：搜索树完全穷尽
    if tree and tree.all_explored():
        logger.info("搜索树已全部探索，进入报告")
        return "reporter"

    # 条件 3：连续 3 轮无发现且无高价值节点
    if dry_cycles >= 3:
        max_val = tree.max_unexplored_value() if tree else 0
        if max_val < 0.4:
            logger.info("连续 %d 轮无发现且最高价值 %.2f，进入报告", dry_cycles, max_val)
            return "reporter"

    # 条件 4：已有足够发现（至少 8 个高危以上）
    if bb:
        high_findings = [f for f in bb.findings if f.severity in ("critical", "high")]
        if len(high_findings) >= 8:
            logger.info("已有 %d 个高危发现，进入报告", len(high_findings))
            return "reporter"

    return "continue"


async def lats_pre_reporter_node(state: dict) -> dict:
    """桥接节点 — 将 LATS 状态映射为 reporter 兼容格式"""
    return {
        "iteration_count": state.get("current_cycle", 0),
        "current_phase": "reporting",
    }


# ──── Graph Builder ────

def build_lats_graph():
    """
    构建 LATS + ReAct 混合架构的 LangGraph 图

    Recon → Init Tree → [MCTS Select → React Execute → Evaluate] (循环) → Reporter
    """
    from app.agents.nodes.reporter import reporter_node

    graph = StateGraph(LATSState)

    # 添加节点
    graph.add_node("recon", lats_recon_node)
    graph.add_node("init_tree", lats_init_tree_node)
    graph.add_node("mcts_select", lats_mcts_select_node)
    graph.add_node("react_execute", lats_react_execute_node)
    graph.add_node("evaluate", lats_evaluate_node)
    graph.add_node("pre_reporter", lats_pre_reporter_node)
    graph.add_node("reporter", reporter_node)

    # 设置入口
    graph.set_entry_point("recon")

    # 固定边
    graph.add_edge("recon", "init_tree")
    graph.add_edge("init_tree", "mcts_select")
    graph.add_edge("mcts_select", "react_execute")
    graph.add_edge("react_execute", "evaluate")

    # 条件路由：继续搜索或报告
    graph.add_conditional_edges(
        "evaluate",
        route_from_evaluate,
        {
            "continue": "mcts_select",
            "reporter": "pre_reporter",
        },
    )

    # pre_reporter → reporter → END
    graph.add_edge("pre_reporter", "reporter")
    graph.add_edge("reporter", END)

    compiled = graph.compile()
    logger.info("LATS 漏洞挖掘图构建完成")
    return compiled


def create_lats_initial_state(
    task_id: str,
    task_config: dict,
    max_cycles: int = 15,
) -> dict:
    """创建 LATS 任务的初始状态"""
    bb = Blackboard(task_id=task_id)

    return {
        "blackboard": bb,
        "search_tree": None,
        "current_cycle": 0,
        "max_cycles": max_cycles,
        "iteration_count": 0,
        "task_id": task_id,
        "task_config": task_config,
        "events": [],
        "dry_cycles": 0,
        "selected_nodes": [],
        "react_results": [],
    }
