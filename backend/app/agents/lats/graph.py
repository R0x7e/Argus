"""
LATS LangGraph 图构建 (v2)

构建 LATS + ReAct 混合架构的状态图：
Recon → Init Tree → [MCTS Select → React Execute → Expand → Evaluate] (循环) → Reporter

v2 新增:
- expand_node: 发现驱动的动态扩展引擎 + 共享知识库集成
- mcts_select 使用自适应多因素选择 (select_batch API)
- Cold start 逻辑 (前 2 周期直接选种子)
- SharedKnowledge 跨分支信息共享
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
from app.agents.lats.expansion_engine import ExpansionEngine, Discovery, DiscoveryType
from app.agents.lats.multi_level_prober import BatchProber, QuickProber
from app.agents.lats.react_executor import ReactExecutorPool, ReactResult
from app.agents.lats.reward import compute_reward, estimate_branch_value, infer_vuln_types
from app.agents.lats.search_tree import NodeState, NodeStatus, SearchNode, SearchTree
from app.agents.lats.shared_knowledge import SharedKnowledge
from app.agents.state import Blackboard, VulnFinding
from app.tools.base import ExecutionContext

logger = logging.getLogger(__name__)

_llm_client: LLMClient | None = None
_executor_pool: ReactExecutorPool | None = None
_expansion_engine: ExpansionEngine | None = None


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


def _get_expansion_engine() -> ExpansionEngine:
    global _expansion_engine
    if _expansion_engine is None:
        _expansion_engine = ExpansionEngine()
    return _expansion_engine


# ──── LATS State Definition (v2) ────

class LATSState(TypedDict):
    """LATS 架构的状态定义（LangGraph TypedDict）v2 扩展"""
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
    # v2: 动态扩展 + 共享知识
    expansion_candidates: list
    discoveries: list
    expansion_stats: dict
    strategy_hints: dict  # v15: eval → select 反馈通道


# ──── Node: Recon ────

async def lats_recon_node(state: dict) -> dict:
    """侦察节点 — 复用原有侦察逻辑"""
    from app.agents.nodes.orchestrator import _run_reconnaissance, _build_execution_context, _get_llm_client as _get_orch_llm
    from app.agents.prompts.orchestrator import ORCHESTRATOR_SYSTEM_PROMPT

    task_id = state["task_id"]
    task_config = state.get("task_config", {}) or {}
    target_url = task_config.get("target_url", "")
    bb = state["blackboard"]

    # v2: 初始化共享知识库
    if bb.shared_knowledge is None:
        bb.shared_knowledge = SharedKnowledge()

    await emit(task_id, "lats_recon", "agent_started", {"node": "recon"})

    recon_results = await _run_reconnaissance(state)

    await emit(task_id, "lats_recon", "recon_complete", {
        "dirs_found": len(recon_results.get("directories", [])),
        "pages_crawled": len(recon_results.get("crawled_pages", [])),
        "params_found": len(recon_results.get("parameters", [])),
        "forms_found": len(recon_results.get("forms", [])),
    })

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

    response_text = await llm.call(agent="orchestrator", messages=messages, task_id=task_id)

    try:
        decision = json.loads(response_text)
    except json.JSONDecodeError:
        try:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            decision = json.loads(response_text[start:end]) if start >= 0 else {}
        except Exception:
            decision = {}

    target_profile = decision.get("target_profile", {})
    target_profile["base_url"] = target_url
    bb.target_profile = target_profile

    attack_surface = decision.get("attack_surface", {})
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

    # v2: 将侦察发现的端点初始录入 SharedKnowledge
    for ep_data in attack_surface.get("endpoints", [])[:50]:
        if isinstance(ep_data, dict):
            path = ep_data.get("path", "")
            method = ep_data.get("method", "GET")
            source = ep_data.get("source", "recon")
        elif isinstance(ep_data, str):
            path = ep_data
            method = "GET"
            source = "recon"
        else:
            continue
        if path and bb.shared_knowledge:
            try:
                import asyncio
                asyncio.ensure_future(
                    bb.shared_knowledge.record_endpoint(path=path, method=method, source=source)
                )
            except Exception:
                pass

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


# ──── v5: URL 语义解析 — 从 URL 路径推断参数和漏洞类型 ────

def _infer_vuln_from_path(path: str) -> list[str]:
    """从 URL 路径名推断可能的漏洞类型，不依赖参数发现"""
    path_lower = path.lower()
    types = []
    kw_map = {
        "sqli": "sql_injection", "sql": "sql_injection",
        "xss": "xss", "cross": "xss",
        "upload": "file_upload", "file": "lfi",
        "admin": "auth_bypass", "manage": "auth_bypass",
        "api": "idor", "search": "xss", "query": "sql_injection",
        "login": "auth_bypass", "signin": "auth_bypass", "auth": "auth_bypass",
        "redirect": "open_redirect", "callback": "ssrf",
        "download": "path_traversal", "exec": "rce", "cmd": "rce",
        "burteforce": "auth_bypass", "bf_": "auth_bypass",
        "user": "idor", "account": "idor", "order": "idor",
        "overpermission": "idor", "idor": "idor",
    }
    for kw, vt in kw_map.items():
        if kw in path_lower and vt not in types:
            types.append(vt)
    if not types:
        types = ["info_disclosure", "auth_bypass"]
    return types


def _is_endpoint_injectable(path: str) -> bool:
    """v9: 判断端点是否可能接受参数注入 (排除静态文件/配置/版本控制)"""
    path_lower = path.lower()
    static_suffixes = ('.git', '.ds_store', '.md', '.css', '.js', '.png', '.jpg',
                       '.jpeg', '.gif', '.svg', '.ico', '.woff', '.ttf', '.txt')
    static_names = ('.env', '.htaccess', '.htpasswd', 'dockerfile', 'docker-compose.yml',
                    '.svn', '.hg', '.bzr', 'license', 'readme', 'changelog',
                    'robots.txt', 'sitemap', 'favicon')
    if any(path_lower.endswith(s) for s in static_suffixes):
        return False
    if any(s in path_lower for s in static_names):
        return False
    return True


def _infer_params_from_url(url: str) -> list[dict]:
    """从 URL 文件名模式推断可能的参数名和漏洞类型"""
    import re as _re
    params = []
    path = url.split("?")[0]
    filename = path.rsplit("/", 1)[-1] if "/" in path else path
    name_lower = filename.lower()

    # 文件名拆词: sqli_id → [sqli, id]; bf_client → [bf, client]
    words = _re.split(r'[_.-]', name_lower)
    words = [w for w in words if w and len(w) > 1]

    param_hints = {
        "id": ["idor", "sql_injection", "xss"],
        "user": ["idor", "auth_bypass"],
        "search": ["xss", "sql_injection"],
        "query": ["sql_injection", "xss"],
        "name": ["xss", "sql_injection"],
        "file": ["lfi", "path_traversal"],
        "page": ["lfi", "path_traversal"],
        "url": ["ssrf", "open_redirect"],
        "cmd": ["rce"],
        "exec": ["rce"],
        "login": ["auth_bypass", "sql_injection"],
        "client": ["idor", "auth_bypass"],
        "server": ["ssrf", "auth_bypass"],
        "form": ["xss", "sql_injection", "auth_bypass"],
        "upload": ["file_upload", "rce"],
        "download": ["path_traversal"],
        "admin": ["auth_bypass"],
    }

    for word in words:
        if word in param_hints:
            params.append({
                "name": word,
                "vuln_types": param_hints[word],
                "source": "url_inferred",
            })

    # 如果 URL 有 query string，直接提取参数
    if "?" in url:
        from urllib.parse import parse_qs, urlparse as _urlparse
        try:
            parsed = _urlparse(url)
            for pname in parse_qs(parsed.query).keys():
                if pname not in [p["name"] for p in params]:
                    from app.agents.lats.reward import infer_vuln_types
                    params.append({
                        "name": pname,
                        "vuln_types": infer_vuln_types(pname, path),
                        "source": "url_query",
                    })
        except Exception:
            pass

    return params


# ──── Node: Init Tree (v2: 使用 SEED 状态) ────

async def lats_init_tree_node(state: dict) -> dict:
    """初始化搜索树 — 将攻击面转换为初始分支 (v2: 标记为 SEED)"""
    bb = state["blackboard"]
    task_id = state["task_id"]
    attack_surface = bb.attack_surface or {}
    target_url = bb.target_profile.get("base_url", "")
    tech_stack = bb.target_profile.get("tech_stack", [])
    # v14: 读取任务目标漏洞类型 — 从 config 或 task_name 推断
    focus_vuln_types = task_config.get("focus_vuln_types", [])
    if not focus_vuln_types:
        task_name = task_config.get("name", task_config.get("task_name", ""))
        name_lower = (task_name or "").lower()
        name_hints = {"xss": ["xss"], "sqli": ["sql_injection"], "sql": ["sql_injection"],
                      "rce": ["rce"], "cmd": ["rce"], "lfi": ["lfi", "path_traversal"],
                      "ssrf": ["ssrf"], "ssti": ["ssti"], "idor": ["idor"],
                      "upload": ["file_upload"], "redirect": ["open_redirect"]}
        for hint, types in name_hints.items():
            if hint in name_lower:
                focus_vuln_types = types
                break
    if focus_vuln_types:
        bb.focus_vuln_types = focus_vuln_types

    # v18: URL 模式自动分类 — 整站 vs 单页
    from urllib.parse import urlparse as _urlparse
    parsed_target = _urlparse(target_url) if target_url else None
    target_path = parsed_target.path if parsed_target else "/"
    is_single_page = bool(parsed_target and parsed_target.path and
                          any(parsed_target.path.lower().endswith(ext)
                              for ext in ('.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.cgi', '.do', '.action')))
    is_single_page = is_single_page or bool(parsed_target and parsed_target.query)
    scan_mode = "single_page" if is_single_page else "full_site"
    logger.info("init_tree scan_mode=%s target=%s", scan_mode, target_url)

    await emit(task_id, "lats_init", "agent_started", {"node": "init_tree", "scan_mode": scan_mode})

    tree = SearchTree()

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
        status=NodeStatus.EXPLORING,  # v5: 根节点不应被选中执行
    )
    tree.set_root(root)

    # v14: 设置搜索树的目标漏洞类型 (供选择器使用 focus bonus)
    if focus_vuln_types:
        tree.focus_vuln_types = focus_vuln_types

    # v5: URL 语义推断 + 随机抖动打破同质化
    import random as _random
    target_path = target_url.split("?")[0] if target_url else ""
    url_inferred_params = _infer_params_from_url(target_url) if target_url else []
    url_inferred_vulns = _infer_vuln_from_path(target_path) if target_path else []

    branches_created = 0
    seen_branches = set()

    # v18: 单页模式 — 仅为目标 URL 创建分支
    if scan_mode == "single_page":
        # 确保目标 URL 本身作为端点被处理
        if target_path and target_path != "/":
            single_endpoints = [{"path": target_path, "params": [], "source": "target_url"}]
            # 从 query string 提取参数
            if parsed_target and parsed_target.query:
                from urllib.parse import parse_qs as _parse_qs
                try:
                    qs_params = list(_parse_qs(parsed_target.query).keys())
                    single_endpoints[0]["params"] = qs_params
                    logger.info("single_page: extracted params from URL: %s", qs_params)
                except Exception:
                    pass
        else:
            single_endpoints = [{"path": target_path or "/", "params": [], "source": "target_url"}]
        endpoints_to_process = single_endpoints
    else:
        endpoints_to_process = attack_surface.get("endpoints", [])

    for endpoint in endpoints_to_process:
        if isinstance(endpoint, str):
            endpoint = {"path": endpoint, "params": [], "source": "llm"}
        path = endpoint.get("path", "")
        params = endpoint.get("params", [])
        source = endpoint.get("source", "")

        if not path:
            continue

        if not params:
            for vtype in ["info_disclosure", "auth_bypass"]:
                branch_key = f"{vtype}@{path}"
                if branch_key in seen_branches:
                    continue
                seen_branches.add(branch_key)
                value = estimate_branch_value(vtype, "", path, tech_stack, source, focus_vuln_types=focus_vuln_types)
                value += _random.uniform(-0.05, 0.05)  # v5: 打破同质化
                value = max(0.05, min(1.0, value))
                child = tree.create_child_node(
                    parent=root, action="explore",
                    action_params={"endpoint": path, "vuln_type": vtype},
                    vuln_type=vtype, endpoint=path, param=None,
                    value_estimate=value, created_at_cycle=0,
                )
                child.status = NodeStatus.SEED  # v2
                branches_created += 1

        for param in params:
            param_name = param if isinstance(param, str) else param.get("name", "")
            vuln_types = infer_vuln_types(param_name, endpoint, tech_stack)
            for vtype in vuln_types:
                branch_key = f"{vtype}@{path}:{param_name}"
                if branch_key in seen_branches:
                    continue
                seen_branches.add(branch_key)
                value = estimate_branch_value(vtype, param_name, path, tech_stack, source, focus_vuln_types=focus_vuln_types)
                value += _random.uniform(-0.05, 0.05)  # v5: 打破同质化
                value = max(0.05, min(1.0, value))
                child = tree.create_child_node(
                    parent=root, action="explore",
                    action_params={"endpoint": path, "param": param_name, "vuln_type": vtype},
                    vuln_type=vtype, endpoint=path, param=param_name,
                    value_estimate=value, created_at_cycle=0,
                )
                child.status = NodeStatus.SEED  # v2
                branches_created += 1

    # v5: 为 URL 推断参数创建分支 (打破 auth_bypass 垄断)
    for inferred in url_inferred_params:
        pname = inferred["name"]
        for vtype in inferred["vuln_types"][:3]:
            for ep_data in attack_surface.get("endpoints", [])[:1]:
                path = ep_data if isinstance(ep_data, str) else ep_data.get("path", "")
                if not path or path.startswith("http://127.0.0.1"):
                    path = target_path or "/"
                branch_key = f"{vtype}@{path}:{pname}"
                if branch_key in seen_branches:
                    continue
                seen_branches.add(branch_key)
                value = estimate_branch_value(vtype, pname, path, tech_stack, "url_inferred", focus_vuln_types=focus_vuln_types)
                value += _random.uniform(-0.05, 0.05)  # v5: 随机抖动打破同质化
                value = max(0.05, min(1.0, value))
                child = tree.create_child_node(
                    parent=root, action="explore_inferred",
                    action_params={"endpoint": path, "param": pname, "vuln_type": vtype},
                    vuln_type=vtype, endpoint=path, param=pname,
                    value_estimate=value, created_at_cycle=0,
                )
                child.status = NodeStatus.SEED
                branches_created += 1

    # v8: Fallback — 为每个可注入端点强制创建注入探测分支 (v9: 过滤静态文件)
    fallback_params = ["id", "q", "file", "url", "cmd", "name", "page"]
    for endpoint_data in attack_surface.get("endpoints", [])[:10]:
        path = endpoint_data if isinstance(endpoint_data, str) else endpoint_data.get("path", "")
        if not path or path.startswith("http://127"):
            path = target_path or "/"
        # v9: 仅为可注入端点创建 RCE/LFI/SQLi 分支
        if not _is_endpoint_injectable(path):
            continue
        for fb_param in fallback_params:
            fb_vuln_map = {
                "id": ["sql_injection", "idor", "xss"],
                "q": ["xss", "sql_injection"],
                "file": ["lfi", "path_traversal"],
                "url": ["ssrf", "open_redirect"],
                "cmd": ["rce"],
                "name": ["xss", "sql_injection"],
                "page": ["lfi", "path_traversal"],
            }
            for vt in fb_vuln_map.get(fb_param, ["sql_injection"])[:2]:
                bk = f"{vt}@{path}:{fb_param}"
                if bk in seen_branches:
                    continue
                seen_branches.add(bk)
                val = max(0.3, estimate_branch_value(vt, fb_param, path, tech_stack, "fallback", focus_vuln_types=focus_vuln_types) - 0.15)
                val += _random.uniform(-0.03, 0.03)
                child = tree.create_child_node(
                    parent=root, action="explore_fallback",
                    action_params={"endpoint": path, "param": fb_param, "vuln_type": vt},
                    vuln_type=vt, endpoint=path, param=fb_param,
                    value_estimate=max(0.1, min(1.0, val)), created_at_cycle=0,
                )
                child.status = NodeStatus.LOW_SIGNAL  # 低优先级, 预算宽松时执行
                branches_created += 1

    # v5: 为 URL 推断的漏洞类型创建分支 (即使无参)
    for vtype in url_inferred_vulns[:4]:
        branch_key = f"{vtype}@{target_path}"
        if branch_key in seen_branches:
            continue
        seen_branches.add(branch_key)
        value = estimate_branch_value(vtype, "", target_path, tech_stack, "url_inferred", focus_vuln_types=focus_vuln_types)
        value += _random.uniform(-0.05, 0.05)
        value = max(0.05, min(1.0, value))
        child = tree.create_child_node(
            parent=root, action="explore_inferred",
            action_params={"endpoint": target_path, "vuln_type": vtype},
            vuln_type=vtype, endpoint=target_path, param=None,
            value_estimate=value, created_at_cycle=0,
        )
        child.status = NodeStatus.SEED
        branches_created += 1

    # v9/v18: 分层剪枝 — 单页模式用更小的上限
    prune_limit = 40 if scan_mode == "single_page" else 120
    if branches_created > prune_limit:
        all_children = [tree.get_node(cid) for cid in root.children]
        # 先保留高优先级节点
        keep = [n for n in all_children if n and n.status in (
            NodeStatus.SEED, NodeStatus.PROMOTED, NodeStatus.HIGH_SIGNAL,
        )]
        remaining_slots = prune_limit - len(keep)
        # 对 LOW_SIGNAL 节点按 val 排序, 保留前 remaining_slots 个
        low_sig = [n for n in all_children if n and n.status == NodeStatus.LOW_SIGNAL]
        low_sig.sort(key=lambda n: n.value_estimate, reverse=True)
        keep_ids = {n.id for n in keep}
        # Prune LOW_SIGNAL beyond limit
        for node in low_sig[remaining_slots:]:
            tree.prune_node(node.id)
        pruned_count = max(0, branches_created - prune_limit)
    else:
        pruned_count = 0

    await emit(task_id, "lats_init", "tree_initialized", {
        "branches": branches_created,
        "pruned_to": min(branches_created, prune_limit),
    })
    await emit(task_id, "lats_init", "agent_stopped", {"node": "init_tree"})

    logger.info("搜索树初始化完成: %d 分支 (v2 SEED 状态)", branches_created)

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


# ──── Node: MCTS Select (v2: 自适应多因素选择) ────

async def lats_mcts_select_node(state: dict) -> dict:
    """MCTS 选择 (v2: 自适应多因素选择 + cold start)"""
    tree: SearchTree = state["search_tree"]
    task_id = state["task_id"]
    pool = _get_executor_pool()
    cycle = state.get("current_cycle", 0)

    await emit(task_id, "lats_mcts", "agent_started", {"node": "mcts_select", "cycle": cycle})

    # v15: 动态 batch_size — 有发现时加并发, 无进展时减并发
    dry = state.get("dry_cycles", 0)
    if dry == 0:
        batch_size = min(6, pool.max_concurrent + 2)
    elif dry <= 2:
        batch_size = pool.max_concurrent
    else:
        batch_size = max(2, pool.max_concurrent - 1)
    selected = tree.select_batch(
        batch_size=batch_size,
        current_cycle=cycle,
        cold_start_until_cycle=2,
    )

    selected_info = []
    for n in selected:
        parent = tree.get_node(n.parent_id) if n.parent_id else None
        score = tree._adaptive_selection_score(n, parent)
        info = {
            "id": n.id[:8], "type": n.state.vuln_type,
            "endpoint": n.state.current_endpoint,
            "value": round(n.value_estimate, 2),
            "empirical": round(n.empirical_value, 2),
            "status": n.status.value, "visits": n.visit_count,
            "score": round(score, 3),
            "score_breakdown": {
                "exploitation": round(tree._exploitation_weight(tree.global_step) * tree._wilson_score_lower_bound(n), 3),
                "exploration": round(tree._exploration_weight(tree.global_step) * (2.0 * __import__('math').exp(-tree.global_step / tree.total_expected_steps) * __import__('math').sqrt(__import__('math').log(max(1, parent.visit_count if parent else 1)) / max(1, n.visit_count))) if n.visit_count > 0 else 0, 3),
                "prior": round(tree._prior_weight(tree.global_step) * n.value_estimate, 3),
                "diversity": round(tree.DIVERSITY_WEIGHT * tree._diversity_score(n), 3),
                "recency": round(tree.RECENCY_WEIGHT * tree._recency_score(n), 3),
            },
        }
        selected_info.append(info)

    await emit(task_id, "lats_mcts", "nodes_selected", {
        "count": len(selected), "nodes": selected_info,
        "selection_path": [n.id for n in selected],
        "cold_start": cycle <= 2,
        "prior_weight": round(tree._prior_weight(tree.global_step), 4),
        "exploration_weight": round(tree._exploration_weight(tree.global_step), 4),
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
    task_config = state.get("task_config", {}) or {}
    selected_ids = state.get("selected_nodes", [])

    await emit(task_id, "lats_react", "agent_started", {"node": "react_execute", "batch_size": len(selected_ids)})

    if not selected_ids:
        await emit(task_id, "lats_react", "agent_stopped", {"node": "react_execute"})
        return {"react_results": [], "events": []}

    target_profile = bb.target_profile or {}
    base_url = target_profile.get("base_url", "")
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"

    context = ExecutionContext(
        task_id=task_id, target_host=host, timeout=30, max_retries=2,
        allowed_hosts=[host],
        auth_headers=task_config.get("auth_headers", {}),
        cookies=task_config.get("cookies", {}),
        auth_token=task_config.get("auth_token", ""),
    )

    nodes = [tree.get_node(nid) for nid in selected_ids if tree.get_node(nid)]
    nodes = [n for n in nodes if n and n.status != NodeStatus.EXHAUSTED]

    if not nodes:
        await emit(task_id, "lats_react", "agent_stopped", {"node": "react_execute"})
        return {"react_results": [], "events": []}

    # 提取 cycle 必须在 Level 0 探测之前，供后续 mark_promoted 等使用
    cycle = state.get("current_cycle", 0)
    max_cycles = state.get("max_cycles", 15)

    # v2: Level 0 快速探测 — 对 SEED 节点执行 3 次廉价 HTTP 请求
    seed_nodes = [n for n in nodes if n.status == NodeStatus.SEED]
    if seed_nodes:
        prober = BatchProber(max_concurrent=5)
        probe_results = await prober.probe_batch(seed_nodes, context, base_url)
        promoted_count = 0
        killed_count = 0
        low_signal_count = 0
        for pr in probe_results:
            node = tree.get_node(pr.node_id)
            if not node:
                continue
            node.probe_level = 1
            node.probe_results = [{
                "verdict": pr.verdict,
                "baseline_status": pr.baseline_status,
                "probe_status": pr.probe_status,
                "inject_status": pr.inject_status,
                "signals": pr.signals,
                "error": pr.error,
            }]
            # 更新经验价值
            if pr.verdict == "promoted":
                node.empirical_value = max(0.3, node.value_estimate)
                tree.mark_promoted(node.id, cycle)
                promoted_count += 1
            elif pr.verdict == "killed":
                node.empirical_value = -0.5
                tree.mark_killed(node.id, reason=f"Level0: {pr.error or 'no_signal'}")
                killed_count += 1
            elif pr.verdict == "low_signal":
                # v7: 降级保留 — 降低 prior, 标记为 LOW_SIGNAL, 预算宽松时可被选中
                node.status = NodeStatus.LOW_SIGNAL
                node.value_estimate = max(0.2, node.value_estimate - 0.2)
                node.empirical_value = 0.0
                low_signal_count += 1
            else:
                node.empirical_value = 0.0

        await emit(task_id, "lats_react", "level0_probe_complete", {
            "total": len(seed_nodes), "promoted": promoted_count,
            "killed": killed_count, "low_signal": low_signal_count,
        })

        # 过滤: 只对 PROMOTED/HIGH_SIGNAL/NEEDS_EXPANSION 执行 Full ReAct
        nodes = [n for n in nodes if n.status not in (NodeStatus.SEED, NodeStatus.KILLED)]

    # 更新 remaining_ratio 基于已提取的 cycle/max_cycles
    remaining_ratio = 1.0 - (cycle / max(1, max_cycles))

    if remaining_ratio > 0.7:
        max_steps = 10
    elif remaining_ratio > 0.4:
        max_steps = 7
    elif remaining_ratio > 0.2:
        max_steps = 5
    else:
        max_steps = 3

    # v2: 提取用户 steering directives
    steering_directives = bb.steering_directives if hasattr(bb, 'steering_directives') and bb.steering_directives else None

    pool = _get_executor_pool()
    llm = _get_llm_client()
    results = await pool.execute_batch(
        nodes, context, llm, max_steps,
        steering_directives=steering_directives,
    )

    events = []
    findings_this_round = []

    for result in results:
        node = tree.get_node(result.node_id)
        if not node:
            continue

        tree.backpropagate(result.node_id, result.reward)

        if result.status == "finding" and result.finding:
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
                "type": finding.type, "severity": finding.severity,
                "endpoint": node.state.current_endpoint,
                "param": node.state.current_param, "steps": len(result.steps),
            })
            events.append({
                "id": str(uuid.uuid4()), "agent": "lats_react", "type": "finding_confirmed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": {"type": finding.type, "severity": finding.severity},
            })

        elif result.status in ("exhausted", "backtrack"):
            # v11: 高价值节点降级为 NEEDS_EXPANSION, 不急于 exhaust
            node_for_check = tree.get_node(result.node_id)
            if node_for_check and node_for_check.value_estimate > 0.55:
                node_for_check.status = NodeStatus.NEEDS_EXPANSION
                # v17: 记录回溯原因, 避免重复进入相同方向
                node_for_check.observation_summary = f"backtracked: {result.status}"
            else:
                tree.mark_exhausted(result.node_id)
                # v17: 记录 vuln_type 失败到知识库
                if node_for_check and bb.shared_knowledge:
                    try:
                        import asyncio
                        asyncio.ensure_future(
                            bb.shared_knowledge.record_vuln_type_failure(node_for_check.state.vuln_type)
                        )
                    except Exception:
                        pass

        elif result.status == "step_limit":
            if result.reward > 0.2:
                node.status = NodeStatus.NEEDS_EXPANSION
                # v15: 触发深度扩展 — 为 NEEDS_EXPANSION 节点创建子方向
                engine = _get_expansion_engine()
                depth_children = engine.expand_node_for_depth(tree, node, cycle)
                if depth_children:
                    await emit(task_id, "lats_react", "depth_expansion", {
                        "parent_node": node.id[:8], "vuln_type": node.state.vuln_type,
                        "depth": node.depth, "children": len(depth_children),
                    })
            else:
                tree.mark_exhausted(result.node_id)

    await emit(task_id, "lats_react", "agent_stopped", {
        "node": "react_execute",
        "findings": len(findings_this_round),
        "exhausted": sum(1 for r in results if r.status in ("exhausted", "backtrack")),
    })

    return {
        "blackboard": bb, "search_tree": tree,
        "react_results": results, "events": events,
    }


# ──── Node: Expand (v2: 发现驱动的动态扩展 + 知识库记录) ────

async def lats_expand_node(state: dict) -> dict:
    """动态扩展节点 (v2): 提取发现 → 创建分支 → 写入知识库 → Graveyard 复活"""
    tree: SearchTree = state["search_tree"]
    bb = state["blackboard"]
    task_id = state["task_id"]
    cycle = state.get("current_cycle", 0)
    react_results = state.get("react_results", [])
    target_url = bb.target_profile.get("base_url", "") if bb.target_profile else ""

    # 确保知识库已初始化
    if bb.shared_knowledge is None:
        bb.shared_knowledge = SharedKnowledge()
    knowledge = bb.shared_knowledge

    await emit(task_id, "lats_expand", "agent_started", {"node": "expand", "cycle": cycle})

    engine = _get_expansion_engine()
    extractor = engine.discovery_extractor

    # 1. 从 ReAct 结果中提取发现
    all_discoveries: list[Discovery] = []
    for result in react_results:
        if result is None:
            continue
        node = tree.get_node(result.node_id) if hasattr(result, 'node_id') else None
        if node is None:
            continue

        react_discoveries = extractor.extract_from_react_result(result, node, cycle)
        all_discoveries.extend(react_discoveries)

        for tr in getattr(result, 'tool_results', []):
            # v2-fix: 防御性检查 — tool_results 中可能混入非 dict 值
            if not isinstance(tr, dict):
                continue
            # v9-fix: result 子字段也可能是字符串
            tool_result_raw = tr.get('result', {})
            if not isinstance(tool_result_raw, dict):
                tool_result_raw = {}
            tool_discoveries = extractor.extract_from_tool_result(
                tool_name=tr.get('tool', ''),
                tool_result=tool_result_raw,
                node=node, cycle=cycle,
            )
            all_discoveries.extend(tool_discoveries)

    unique_discoveries = _deduplicate_discoveries(all_discoveries)

    # 2. 写入 SharedKnowledge (从 ReAct 结果 + 发现)
    await _sync_discoveries_to_knowledge(knowledge, unique_discoveries, react_results, tree)

    # 3. 执行扩展 (传入 knowledge 以启用 Graveyard 复活)
    expansion_result = engine.expand(
        tree=tree,
        discoveries=unique_discoveries,
        current_cycle=cycle,
        base_url=target_url,
        knowledge=knowledge,
    )

    tree_stats = tree.stats()

    await emit(task_id, "lats_expand", "expansion_complete", {
        **expansion_result,
        "tree_stats": tree_stats,
        "graveyard": tree.get_graveyard_stats(),
        "knowledge_summary": knowledge.get_summary() if knowledge else {},
    })

    await emit(task_id, "lats_expand", "agent_stopped", {"node": "expand"})

    # v18-fix: engine.expand 异常保护 (修复 v13 缩进语法错误)
    try:
        expansion_result = engine.expand(
            tree=tree, discoveries=unique_discoveries,
            current_cycle=cycle, base_url=target_url, knowledge=knowledge,
        )
    except Exception as e:
        logger.error("engine.expand failed (non-fatal): %s", str(e))
        expansion_result = {"error": str(e)[:200], "new_branches": 0, "resurrected": 0, "by_type": {}}

    tree_stats = tree.stats()

    await emit(task_id, "lats_expand", "expansion_complete", {
        **expansion_result,
        "tree_stats": tree_stats,
        "graveyard": tree.get_graveyard_stats(),
        "knowledge_summary": knowledge.get_summary() if knowledge else {},
    })

    return {
        "search_tree": tree,
        "discoveries": [d.data for d in unique_discoveries],
        "expansion_stats": expansion_result,
        "blackboard": bb,
        "events": [{
            "id": str(uuid.uuid4()),
            "agent": "lats_expand",
            "type": "expansion_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": expansion_result,
        }],
    }


async def _sync_discoveries_to_knowledge(
    knowledge, discoveries: list, react_results: list, tree: SearchTree,
) -> None:
    """将本轮的发现同步到 SharedKnowledge (非阻塞)"""
    import asyncio as _asyncio

    for d in discoveries:
        # v3-fix: data 防御 — d.data 可能为字符串
        data = d.data if isinstance(d.data, dict) else {}
        try:
            if d.discovery_type == DiscoveryType.NEW_ENDPOINT:
                await knowledge.record_endpoint(
                    path=data.get("url", ""), method="GET",
                    source=data.get("source", "react"),
                )
            elif d.discovery_type == DiscoveryType.NEW_PARAM:
                await knowledge.record_param(
                    param_name=data.get("param_name", ""),
                    endpoint=data.get("endpoint", ""),
                )
            elif d.discovery_type == DiscoveryType.WAF_BYPASS_FOUND:
                # v16: 完整记录 WAF 规则 (filtered/allowed chars + bypass technique)
                filter_data = data.get("filter_rules", {})
                if isinstance(filter_data, dict):
                    blocked = filter_data.get("blocked", [])
                    allowed = filter_data.get("allowed", [])
                    for ch in (blocked if isinstance(blocked, list) else []):
                        await knowledge.record_waf_rule(filtered_char=str(ch)[:1])
                    for ch in (allowed if isinstance(allowed, list) else []):
                        await knowledge.record_waf_rule(allowed_char=str(ch)[:1])
                await knowledge.record_waf_rule(
                    bypass_technique={"technique": str(data.get("filter_rules", ""))[:100]},
                )
            elif d.discovery_type == DiscoveryType.TECH_DISCOVERY:
                await knowledge.record_tech_discovery(
                    tech_name=data.get("tech_name", ""),
                    source=data.get("evidence", "react"),
                )
            elif d.discovery_type == DiscoveryType.ERROR_LEAK:
                # v16: 从 source_node 获取 endpoint (discovery.data 中无此字段)
                src_node = tree.get_node(d.source_node_id)
                ep = src_node.state.current_endpoint if src_node else data.get("endpoint", "")
                param = src_node.state.current_param if src_node else data.get("param", "")
                await knowledge.record_vuln_signal(
                    endpoint=ep, param=param or "",
                    vuln_type="sql_injection", signal_type="error_leaked",
                    confidence=0.6, evidence=data.get("observation", ""),
                )
            elif d.discovery_type == DiscoveryType.VULN_TYPE_CLUE:
                # v16: VULN_TYPE_CLUE → 记录漏洞信号
                src_node = tree.get_node(d.source_node_id)
                ep = src_node.state.current_endpoint if src_node else data.get("endpoint", "")
                param = src_node.state.current_param if src_node else data.get("param", "")
                await knowledge.record_vuln_signal(
                    endpoint=ep, param=param or "",
                    vuln_type=src_node.state.vuln_type if src_node else "unknown",
                    signal_type="reflected" if "reflected" in str(data).lower() else "vuln_clue",
                    confidence=d.confidence, evidence=str(data.get("observation", data))[:200],
                )
        except Exception as e:
            logger.warning("knowledge sync failed for %s: %s",
                          d.discovery_type.value if d.discovery_type else "?", str(e)[:100])

    # 从 ReAct 结果中记录探索历史
    for result in react_results:
        if result is None or not hasattr(result, 'node_id'):
            continue
        node = tree.get_node(result.node_id)
        if node is None:
            continue
        try:
            await knowledge.record_exploration(
                node_id=result.node_id,
                vuln_type=node.state.vuln_type,
                endpoint=node.state.current_endpoint,
                param=node.state.current_param,
                result=result.status,
                key_findings=getattr(result, 'new_facts', []),
            )
        except Exception:
            pass


def _deduplicate_discoveries(discoveries: list) -> list:
    """去重：同类型、同 endpoint、同 param 只保留一个 (v2-fix: data 防御)"""
    seen = set()
    unique = []
    for d in discoveries:
        # v2-fix: data 可能是字符串(非 dict)的防御
        data = d.data if isinstance(d.data, dict) else {}
        endpoint = data.get('endpoint', data.get('url', ''))
        param = data.get('param_name', '')
        key = f"{d.discovery_type.value}@{endpoint}@{param}"
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


# ──── Node: Evaluate (v2: 增强) ────

async def lats_evaluate_node(state: dict) -> dict:
    """评估节点 — 决定继续搜索还是生成报告 (v2: 考虑 Graveyard 复活)"""
    tree: SearchTree = state["search_tree"]
    bb = state["blackboard"]
    task_id = state["task_id"]
    cycle = state.get("current_cycle", 0)
    max_cycles = state.get("max_cycles", 15)
    results = state.get("react_results", [])
    expansion_stats = state.get("expansion_stats", {})

    await emit(task_id, "lats_eval", "agent_started", {"node": "evaluate"})

    findings_this_round = sum(1 for r in results if r.status == "finding")
    total_findings = len(bb.findings)

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

    # v2: 知识库覆盖率统计
    knowledge_stats = {}
    if bb.shared_knowledge:
        knowledge_stats = bb.shared_knowledge.get_coverage_stats()

    tree_snapshot = []
    for nid, n in tree.nodes.items():
        tree_snapshot.append({
            "id": n.id, "parent": n.parent_id,
            "endpoint": n.state.current_endpoint,
            "vuln_type": n.state.vuln_type,
            "param": n.state.current_param,
            "value": round(n.average_reward, 3),
            "empirical": round(n.empirical_value, 3),
            "visits": n.visit_count,
            "status": n.status.value, "depth": n.depth,
        })

    await emit(task_id, "lats_eval", "cycle_summary", {
        "cycle": cycle + 1, "max_cycles": max_cycles,
        "findings_this_round": findings_this_round,
        "total_findings": total_findings,
        "dry_cycles": dry_cycles, "pruned": pruned,
        "tree_stats": tree_stats, "tree_snapshot": tree_snapshot,
        "knowledge_stats": knowledge_stats,
        "expansion_new_branches": expansion_stats.get("new_branches", 0),
        "expansion_resurrected": expansion_stats.get("resurrected", 0),
    })

    await emit(task_id, "lats_eval", "agent_stopped", {"node": "evaluate"})

    # v15: eval → select 反馈
    bb_focus = getattr(bb, 'focus_vuln_types', None) or tree.focus_vuln_types
    strategy_hints = {
        "dry_cycles": dry_cycles,
        "should_focus": dry_cycles >= 2,
        "new_branches_this_cycle": expansion_stats.get("new_branches", 0),
        "focus_vuln_types": bb_focus,
        "total_nodes": tree_stats.get("total_nodes", 0),
    }

    return {
        "current_cycle": cycle + 1,
        "dry_cycles": dry_cycles,
        "search_tree": tree,
        "blackboard": bb,
        "expansion_stats": expansion_stats,
        "strategy_hints": strategy_hints,
        "events": [{
            "id": str(uuid.uuid4()),
            "agent": "lats_eval",
            "type": "cycle_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"cycle": cycle + 1, "findings": total_findings, "tree": tree_stats},
        }],
    }


# ──── Routing (v2) ────

def route_from_evaluate(state: dict) -> str:
    """评估节点的路由决策 (v2: 考虑新状态 + Graveyard 复活)"""
    tree: SearchTree = state.get("search_tree")
    cycle = state.get("current_cycle", 0)
    max_cycles = state.get("max_cycles", 15)
    dry_cycles = state.get("dry_cycles", 0)
    bb = state.get("blackboard")
    expansion_stats = state.get("expansion_stats", {})

    if cycle >= max_cycles:
        logger.info("达到最大搜索周期 (%d)，进入报告", max_cycles)
        return "reporter"

    if tree and tree.all_explored():
        if tree.graveyard and expansion_stats.get("resurrected", 0) > 0:
            logger.info("Graveyard 中有节点被复活，继续搜索")
            return "continue"
        logger.info("搜索树已全部探索，进入报告")
        return "reporter"

    if dry_cycles >= 3:
        max_val = tree.max_unexplored_value() if tree else 0
        if max_val < 0.3:
            logger.info("连续 %d 轮无发现且最高价值 %.2f，进入报告", dry_cycles, max_val)
            return "reporter"

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


# ──── Graph Builder (v2) ────

def build_lats_graph():
    """构建 LATS + ReAct + 动态扩展 + 知识库的 LangGraph 图"""
    from app.agents.nodes.reporter import reporter_node

    graph = StateGraph(LATSState)

    graph.add_node("recon", lats_recon_node)
    graph.add_node("init_tree", lats_init_tree_node)
    graph.add_node("mcts_select", lats_mcts_select_node)
    graph.add_node("react_execute", lats_react_execute_node)
    graph.add_node("expand", lats_expand_node)  # v2
    graph.add_node("evaluate", lats_evaluate_node)
    graph.add_node("pre_reporter", lats_pre_reporter_node)
    graph.add_node("reporter", reporter_node)

    graph.set_entry_point("recon")

    graph.add_edge("recon", "init_tree")
    graph.add_edge("init_tree", "mcts_select")
    graph.add_edge("mcts_select", "react_execute")
    graph.add_edge("react_execute", "expand")  # v2: execute → expand
    graph.add_edge("expand", "evaluate")        # v2: expand → evaluate

    graph.add_conditional_edges(
        "evaluate", route_from_evaluate,
        {"continue": "mcts_select", "reporter": "pre_reporter"},
    )

    graph.add_edge("pre_reporter", "reporter")
    graph.add_edge("reporter", END)

    compiled = graph.compile()
    logger.info("LATS v2 漏洞挖掘图构建完成 (自适应选择 + 动态扩展 + 共享知识库)")
    return compiled


def create_lats_initial_state(
    task_id: str,
    task_config: dict,
    max_cycles: int = 15,
) -> dict:
    """创建 LATS 任务的初始状态 (v2-fix: max_cycles 从 task_config 兜底)"""
    bb = Blackboard(task_id=task_id)
    # v4-fix: 无条件从 task_config 读取更大的 max_cycles
    config_max = int(task_config.get("max_iterations",
                    task_config.get("config", {}).get("max_iterations", 0)))
    if config_max > max_cycles:
        max_cycles = config_max
    # 如果 task_config 中有 max_cycles 字段也读取
    tc_max = int(task_config.get("max_cycles", 0))
    if tc_max > max_cycles:
        max_cycles = tc_max

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
        "expansion_candidates": [],
        "discoveries": [],
        "expansion_stats": {},
        "strategy_hints": {},
    }
