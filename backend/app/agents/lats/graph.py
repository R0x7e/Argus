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
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, TypedDict
from urllib.parse import urlparse

import operator
from langgraph.graph import END, StateGraph

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.agents.lats.expansion_engine import ExpansionEngine, Discovery, DiscoveryType
from app.agents.lats.node_resurrection import NodeResurrectionEngine
from app.agents.lats.multi_level_prober import BatchProber, QuickProber
from app.agents.lats.react_executor import ReactExecutorPool, ReactResult
from app.agents.lats.reward import compute_reward, estimate_branch_value, infer_vuln_types
from app.agents.lats.search_tree import NodeState, NodeStatus, SearchNode, SearchTree
from app.agents.lats.endpoint_capability import (
    EndpointCapability, get_endpoint_capability_sync, estimate_branch_value_v2,
    is_vuln_type_compatible, get_compatible_vuln_types,
)
from app.agents.lats.shared_knowledge import SharedKnowledge
from app.agents.state import Blackboard, VulnFinding
from app.agents.token_budget import BudgetTier, TieredBudgetManager
from app.tools.base import ExecutionContext

logger = logging.getLogger(__name__)

_llm_client: LLMClient | None = None
_executor_pool: ReactExecutorPool | None = None
_expansion_engine: ExpansionEngine | None = None
# 每任务独立的 LLM 客户端实例，避免并发任务间状态污染
_task_llm_clients: dict[str, LLMClient] = {}


def register_task_llm_client(task_id: str, client: LLMClient) -> None:
    """注册任务专属的 LLM 客户端实例"""
    _task_llm_clients[task_id] = client


def unregister_task_llm_client(task_id: str) -> None:
    """清理任务专属的 LLM 客户端实例"""
    _task_llm_clients.pop(task_id, None)


def _get_llm_client(task_id: str = "") -> LLMClient:
    """获取 LLM 客户端：优先使用任务专属实例，回退到全局单例"""
    if task_id and task_id in _task_llm_clients:
        return _task_llm_clients[task_id]
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
    current_phase: str  # reporter 节点返回的当前阶段标识
    # v21: HDE 架构 — 端点聚焦探索模式
    exploration_mode: str  # "tree"(默认,MCTS) | "endpoint"(新HDE)
    endpoint_explorer: Any  # EndpointExplorer 实例(仅 endpoint 模式使用)
    # v2/L3-P3b: rescue 次数追踪
    rescue_count: int


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

    # L1-fix: recon_complete 移到 P2 多层提取之后, 避免事件统计恒为 0
    llm = _get_llm_client(task_id)


    # P2: 多层参数提取 (PageContentExtractor → Playwright → Link query fallback)
    page_contents: list[dict] = []
    try:
        import httpx
        from app.core.page_content_extractor import PageContentExtractor
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(target_url)
            extractor = PageContentExtractor(max_depth=2, max_pages=20)
            extracted = await extractor.extract(target_url, resp)
            for pc in extracted:
                for form in pc.forms:
                    if form.params:
                        recon_results.setdefault("forms", [])
                        recon_results["forms"].append({
                            "action": pc.url, "method": form.method,
                            "params": form.params, "form_fields": list(form.params),
                            "source": "page_extraction",
                        })
                    for pname in form.params:
                        recon_results.setdefault("parameters", [])
                        if not any(isinstance(p, dict) and p.get("name") == pname
                                   for p in recon_results["parameters"]):
                            recon_results["parameters"].append({
                                "name": pname, "url": pc.url, "source": "page_extraction",
                            })
            logger.info("PageContentExtractor: %d pages, %d forms, %d params",
                        len(extracted), len(recon_results.get("forms", [])),
                        len(recon_results.get("parameters", [])))
    except Exception as e:
        logger.warning("PageContentExtractor 失败 (非致命): %s", e)

    # P2 Layer2: Playwright 渲染提取表单 (PageContentExtractor 失败或表单少的回退)
    if len(recon_results.get("forms", [])) < 2:
        try:
            from app.core.playwright_manager import get_browser
            browser = get_browser()
            bctx = await browser.new_context(ignore_https_errors=True)
            page = await bctx.new_page()
            await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            pw_forms = await page.evaluate("""() => {
                return [...document.querySelectorAll('form')].map(f => ({
                    action: f.action || window.location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    inputs: [...f.querySelectorAll('input,textarea,select')]
                        .map(i => i.name || i.id).filter(Boolean)
                }));
            }""")
            for fm in (pw_forms or []):
                if fm.get("inputs"):
                    recon_results.setdefault("forms", [])
                    recon_results["forms"].append({
                        "action": fm["action"], "method": fm["method"],
                        "params": fm["inputs"], "form_fields": list(fm["inputs"]),
                        "source": "playwright",
                    })
                    for pname in fm["inputs"]:
                        recon_results.setdefault("parameters", [])
                        if not any(isinstance(p, dict) and p.get("name") == pname
                                   for p in recon_results["parameters"]):
                            recon_results["parameters"].append({
                                "name": pname, "url": target_url, "source": "playwright",
                            })
            await bctx.close()
            logger.info("Playwright: 提取 %d forms", len(pw_forms or []))
        except Exception as e:
            logger.warning("Playwright 表单提取失败: %s", e)

    # P2 Layer3: 从分类链接的 query string 提取参数
    if not recon_results.get("parameters"):
        categorized = recon_results.get("homepage_info", {}).get("categorized_links", {})
        for cat, items in categorized.items():
            for item in items:
                link = item.get("link", "")
                if "?" in link:
                    try:
                        from urllib.parse import parse_qs, urlparse
                        parsed = urlparse(link if "http" in link else f"http://x{link}")
                        for pname in parse_qs(parsed.query).keys():
                            recon_results.setdefault("parameters", [])
                            recon_results["parameters"].append({
                                "name": pname, "url": link, "source": "link_query",
                            })
                    except Exception:
                        pass

    # L1-fix: P2 兜底 — 若 tools 失败/Playwright 不可用, 用纯 HTTP 重抽表单
    if not recon_results.get("forms"):
        try:
            import httpx as _httpx
            from app.agents.nodes.orchestrator import _extract_forms as _xf
            async with _httpx.AsyncClient(timeout=15, follow_redirects=True) as _client:
                _resp = await _client.get(target_url)
                if _resp.status_code == 200 and _resp.text:
                    _fallback_forms = _xf(_resp.text)
                    for _fm in _fallback_forms:
                        _act = _fm.get("action") or ""
                        recon_results.setdefault("forms", [])
                        recon_results["forms"].append({
                            "action": _act, "method": _fm.get("method", "GET"),
                            "params": _fm.get("params", []),
                            "form_fields": _fm.get("form_fields", list(_fm.get("params", []))),
                            "source": "http_fallback",
                        })
                        for _pn in _fm.get("params", []):
                            recon_results.setdefault("parameters", [])
                            if not any(isinstance(_p, dict) and _p.get("name") == _pn
                                       for _p in recon_results["parameters"]):
                                recon_results["parameters"].append({
                                    "name": _pn, "url": target_url, "source": "http_fallback",
                                })
        except Exception as _e:
            logger.warning("HTTP 表单兜底提取失败: %s", _e)

    await emit(task_id, "lats_recon", "recon_complete", {
        "dirs_found": len(recon_results.get("directories", [])),
        "pages_crawled": len(recon_results.get("crawled_pages", [])),
        "params_found": len(recon_results.get("parameters", [])),
        "forms_found": len(recon_results.get("forms", [])),
        "tool_health": recon_results.get("tool_health", {}),
    })

    # P1: 将 PCE 提取的表单 action 注入 homepage_info.categorized_links
    for form in recon_results.get("forms", []):
        action = form.get("action", "")
        if action:
            homepage = recon_results.setdefault("homepage_info", {})
            cat_links = homepage.setdefault("categorized_links", {})
            cat_links.setdefault("form_handler", [])
            if not any(item.get("link") == action for item in cat_links["form_handler"]):
                cat_links["form_handler"].append({"link": action, "score": 0.75})

    # P2: 将 PCE 发现的所有 URL 合并到 homepage_info.links 并重新分类
    homepage = recon_results.get("homepage_info", {})
    existing_links = set(str(l) for l in homepage.get("links", []))
    for page in recon_results.get("crawled_pages", []):
        url = page.get("url", "") if isinstance(page, dict) else str(page)
        if url and url not in existing_links:
            existing_links.add(url)
    for p in recon_results.get("parameters", []):
        url = p.get("url", "") if isinstance(p, dict) else ""
        if url and url not in existing_links:
            existing_links.add(url)
    if existing_links:
        all_merged = list(existing_links)
        from app.agents.nodes.orchestrator import _classify_and_score_links
        merged_categorized = _classify_and_score_links(all_merged)
        homepage["categorized_links"] = {cat: items[:15] for cat, items in merged_categorized.items()}
        scored = []
        for cat_items in merged_categorized.values():
            scored.extend(cat_items)
        scored.sort(key=lambda x: x["score"], reverse=True)
        homepage["links"] = [item["link"] for item in scored[:50]]
        homepage["total_links"] = len(all_merged)
        recon_results["homepage_info"] = homepage
        logger.info("P2 链接合并: %d links → %d categorized types (%d vuln)",
                    len(all_merged), len(merged_categorized),
                    len(merged_categorized.get("vuln_page", [])))

    # P0: 工具驱动攻击面构造 — 替代 LLM
    from app.agents.lats.attack_surface_builder import build_attack_surface
    surface = await build_attack_surface(recon_results, target_url, task_id)

    # P0: LLM 仅提供策略建议
    endpoint_summary = []
    for ep in surface.endpoints[:25]:
        endpoint_summary.append({
            "path": ep["path"], "score": round(ep.get("score", 0), 2),
            "category": ep.get("category", "unknown"),
            "compatible_vulns": ep.get("compatible_vuln_types", [])[:5],
        })

    advice_messages = [
        {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps({
            "task_id": task_id, "target": target_url,
            "tech_indicators": surface.recon_summary.get("tech_indicators", []),
            "top_endpoints": endpoint_summary,
            "total_endpoints": surface.total_endpoints,
            "vuln_pages": surface.vuln_pages,
            "forms": surface.forms[:5],
        }, ensure_ascii=False)},
    ]

    response_text = await llm.call(agent="orchestrator", messages=advice_messages, task_id=task_id)
    try:
        decision = json.loads(response_text)
    except json.JSONDecodeError:
        try:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            decision = json.loads(response_text[start:end]) if start >= 0 else {}
        except Exception:
            decision = {}

    # 组装黑板 — 端点来自工具, 策略来自 LLM
    bb.target_profile = {
        "base_url": target_url,
        "tech_stack": decision.get("tech_stack", surface.recon_summary.get("tech_indicators", [])),
        "framework": decision.get("framework", ""),
        "server": decision.get("server", ""),
        "waf": decision.get("waf", ""),
        "recon_data": {
            "directories": recon_results.get("directories", [])[:50],
            "homepage_info": recon_results.get("homepage_info", {}),
            "tool_health": recon_results.get("tool_health", {}),
        },
    }

    bb.attack_surface = {
        "endpoints": surface.endpoints,  # ← 工具驱动, 非 LLM
        "parameters": surface.parameters,
        "forms": surface.forms,
    }
    bb.focus_vuln_types = decision.get("focus_vuln_types", [])

    # v2: 将端点录入 SharedKnowledge
    for ep_data in surface.endpoints[:50]:
        path = ep_data.get("path", "")
        if path and bb.shared_knowledge:
            try:
                import asyncio
                asyncio.ensure_future(
                    bb.shared_knowledge.record_endpoint(path=path, method="GET", source="recon")
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
            "data": {"endpoints": len(surface.endpoints)},
        }],
    }


# ──── v5: URL 语义解析 — 从 URL 路径推断参数和漏洞类型 ────

def _infer_vuln_from_path(path: str) -> list[str]:
    """从 URL 路径名推断可能的漏洞类型，不依赖参数发现 (P6: 配置路径约束)

    v2/L1-P1a: 委托给 path_semantics 单一真相源 — 治 R2 (原 kw_map 缺 "rce"
    关键字, 导致 /vul/rce/rce_ping.php 推不出 rce)。
    """
    from app.agents.lats.path_semantics import infer_vuln_from_path as _infer
    return _infer(path)


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


# ──── P6: 配置路径精确约束 ────
# L1-fix: 旧表用 `in` 子串匹配, '.git/'(带斜杠) 漏判 'foo.php/.git'(无斜杠)
# 导致 dir_scan 的 bogus 目录被 _infer_vuln_from_path 误判成 SQLi 端点。
# 改为正则, 版本控制目录以 .git/.svn/.hg/.bzr 后接 / 或字符串尾或 . 即匹配。
_CONFIG_PATH_PATTERNS_V2 = (
    '.gitconfig', '.gitignore', '.env', 'dockerfile', 'docker-compose',
    '.htaccess', '.htpasswd', 'robots.txt', 'sitemap', 'composer.lock',
    'package-lock', 'yarn.lock', 'Gemfile.lock', 'Pipfile.lock',
    '.DS_Store', 'web.config', 'web.xml', 'server.xml', 'thumbs.db',
    '.project', '.classpath', '.settings/', 'backup/', 'dump/',
    'phpinfo', 'info.php', 'test.php', 'readme', 'changelog',
    'license', 'copying',
)
# 版本控制目录正则 — 匹配 .git/.svn/.hg/.bzr (后跟 / 或 . 或字符串尾)
_VERSION_CONTROL_RE = re.compile(r'\.(git|svn|hg|bzr)(?:[/.]|$)')


def _is_config_path(path: str) -> bool:
    """P6: 判断是否为配置/静态文件路径 (仅允许 info_disclosure)

    v2/L1-P1a: 委托给 path_semantics 单一真相源。
    """
    from app.agents.lats.path_semantics import is_config_path
    return is_config_path(path)


# ──── P1: 端点预验证 ────

# 端点可访问性枚举
_ENDPOINT_ACCESSIBILITY: dict[int, str] = {
    200: "accessible",
    301: "redirect", 302: "redirect", 303: "redirect", 307: "redirect", 308: "redirect",
    401: "auth_required",
    403: "forbidden",
    404: "not_found",
    500: "server_error", 502: "server_error", 503: "server_error",
}

# 可访问性 → 允许的漏洞类型
_ACCESSIBILITY_VULN_TYPES: dict[str, list[str]] = {
    "accessible": [],   # 空列表 = 允许全部
    "redirect": ["open_redirect"],
    "auth_required": ["auth_bypass"],
    "forbidden": [],     # 空列表 = 不测试
    "not_found": [],     # 空列表 = 不测试
    "server_error": ["info_disclosure"],
    "timeout": [],
    "unknown": [],
}

# 可访问性 MCTS 权重
_ACCESSIBILITY_MCTS_WEIGHT: dict[str, float] = {
    "accessible": 1.0,
    "redirect": 0.7,
    "auth_required": 0.5,
    "server_error": 0.3,
    "forbidden": 0.0,
    "not_found": 0.0,
    "timeout": 0.0,
    "unknown": 0.3,
}


async def _prevalidate_endpoint(
    path: str,
    base_url: str,
    timeout: float = 5.0,
) -> dict:
    """P1: 端点预验证 — GET 探测并分类可访问性

    Returns:
        {"accessibility": str, "status": int, "response_time_ms": int,
         "content_type": str, "has_forms": bool, "is_config_path": bool}
    """
    import httpx
    full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
    result = {
        "accessibility": "unknown",
        "status": 0,
        "response_time_ms": 0,
        "content_type": "",
        "has_forms": False,
        "is_config_path": _is_config_path(path),
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            import time as _time
            start = _time.monotonic()
            resp = await client.get(full_url)
            elapsed_ms = int((_time.monotonic() - start) * 1000)
            result["status"] = resp.status_code
            result["response_time_ms"] = elapsed_ms
            result["content_type"] = resp.headers.get("content-type", "")
            result["accessibility"] = _ENDPOINT_ACCESSIBILITY.get(
                resp.status_code, "unknown"
            )
            # 检测是否含表单
            if resp.status_code == 200 and "text/html" in (resp.headers.get("content-type", "")):
                import re as _re
                result["has_forms"] = bool(_re.search(r'<form[\s>]', resp.text, _re.I))
    except Exception:
        result["accessibility"] = "timeout"
    return result


def _get_allowed_vuln_types(
    accessibility: str,
    is_config_path: bool,
    path: str = "",
) -> list[str] | None:
    """P1: 根据端点可访问性返回允许的漏洞类型列表 (None = 全部允许)"""
    # 配置路径: 仅 info_disclosure
    if is_config_path:
        return ["info_disclosure"]
    # forbidden/not_found/timeout: 空列表 = 禁止所有
    if accessibility in ("forbidden", "not_found", "timeout"):
        return []
    # 其余按可访问性限定
    allowed = _ACCESSIBILITY_VULN_TYPES.get(accessibility)
    if allowed is not None and len(allowed) == 0 and accessibility == "accessible":
        return None  # accessible → 无限制
    return allowed  # None 表示允许全部, [] 表示不允许


def _get_accessibility_mcts_weight(accessibility: str) -> float:
    """P1: 获取端点可访问性对应的 MCTS 选择权重"""
    return _ACCESSIBILITY_MCTS_WEIGHT.get(accessibility, 0.3)


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


# ──── v21: HDE 端点上下文初始化 ────

async def _init_endpoint_contexts(state: dict, bb, task_id: str, task_config: dict,
                                   attack_surface: dict, target_url: str,
                                   tech_stack: list, focus_vuln_types: list,
                                   scan_mode: str) -> dict:
    """初始化端点聚焦探索上下文 (替代 SearchTree 创建)"""
    import uuid as _uuid
    from .endpoint_explorer import EndpointExplorer, PerEndpointContext

    explorer = EndpointExplorer()
    url_inferred_vulns = _infer_vuln_from_path(
        target_url.split("?")[0]) if target_url else []

    # 收集端点列表
    endpoints = attack_surface.get("endpoints", [])
    if scan_mode == "single_page":
        parsed = __import__('urllib.parse', fromlist=['urlparse']).urlparse(target_url)
        target_path = parsed.path if parsed else "/"
        endpoints = [{"path": target_path, "params": [], "source": "target_url"}]

    for ep_data in endpoints[:20]:  # 最多 20 个端点
        if isinstance(ep_data, str):
            path = ep_data
            params = []
            source = "dir_scan"
        elif isinstance(ep_data, dict):
            path = ep_data.get("path", "")
            params = ep_data.get("params", [])
            source = ep_data.get("source", "dir_scan")
        else:
            continue
        if not path:
            continue

        # 跳过静态文件和版本控制路径
        if not _is_endpoint_injectable(path):
            continue

        # 路径暗示的漏洞类型
        path_hints = _infer_vuln_from_path(path) if path else []
        if not path_hints or path_hints == ["info_disclosure", "auth_bypass"]:
            path_hints = ["info_disclosure", "auth_bypass"]

        # 如果有 focus_vuln_types，优先这些类型
        if focus_vuln_types:
            path_hints = [vt for vt in focus_vuln_types if vt in path_hints] + path_hints

        ctx = PerEndpointContext(
            endpoint_id=str(_uuid.uuid4()),
            endpoint_path=path,
            full_url=target_url if scan_mode == "single_page"
                     else (target_url.rstrip("/") + "/" + path.lstrip("/")),
            source=source,
            path_hints=path_hints[:4],
            known_params=params if isinstance(params, list) else [],
        )
        explorer.add_context(ctx)

    logger.info("HDE endpoint init: %d contexts (mode=%s)", len(explorer.contexts), scan_mode)

    await emit(task_id, "lats_init", "endpoints_initialized", {
        "endpoints_count": len(explorer.contexts),
        "scan_mode": scan_mode,
        "focus_vuln_types": focus_vuln_types,
    })
    await emit(task_id, "lats_init", "agent_stopped", {"node": "init_tree"})

    return {
        "endpoint_explorer": explorer,
        "current_cycle": 0,
        "events": [{
            "id": str(_uuid.uuid4()),
            "agent": "lats_init",
            "type": "endpoints_initialized",
            "timestamp": __import__('datetime', fromlist=['datetime']).datetime.now(
                __import__('datetime', fromlist=['timezone']).timezone.utc).isoformat(),
            "data": {"endpoints_count": len(explorer.contexts)},
        }],
    }


# ──── Node: Init Tree (v2: 使用 SEED 状态) ────

async def lats_init_tree_node(state: dict) -> dict:
    """初始化搜索树 — 将攻击面转换为初始分支 (v2: 标记为 SEED)"""
    bb = state["blackboard"]
    task_id = state["task_id"]
    task_config = state.get("task_config", {}) or {}  # v18-fix
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

    # v19-fix: 如果 task_name 推断失败, 从 target_url 路径回退推断 focus_vuln_types
    if not focus_vuln_types:
        url_inferred_focus = _infer_vuln_from_path(target_path) if target_path else []
        if url_inferred_focus and url_inferred_focus != ["info_disclosure", "auth_bypass"]:
            focus_vuln_types = url_inferred_focus
            logger.info("focus_vuln_types inferred from URL path: %s", focus_vuln_types)
            bb.focus_vuln_types = focus_vuln_types
    is_single_page = bool(parsed_target and parsed_target.path and
                          any(parsed_target.path.lower().endswith(ext)
                              for ext in ('.php', '.asp', '.aspx', '.jsp', '.py', '.pl', '.cgi', '.do', '.action')))
    is_single_page = is_single_page or bool(parsed_target and parsed_target.query)
    scan_mode = "single_page" if is_single_page else "full_site"
    logger.info("init_tree scan_mode=%s target=%s", scan_mode, target_url)

    # P1: 批量端点预验证 (仅 full_site 模式)
    endpoint_meta_cache: dict[str, dict] = {}
    if scan_mode == "full_site":
        endpoints_raw = attack_surface.get("endpoints", [])
        paths_to_validate = set()
        for ep in endpoints_raw:
            path = ep if isinstance(ep, str) else ep.get("path", "")
            if path and path not in paths_to_validate:
                paths_to_validate.add(path)
        # 限制预验证数量
        paths_list = list(paths_to_validate)[:30]
        if paths_list:
            logger.info("P1: 预验证 %d 个端点...", len(paths_list))
            import asyncio as _asyncio_pre
            tasks = [_prevalidate_endpoint(p, target_url) for p in paths_list]
            results = await _asyncio_pre.gather(*tasks, return_exceptions=True)
            for path, result in zip(paths_list, results):
                if isinstance(result, dict):
                    endpoint_meta_cache[path] = result
                else:
                    endpoint_meta_cache[path] = {"accessibility": "timeout", "status": 0}
            accessible = sum(1 for m in endpoint_meta_cache.values() if m.get("accessibility") == "accessible")
            forbidden = sum(1 for m in endpoint_meta_cache.values() if m.get("accessibility") in ("forbidden", "not_found"))
            logger.info("P1: 预验证完成: accessible=%d, forbidden/404=%d, total=%d",
                        accessible, forbidden, len(results))

    await emit(task_id, "lats_init", "agent_started", {"node": "init_tree", "scan_mode": scan_mode})

    # v21: HDE 探索模式 — 从 state 读取
    exploration_mode = state.get("exploration_mode", "tree")
    if exploration_mode == "endpoint":
        return await _init_endpoint_contexts(state, bb, task_id, task_config,
                                              attack_surface, target_url, tech_stack,
                                              focus_vuln_types, scan_mode)

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
    # L2/PR-3 修复: 单页模式不能直接丢弃 attack_surface — 否则会丢掉表单来源的
    # http_method(POST) 与完整 form_fields, 导致 Level0 探针回退 GET 永远打不到 POST-only 注入点。
    # 改为: 从 attack_surface 中查找与目标路径匹配的端点, 继承其 method/form_fields/params。
    # 默认端点能力 (对 full_site 模式也适用)
    _cap_method = "GET"
    _cap_form_fields: list[str] = []
    _cap_params: list[str] = []

    if scan_mode == "single_page":
        _norm_target_path = target_path or "/"
        # L2-fix: 优先从 attack_surface["forms"] 直接查表单 — forms 是 ground truth,
        # 攻击面 endpoint 合并时 method/form_fields 易被无关来源覆盖成 GET/空。
        for _fm in attack_surface.get("forms", []) or []:
            if not isinstance(_fm, dict):
                continue
            _fma = _fm.get("action", "") or ""
            # 归一化 form action 到 path 比较
            if _fma.startswith("http"):
                _fma_path = urlparse(_fma).path or "/"
            elif _fma:
                _fma_path = _fma
            else:
                _fma_path = _norm_target_path  # 空 action 默认当前页
            if (_fma_path == _norm_target_path
                    or _fma_path.endswith(_norm_target_path)
                    or _norm_target_path.endswith(_fma_path)):
                _fm_method = str(_fm.get("method", "GET")).upper()
                if _fm_method == "POST":
                    _cap_method = "POST"
                _fm_fields = list(_fm.get("form_fields") or _fm.get("params") or [])
                for _ff in _fm_fields:
                    if _ff and _ff not in _cap_form_fields:
                        _cap_form_fields.append(_ff)
                    if _ff and _ff not in _cap_params:
                        _cap_params.append(_ff)
                logger.info("single_page form-authority: action=%s method=%s ff=%s",
                            _fma, _fm_method, _cap_form_fields)
        for _ep in attack_surface.get("endpoints", []):
            if not isinstance(_ep, dict):
                continue
            _ep_path = _ep.get("path", "")
            if _ep_path == _norm_target_path or _ep_path.endswith(_norm_target_path) or _norm_target_path.endswith(_ep_path):
                if _ep.get("http_method", "").upper() == "POST":
                    _cap_method = "POST"  # form 来源优先, 但需是 POST 才覆盖
                for _p in _ep.get("params", []):
                    if _p and _p not in _cap_params:
                        _cap_params.append(_p)
                for _f in _ep.get("form_fields", []):
                    if _f and _f not in _cap_form_fields:
                        _cap_form_fields.append(_f)
        # 确保目标 URL 本身作为端点被处理
        if target_path and target_path != "/":
            single_endpoints = [{
                "path": target_path,
                "params": list(_cap_params),
                "source": "target_url",
                "http_method": _cap_method,
                "form_fields": list(_cap_form_fields),
            }]
            # 从 query string 提取参数
            if parsed_target and parsed_target.query:
                from urllib.parse import parse_qs as _parse_qs
                try:
                    qs_params = list(_parse_qs(parsed_target.query).keys())
                    for _qp in qs_params:
                        if _qp not in single_endpoints[0]["params"]:
                            single_endpoints[0]["params"].append(_qp)
                    logger.info("single_page: extracted params from URL: %s", qs_params)
                except Exception:
                    pass
            logger.info("single_page: capability method=%s form_fields=%s params=%s",
                         _cap_method, _cap_form_fields, single_endpoints[0]["params"])
        else:
            single_endpoints = [{"path": target_path or "/", "params": list(_cap_params),
                                 "source": "target_url", "http_method": _cap_method,
                                 "form_fields": list(_cap_form_fields)}]
        endpoints_to_process = single_endpoints
        # L2/PR-3 修复: 单页目标默认视为可达 (它是任务目标), 并把表单能力写入
        # endpoint_meta_cache, 使主循环不因 accessibility=unknown 而整端点跳过。
        # v2/L0-P0b: 缓存 key 必须用 normalize 后的 path — 治 R1。
        # 旧实现 _sp = _se.get("path") 可能是完整 URL (target_url.split("?")[0]),
        # 而主循环 normalize_endpoint_path 后用纯 path 查找 → miss → 整端点跳过。
        from app.agents.lats.endpoint_normalizer import normalize_endpoint_path as _nep
        for _se in single_endpoints:
            _sp_raw = _se.get("path", "")
            _sp = _nep(_sp_raw) or _sp_raw
            if _sp:
                _se["path"] = _sp  # 同步回写, 保证主循环与 cache key 一致
                endpoint_meta_cache[_sp] = {
                    "accessibility": "accessible",
                    "status": 200,
                    "is_config_path": _is_config_path(_sp),
                    "has_forms": bool(_se.get("form_fields")),
                    # 保留 attack_surface 的 http_method/form_fields 供 default_meta 透传
                    "http_method": _se.get("http_method", "GET"),
                    "form_fields": list(_se.get("form_fields", [])),
                }
        # P1-2: 在 single_page 模式下，限制只测试 focus_vuln_types
        # 这样可以避免 Agent 被无关漏洞类型分散注意力
        logger.info("single_page: focus_vuln_types=%s, endpoints=%s", focus_vuln_types, [e['path'] for e in single_endpoints])
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

        # NEW: 入口处标准化 — 拒绝 LLM 幻觉路径
        from app.agents.lats.endpoint_normalizer import normalize_endpoint_path
        clean_path = normalize_endpoint_path(path)
        if clean_path is None:
            logger.warning("tree_init: 拒绝无效端点路径: %s", str(path)[:100])
            continue
        if clean_path != path:
            logger.info("tree_init: 标准化端点路径: %s → %s", path, clean_path)
            path = clean_path
            endpoint["path"] = clean_path

        # P1: 端点预验证过滤
        meta = endpoint_meta_cache.get(path, {})
        accessibility = meta.get("accessibility", "unknown")
        is_config = meta.get("is_config_path", _is_config_path(path))
        # v2/L1-P1b: fail-open — 对任务目标端点和表单来源端点, 预验证缺失
        # 不等于不可达 (治 R1: 一个 cache miss 整端点跳过)。
        # 仅对 dir_scan/crawled_page 来源的端点仍要求预验证通过。
        if accessibility == "unknown" and source in ("target_url", "form",
                                                       "page_extraction", "playwright",
                                                       "http_fallback"):
            accessibility = "accessible"
            try:
                await emit(task_id, "lats_init", "capability_fallback_used", {
                    "endpoint": path, "source": source,
                    "reason": "meta_cache_miss_fail_open",
                })
            except Exception:
                pass
        allowed_vulns = _get_allowed_vuln_types(accessibility, is_config, path)
        # allowed_vulns 为 [] 表示完全跳过此端点
        if allowed_vulns is not None and len(allowed_vulns) == 0:
            logger.debug("P1: 跳过端点 %s (accessibility=%s)", path, accessibility)
            continue

        # P1: 默认的 endpoint_metadata
        # L2/PR-3: 携带 http_method + form_fields 供 Level0 探针使用
        default_meta = {
            "accessibility": accessibility, "is_config_path": is_config,
            "status": meta.get("status", 0),
            "http_method": endpoint.get("http_method", "GET"),
            "form_fields": list(endpoint.get("form_fields", [])),
            "reachable": True,  # accessible/通过的端点均为可达
        }

        if not params:
            default_vulns = ["info_disclosure", "auth_bypass"]
            # P1: 如果有 allowed_vulns 且不为 None, 过滤
            if allowed_vulns is not None:
                default_vulns = [vt for vt in default_vulns if vt in allowed_vulns]
            if not default_vulns:
                continue
            for vtype in default_vulns:
                branch_key = f"{vtype}@{path}"
                if branch_key in seen_branches:
                    continue
                seen_branches.add(branch_key)
                # v2: 使用 capability 感知的估值
                cap = get_endpoint_capability_sync(path, target_url) if target_url else None
                if cap:
                    value = estimate_branch_value_v2(vtype, "", cap, source, focus_vuln_types)
                else:
                    value = estimate_branch_value(vtype, "", path, tech_stack, source, focus_vuln_types)
                value += _random.uniform(-0.05, 0.05)
                value = max(0.05, min(1.0, value))
                child = tree.create_child_node(
                    parent=root, action="explore",
                    action_params={"endpoint": path, "vuln_type": vtype},
                    vuln_type=vtype, endpoint=path, param=None,
                    value_estimate=value, created_at_cycle=0,
                )
                child.status = NodeStatus.SEED
                child.endpoint_metadata = dict(default_meta)
                branches_created += 1

        for param in params:
            param_name = param if isinstance(param, str) else param.get("name", "")
            vuln_types = infer_vuln_types(param_name, endpoint, tech_stack)
            # P1: 应用预验证约束
            if allowed_vulns is not None:
                vuln_types = [vt for vt in vuln_types if vt in allowed_vulns]
            # v21: 端点路径语义过滤
            path_hints = _infer_vuln_from_path(path) if path else []
            if path_hints and path_hints != ["info_disclosure", "auth_bypass"]:
                vuln_types = [vt for vt in vuln_types if vt in path_hints] or vuln_types[:1]
            if not vuln_types:
                continue
            for vtype in vuln_types:
                branch_key = f"{vtype}@{path}:{param_name}"
                if branch_key in seen_branches:
                    continue
                seen_branches.add(branch_key)
                # v2: 使用 capability 感知的估值
                cap = get_endpoint_capability_sync(path, target_url) if target_url else None
                if cap:
                    value = estimate_branch_value_v2(vtype, param_name, cap, source, focus_vuln_types)
                else:
                    value = estimate_branch_value(vtype, param_name, path, tech_stack, source, focus_vuln_types)
                value += _random.uniform(-0.05, 0.05)
                value = max(0.05, min(1.0, value))
                child = tree.create_child_node(
                    parent=root, action="explore",
                    action_params={"endpoint": path, "param": param_name, "vuln_type": vtype},
                    vuln_type=vtype, endpoint=path, param=param_name,
                    value_estimate=value, created_at_cycle=0,
                )
                child.status = NodeStatus.SEED
                child.endpoint_metadata = dict(default_meta)
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
                cap = get_endpoint_capability_sync(path, target_url) if target_url else None
                value = estimate_branch_value_v2(vtype, pname, cap, "url_inferred", focus_vuln_types) if cap else estimate_branch_value(vtype, pname, path, tech_stack, "url_inferred", focus_vuln_types)
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
    # v19-fix: 使用 endpoints_to_process 而非 attack_surface.endpoints, 避免单页模式下为 dir_scan 结果创建无关分支
    fallback_params = ["id", "q", "file", "url", "cmd", "name", "page"]
    for endpoint_data in endpoints_to_process[:10]:
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
                # P1-2: 如果有 focus_vuln_types, 不为不相关的 vuln_type 创建分支
                if focus_vuln_types and vt not in focus_vuln_types:
                    continue
                # v21: 路径语义过滤 — 路径明确时跳过不匹配的 vuln_type
                fb_path_hints = _infer_vuln_from_path(path) if path else []
                if fb_path_hints and fb_path_hints != ["info_disclosure", "auth_bypass"]:
                    if vt not in fb_path_hints:
                        continue
                bk = f"{vt}@{path}:{fb_param}"
                if bk in seen_branches:
                    continue
                cap = get_endpoint_capability_sync(path, target_url) if target_url else None
                if cap and not is_vuln_type_compatible(vt, cap):
                    continue  # v2: 不兼容 → 跳过
                val = max(0.3, estimate_branch_value_v2(vt, fb_param, cap, "fallback", focus_vuln_types) if cap else estimate_branch_value(vt, fb_param, path, tech_stack, "fallback", focus_vuln_types) - 0.15)
                val += _random.uniform(-0.03, 0.03)
                child = tree.create_child_node(
                    parent=root, action="explore_fallback",
                    action_params={"endpoint": path, "param": fb_param, "vuln_type": vt},
                    vuln_type=vt, endpoint=path, param=fb_param,
                    value_estimate=max(0.1, min(1.0, val)), created_at_cycle=0,
                )
                child.status = NodeStatus.LOW_SIGNAL  # 低优先级, 预算宽松时执行
                # L2/PR-3: 透传端点能力 (method/form_fields) 给 Level0 探针
                _fb_ep = endpoint_data if isinstance(endpoint_data, dict) else {}
                child.endpoint_metadata = dict(endpoint_meta_cache.get(path, {
                    "accessibility": "accessible", "is_config_path": _is_config_path(path),
                    "status": 0,
                    "http_method": _fb_ep.get("http_method", "GET"),
                    "form_fields": list(_fb_ep.get("form_fields", [])),
                    "reachable": True,
                }))
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
        # L2/PR-3: 继承单页端点能力 (POST method/form_fields)
        child.endpoint_metadata = dict(endpoint_meta_cache.get(target_path, {
            "accessibility": "accessible", "is_config_path": _is_config_path(target_path),
            "status": 0, "http_method": _cap_method, "form_fields": list(_cap_form_fields),
            "reachable": True,
        }))
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
    bb = state.get("blackboard", None)  # P1-1: 获取 blackboard 以访问 shared_knowledge
    pool = _get_executor_pool()
    cycle = state.get("current_cycle", 0)

    await emit(task_id, "lats_mcts", "agent_started", {"node": "mcts_select", "cycle": cycle})

    # v21: HDE 端点模式 — 使用 EndpointSelector 替代 MCTS select_batch
    exploration_mode = state.get("exploration_mode", "tree")
    if exploration_mode == "endpoint":
        explorer = state.get("endpoint_explorer")
        if explorer is not None:
            from .endpoint_selector import EndpointSelector
            selector = EndpointSelector(
                focus_vuln_types=bb.focus_vuln_types if hasattr(bb, 'focus_vuln_types') else None
            )
            active = explorer.get_active_contexts()
            if not active:
                await emit(task_id, "lats_mcts", "agent_stopped", {"node": "mcts_select"})
                return {"selected_nodes": [], "events": []}
            selected_ctxs = selector.select_top_k(active, k=batch_size)
            # 将 PerEndpointContext 映射回 selected_nodes (兼容下游节点)
            selected_ids = [ctx.endpoint_id for ctx in selected_ctxs]
            selected_info = [ctx.to_dict() for ctx in selected_ctxs]
            await emit(task_id, "lats_mcts", "endpoints_selected", {
                "count": len(selected_ctxs), "endpoints": selected_info,
                "mode": "endpoint",
            })
            await emit(task_id, "lats_mcts", "agent_stopped", {"node": "mcts_select"})
            return {
                "selected_nodes": selected_ids,
                "events": [{
                    "id": str(uuid.uuid4()),
                    "agent": "lats_mcts",
                    "type": "endpoints_selected",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": {"count": len(selected_ctxs), "endpoints": selected_info},
                }],
            }

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
        knowledge=bb.shared_knowledge if hasattr(bb, 'shared_knowledge') and bb.shared_knowledge else None,  # P1-1: 传入 knowledge
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
    base_url_full = target_profile.get("base_url", "")
    parsed = urlparse(base_url_full)
    host = parsed.hostname or "localhost"
    # L2-fix: Level0 探针的 base_url 用 origin(scheme://netloc), 而非完整
    # target_url — 否则 _build_url 把 path 拼到含文件名的 base 之后, 产生
    # "sqli_id.php/vul/sqli/sqli_id.php" 这类 bogus 双重路径。
    base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else base_url_full

    context = ExecutionContext(
        task_id=task_id,
        target_host=host,
        timeout=30,
        max_retries=2,
        allowed_hosts=[host],
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

            # v2/L4-P4b: 节点级诊断卡片 — 每个被探测的 SEED 输出可观测事件
            _meta = node.endpoint_metadata or {}
            _sig_matches = pr.signals.get("_signal_matches", [])
            _sig_summary = [{"type": m.type, "conf": m.confidence, "vt": m.vuln_type} for m in _sig_matches[:3]]
            try:
                await emit(task_id, "lats_react", "node_diagnostic", {
                    "node_id": node.id[:8], "path": node.state.current_endpoint,
                    "http_method": _meta.get("http_method", "GET"),
                    "form_fields": _meta.get("form_fields", []),
                    "param": node.state.current_param, "vuln_type": node.state.vuln_type,
                    "probe_count": len(node.probe_results), "verdict": pr.verdict,
                    "kill_reason": pr.error if pr.verdict == "killed" else "",
                    "signals_matched": _sig_summary,
                    "baseline_length": pr.baseline_length, "inject_length": pr.inject_length,
                    "reachable": _meta.get("reachable", False),
                })
            except Exception:
                pass

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
    llm = _get_llm_client(task_id)

    # v22: 将 SharedKnowledge 注入到每个节点的 state 中 (供跨Agent知识共享)
    if bb.shared_knowledge and nodes:
        for n in nodes:
            n.state._shared_knowledge = bb.shared_knowledge

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

    # 3. 执行扩展 (P2-3: 传入 knowledge + llm 以启用 LLM 辅助扩展)
    llm = _get_llm_client(task_id)
    expansion_result = await engine.expand(
        tree=tree,
        discoveries=unique_discoveries,
        current_cycle=cycle,
        base_url=target_url,
        knowledge=knowledge,
        llm=llm,
        task_id=task_id,
    )


    # 4. [v3] 节点复活: 检查 Graveyard 中是否有节点可以因新发现而复活
    resurrection_engine = NodeResurrectionEngine(max_resurrections_per_cycle=3)
    resurrected = resurrection_engine.check_resurrection(
        tree=tree,
        new_discoveries=unique_discoveries,
        shared_knowledge=knowledge,
        current_cycle=cycle,
    )
    if resurrected:
        expansion_result["resurrected"] = expansion_result.get("resurrected", 0) + len(resurrected)
    tree_stats = tree.stats()

    await emit(task_id, "lats_expand", "expansion_complete", {
        **expansion_result,
        "tree_stats": tree_stats,
        "graveyard": tree.get_graveyard_stats(),
        "knowledge_summary": knowledge.get_summary() if knowledge else {},
    })

    await emit(task_id, "lats_expand", "agent_stopped", {"node": "expand"})

    # P1-3: 删除重复的 engine.expand() 调用 (原 L907-L924)
    # 原代码在此处重复调用 engine.expand(), 导致重复创建分支和重复事件

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
        "_last_explored": tree_stats.get("explored", 0),
        "events": [{
            "id": str(uuid.uuid4()),
            "agent": "lats_eval",
            "type": "cycle_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"cycle": cycle + 1, "findings": total_findings, "tree": tree_stats},
        }],
    }


# ──── Routing (v2) ────

# v2/L3-P3a: 最小 dry gate — 至少 2 个 dry cycle 才允许直接报告,
# 避免 cycle1 全 killed 即转报告 (治 R5)。rescue 节点在此期间重建攻击面。
MIN_DRY_BEFORE_REPORT = 2


def route_from_evaluate(state: dict) -> str:
    """评估节点的路由决策 (v2: dry gate + rescue + Graveyard 复活)

    v2/L3-P3a: 新增 MIN_DRY_BEFORE_REPORT 门禁 — dry_cycles < 阈值时
    不直接报告, 改走 rescue 重建攻击面 (治 R5: cycle1 全 killed 即报告)。
    v2/L3-P3b: 新增 rescue 路由分支。
    """
    tree = state.get("search_tree")
    cycle = int(state.get("current_cycle", 0) or 0)
    max_cycles = int(state.get("max_cycles", 15) or 15)
    dry_cycles = int(state.get("dry_cycles", 0) or 0)
    bb = state.get("blackboard")
    expansion_stats = state.get("expansion_stats") or {}
    # v2/L3-P3b: rescue 次数追踪
    rescue_count = int(state.get("rescue_count", 0) or 0)
    rescue_cap = 2  # rescue 最多 2 次

    # 硬上限: 达到最大周期 → 报告
    if cycle >= max_cycles:
        logger.info("达到最大搜索周期 (%d)，进入报告", max_cycles)
        return "reporter"

    # v2/L3-P3a: dry gate — 全树探索完但 dry 不足 + 有可救节点 → rescue
    if tree:
        all_done, has_resurrectable = tree._exploration_status()
        if all_done:
            # Graveyard 有可救节点且未用完 rescue 配额 → continue (复活)
            if has_resurrectable and expansion_stats.get("resurrected", 0) > 0:
                logger.info("Graveyard 中有节点被复活，继续搜索")
                return "continue"
            # dry 不足 + rescue 配额未满 → rescue 重建攻击面 (治 R5)
            budget_exhausted = cycle >= max_cycles * 0.8
            if (dry_cycles < MIN_DRY_BEFORE_REPORT
                    and rescue_count < rescue_cap
                    and not budget_exhausted):
                logger.info("全树探索完但 dry_cycles=%d < %d, 进入 rescue (第 %d 次)",
                            dry_cycles, MIN_DRY_BEFORE_REPORT, rescue_count + 1)
                return "rescue"
            logger.info("搜索树已全部探索 (dry=%d, rescue=%d/%d)，进入报告",
                        dry_cycles, rescue_count, rescue_cap)
            return "reporter"

    if dry_cycles >= 3:
        max_val = tree.max_unexplored_value() if tree else 0
        if max_val < 0.3:
            logger.info("连续 %d 轮无发现且最高价值 %.2f，进入报告", dry_cycles, max_val)
            return "reporter"
        # v20-fix: 同时检查是否真的还有新探索发生 (消灭闲置空转)
        new_branches = expansion_stats.get("new_branches", 0)
        tree_stats_now = tree.stats() if tree else {}
        explored_now = tree_stats_now.get("explored", 0)
        last_explored = state.get("_last_explored", 0)
        if dry_cycles >= 5 and explored_now == last_explored and new_branches == 0:
            logger.info("连续 %d 轮无新探索(explored=%d, new_branches=%d)，进入报告",
                         dry_cycles, explored_now, new_branches)
            return "reporter"

    if bb:
        high_findings = [f for f in bb.findings if f.severity in ("critical", "high")]
        if len(high_findings) >= 8:
            logger.info("已有 %d 个高危发现，进入报告", len(high_findings))
            return "reporter"

    return "continue"


async def lats_rescue_node(state: dict) -> dict:
    """v2/L3-P3b: 救援节点 — 全树 dry 时重建攻击面/重播种 POST SEED。

    触发条件 (route_from_evaluate 返回 "rescue"):
    1. dry_cycles≥1 且 explored==0 且 findings==0 (RCE 任务正是此情形)
    2. dry_cycles≥2 且 new_branches==0 且 budget>40%

    动作:
    1. 重新侦察 — 对 reachable 端点用纯 HTTP 表单解析器重抓 forms/params
    2. 方法论切换 — 对 reachable 端点按 http_method 维度重建 SEED (补 POST SEED)
    3. 定向注入 — 跳过 Level0, 直接用 SignalDetector 梯度载荷集
    4. 重播种带 cap — rescue 最多 2 次, 总新增分支 ≤ 6
    """
    tree: SearchTree = state["search_tree"]
    bb = state["blackboard"]
    task_id = state["task_id"]
    task_config = state.get("task_config", {}) or {}
    target_url = bb.target_profile.get("base_url", "") if bb.target_profile else ""
    focus_vuln_types = bb.focus_vuln_types or task_config.get("focus_vuln_types", [])
    rescue_count = int(state.get("rescue_count", 0) or 0)

    await emit(task_id, "lats_rescue", "agent_started", {
        "node": "rescue", "rescue_count": rescue_count + 1,
        "findings": len(bb.findings),
    })

    # 动作 1: 重新侦察 — 重抓目标页表单 (Level0 可能因 GET 误判错过 POST 表单)
    new_branches = 0
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url)
            if resp.status_code == 200 and resp.text:
                from app.agents.nodes.orchestrator import _extract_forms
                re_forms = _extract_forms(resp.text)
                for fm in re_forms:
                    action = fm.get("action", "") or target_url
                    if action.startswith("http"):
                        from urllib.parse import urlparse as _pu
                        _ap = _pu(action)
                        action = _ap.path or "/"
                    method = str(fm.get("method", "GET")).upper()
                    fields = fm.get("form_fields") or fm.get("params") or []
                    if not fields:
                        continue
                    # 动作 2: 为每个表单字段重建 SEED (POST 优先)
                    from app.agents.lats.path_semantics import infer_vuln_from_param
                    root = tree.get_root()
                    if root is None:
                        break
                    seen_keys = {f"{n.state.vuln_type}@{action}:{p}"
                                 for n in tree.nodes.values() if n.state.current_endpoint == action}
                    for field in fields[:3]:
                        inferred_types = infer_vuln_from_param(field)
                        if focus_vuln_types:
                            inferred_types = [vt for vt in inferred_types if vt in focus_vuln_types] or inferred_types[:1]
                        for vt in inferred_types[:2]:
                            bk = f"{vt}@{action}:{field}"
                            if bk in seen_keys:
                                continue
                            seen_keys.add(bk)
                            child = tree.create_child_node(
                                parent=root, action="rescue_reseed",
                                action_params={"endpoint": action, "param": field, "vuln_type": vt},
                                vuln_type=vt, endpoint=action, param=field,
                                value_estimate=0.6, created_at_cycle=state.get("current_cycle", 0),
                            )
                            child.status = NodeStatus.SEED
                            child.endpoint_metadata = {
                                "accessibility": "accessible", "is_config_path": False,
                                "status": 200, "http_method": method,
                                "form_fields": list(fields), "reachable": True,
                            }
                            new_branches += 1
                            if new_branches >= 6:  # 重播种 cap
                                break
                        if new_branches >= 6:
                            break
                    if new_branches >= 6:
                        break
    except Exception as e:
        logger.warning("rescue 重新侦察失败: %s", str(e)[:120])

    # 动作 3: 从 graveyard 复活 reachable 节点
    resurrected = 0
    for nid, node in list(tree.graveyard.items()):
        if (node.endpoint_metadata or {}).get("reachable", False) and resurrected < 3:
            node.status = NodeStatus.SEED
            node.probe_level = 0
            node.probe_results = []
            node.value_estimate = max(0.3, node.value_estimate)
            del tree.graveyard[nid]
            resurrected += 1

    await emit(task_id, "lats_rescue", "rescue_complete", {
        "new_branches": new_branches, "resurrected": resurrected,
        "rescue_count": rescue_count + 1,
    })

    tree_stats = tree.stats()
    logger.info("rescue 完成: %d 新分支, %d 复活 (total_nodes=%d)",
                new_branches, resurrected, tree_stats.get("total_nodes", 0))

    return {
        "search_tree": tree,
        "blackboard": bb,
        "rescue_count": rescue_count + 1,
        "events": [{
            "id": str(uuid.uuid4()),
            "agent": "lats_rescue",
            "type": "rescue_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"new_branches": new_branches, "resurrected": resurrected},
        }],
    }


async def lats_pre_reporter_node(state: dict) -> dict:
    """桥接节点 — 将 LATS 状态映射为 reporter 兼容格式"""
    return {
        "iteration_count": state.get("current_cycle", 0),
        "current_phase": "reporting",
    }


# ──── Graph Builder (v2) ────

def build_lats_graph():
    """构建 LATS + ReAct + 动态扩展 + 知识库的 LangGraph 图

    v2/L3-P3b: 新增 rescue 节点 — 全树 dry 时重建攻击面/重播种 POST SEED。
    """
    from app.agents.nodes.reporter import reporter_node

    graph = StateGraph(LATSState)

    graph.add_node("recon", lats_recon_node)
    graph.add_node("init_tree", lats_init_tree_node)
    graph.add_node("mcts_select", lats_mcts_select_node)
    graph.add_node("react_execute", lats_react_execute_node)
    graph.add_node("expand", lats_expand_node)  # v2
    graph.add_node("evaluate", lats_evaluate_node)
    graph.add_node("rescue", lats_rescue_node)  # v2/L3-P3b: 救援节点
    graph.add_node("pre_reporter", lats_pre_reporter_node)
    graph.add_node("reporter", reporter_node)

    graph.set_entry_point("recon")

    graph.add_edge("recon", "init_tree")
    graph.add_edge("init_tree", "mcts_select")
    graph.add_edge("mcts_select", "react_execute")
    graph.add_edge("react_execute", "expand")  # v2: execute → expand
    graph.add_edge("expand", "evaluate")        # v2: expand → evaluate
    graph.add_edge("rescue", "mcts_select")     # v2/L3-P3b: rescue → 重选

    graph.add_conditional_edges(
        "evaluate", route_from_evaluate,
        {"continue": "mcts_select", "rescue": "rescue", "reporter": "pre_reporter"},
    )

    graph.add_edge("pre_reporter", "reporter")
    graph.add_edge("reporter", END)

    compiled = graph.compile()
    logger.info("LATS v2 漏洞挖掘图构建完成 (自适应选择 + 动态扩展 + 共享知识库 + rescue)")
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

    # v21: HDE 探索模式 — 从 task_config 读取, 默认 "tree"(兼容旧行为)
    exploration_mode = task_config.get("exploration_mode",
                        task_config.get("config", {}).get("exploration_mode", "tree"))

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
        "current_phase": "initializing",
        "exploration_mode": exploration_mode,
        "endpoint_explorer": None,
        "rescue_count": 0,  # v2/L3-P3b
    }
