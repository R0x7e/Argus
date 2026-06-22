"""
Orchestrator 节点

LangGraph 图中的总指挥节点。负责：
1. 首次运行时调用侦察工具（子域名枚举、端口扫描、目录扫描）分析目标
2. 将工具结果交给 LLM 生成结构化目标画像和攻击面
3. 评估当前进度，决定下一步行动
4. 当达到最大迭代或有足够发现时，决定结束
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.agents.prompts.orchestrator import ORCHESTRATOR_SYSTEM_PROMPT
from app.agents.state import SlotStatus, VulnHuntState
from app.tools.base import ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

_llm_client: LLMClient | None = None


def _extract_links(html: str) -> list[str]:
    """从 HTML 中提取所有链接路径"""
    import re
    links = set()
    for match in re.finditer(r'(?:href|action|src)=["\']([^"\'#]+)["\']', html, re.IGNORECASE):
        link = match.group(1)
        if link.startswith(("javascript:", "mailto:", "data:")):
            continue
        if link.startswith("/") or (not link.startswith("http") and "." in link):
            links.add(link.split("?")[0])
        elif link.startswith("http"):
            links.add(link)
    return sorted(links)


def _extract_forms(html: str) -> list[dict]:
    """从 HTML 中提取表单信息（action + 参数名）"""
    import re
    forms = []
    form_pattern = re.compile(
        r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
        re.IGNORECASE | re.DOTALL,
    )
    input_pattern = re.compile(
        r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    method_pattern = re.compile(r'method=["\']([^"\']+)["\']', re.IGNORECASE)

    for form_match in form_pattern.finditer(html):
        action = form_match.group(1)
        form_body = form_match.group(2)
        method_m = method_pattern.search(form_match.group(0))
        method = method_m.group(1).upper() if method_m else "GET"
        params = input_pattern.findall(form_body)
        if action or params:
            forms.append({
                "action": action,
                "method": method,
                "params": params,
            })
    return forms


def _extract_params_from_links(links: list[str]) -> list[dict]:
    """从 URL 列表中提取参数名"""
    from urllib.parse import parse_qs, urlparse
    params = []
    for link in links:
        if "?" not in link and "=" not in link:
            continue
        try:
            parsed = urlparse(link) if link.startswith("http") else urlparse(f"http://x{link}")
            qs = parse_qs(parsed.query)
            for name in qs:
                params.append({"url": link.split("?")[0], "name": name, "sample_value": qs[name][0]})
        except Exception:
            continue
    return params


def _get_llm_client() -> LLMClient:
    """获取或创建 LLM 客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def _build_execution_context(state: VulnHuntState) -> ExecutionContext:
    """从状态中构建工具执行上下文"""
    task_id = state["task_id"]
    bb = state["blackboard"]

    # 从 task_config 或 target_profile 中提取目标 URL
    task_config = state.get("task_config", {}) or {}
    target_url = task_config.get("target_url", "")

    if not target_url and bb.target_profile:
        target_url = bb.target_profile.get("base_url", "")

    parsed = urlparse(target_url)
    host = parsed.hostname or "localhost"

    return ExecutionContext(
        task_id=task_id,
        target_host=host,
        timeout=60,
        max_retries=2,
        allowed_hosts=[host],
    )


async def _run_recon_tool(tool_name: str, params: dict, context: ExecutionContext) -> dict:
    """安全执行侦察工具，捕获异常"""
    from app.tools import tool_registry

    tool = tool_registry.get(tool_name)
    if tool is None:
        return {"success": False, "error": f"工具 {tool_name} 未注册"}

    if tool.risk_level > RiskLevel.L0:
        return {"success": False, "error": f"侦察阶段仅允许 L0 工具，{tool_name} 为 {tool.risk_level.name}"}

    try:
        result = await tool.execute(params, context)
        return result
    except Exception as e:
        logger.warning("侦察工具 %s 执行异常: %s", tool_name, str(e))
        return {"success": False, "error": str(e)}


async def _run_reconnaissance(state: VulnHuntState) -> dict:
    """
    执行侦察阶段：对目标 URL 进行深度侦察

    SRC 模式下不做子域名枚举和端口扫描，但增加：
    1. 目录扫描 + 首页探测（第一层）
    2. 递归抓取首页链接（第二层，最多 15 个页面）
    3. 收集所有发现的参数名和表单
    """
    import asyncio
    import re

    context = _build_execution_context(state)
    target_host = context.target_host
    task_config = state.get("task_config", {}) or {}
    target_url = task_config.get("target_url", f"http://{target_host}")

    recon_results = {
        "subdomains": [],
        "open_ports": [],
        "directories": [],
        "homepage_info": {},
        "crawled_pages": [],
        "parameters": [],
        "forms": [],
        "tools_run": [],
        "errors": [],
    }

    # === 第一层：目录扫描 + 首页请求 ===
    tasks = [
        _run_recon_tool("dir_scan", {"base_url": target_url}, context),
        _run_recon_tool("http_request", {"url": target_url, "method": "GET"}, context),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 处理目录扫描结果
    dir_result = results[0]
    if isinstance(dir_result, dict) and dir_result.get("success"):
        found_paths = dir_result.get("found_paths", [])
        recon_results["directories"] = [p.get("path", p) if isinstance(p, dict) else p for p in found_paths]
        recon_results["tools_run"].append("dir_scan")
    elif isinstance(dir_result, dict):
        recon_results["errors"].append(f"dir_scan: {dir_result.get('error', 'unknown')}")

    # 处理首页请求结果
    homepage_result = results[1]
    all_links = []
    if isinstance(homepage_result, dict) and homepage_result.get("success"):
        body = homepage_result.get("body", "") or ""
        links = _extract_links(body)
        all_links = links[:]
        # 提取页面中的表单和参数
        forms = _extract_forms(body)
        params = _extract_params_from_links(links)
        recon_results["homepage_info"] = {
            "status_code": homepage_result.get("status_code"),
            "headers": homepage_result.get("headers", {}),
            "body_preview": body[:3000],
            "links": links[:50],
        }
        recon_results["forms"] = forms
        recon_results["parameters"] = params
        recon_results["tools_run"].append("http_request")
    elif isinstance(homepage_result, dict):
        recon_results["errors"].append(f"http_request: {homepage_result.get('error', 'unknown')}")

    # === 第二层：递归抓取发现的链接（最多 15 个） ===
    crawl_targets = []
    base_parsed = urlparse(target_url)
    for link in all_links[:15]:
        if link.startswith("/"):
            full_url = f"{base_parsed.scheme}://{base_parsed.netloc}{link}"
        elif link.startswith("http"):
            full_url = link
        else:
            full_url = f"{target_url.rstrip('/')}/{link}"
        # 只爬同域页面，跳过静态资源
        if base_parsed.netloc not in full_url:
            continue
        if re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|ttf|pdf|zip)$', full_url, re.I):
            continue
        crawl_targets.append(full_url)

    if crawl_targets:
        crawl_tasks = [
            _run_recon_tool("http_request", {"url": url, "method": "GET"}, context)
            for url in crawl_targets[:15]
        ]
        crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)

        for i, cr in enumerate(crawl_results):
            if isinstance(cr, dict) and cr.get("success"):
                page_body = cr.get("body", "") or ""
                page_links = _extract_links(page_body)
                page_forms = _extract_forms(page_body)
                page_params = _extract_params_from_links(page_links)
                recon_results["crawled_pages"].append({
                    "url": crawl_targets[i],
                    "status": cr.get("status_code"),
                    "links_count": len(page_links),
                    "forms_count": len(page_forms),
                })
                # 合并新发现的链接和参数
                for link in page_links:
                    if link not in all_links:
                        all_links.append(link)
                recon_results["forms"].extend(page_forms)
                recon_results["parameters"].extend(page_params)

        recon_results["tools_run"].append("recursive_crawl")

    # 去重参数
    seen_params = set()
    unique_params = []
    for p in recon_results["parameters"]:
        key = f"{p.get('url', '')}:{p.get('name', '')}"
        if key not in seen_params:
            seen_params.add(key)
            unique_params.append(p)
    recon_results["parameters"] = unique_params[:100]

    # 更新 homepage_info 中的 links 为完整集合
    recon_results["homepage_info"]["all_discovered_links"] = all_links[:100]

    logger.info(
        "侦察完成: %d 目录, %d 页面已爬取, %d 参数, %d 表单",
        len(recon_results["directories"]),
        len(recon_results["crawled_pages"]),
        len(recon_results["parameters"]),
        len(recon_results["forms"]),
    )

    return recon_results


async def orchestrator_node(state: VulnHuntState) -> dict:
    """
    总指挥节点

    根据黑板当前状态做出调度决策：
    - 若目标画像为空 → 调用侦察工具 + LLM 创建画像和攻击面
    - 若已有验证结果 → 评估进度，决定继续还是生成报告
    - 若达到最大迭代次数 → 转入报告阶段
    """
    bb = state["blackboard"]
    iteration = state["iteration_count"]
    max_iter = state["max_iterations"]
    task_id = state["task_id"]

    logger.info(
        "Orchestrator 启动 - 任务 [%s], 迭代 %d/%d",
        task_id,
        iteration,
        max_iter,
    )

    events = []

    await emit(task_id, "orchestrator", "agent_started", {
        "node": "orchestrator", "iteration": iteration,
    })

    # ---- 场景 1: 首次运行，目标画像为空 → 侦察 + 分析 ----
    if not bb.target_profile:
        logger.info("目标画像为空，执行侦察阶段...")

        await emit(task_id, "orchestrator", "tool_call", {
            "tool_name": "reconnaissance_suite",
            "params": {"tools": ["dir_scan", "http_request"]},
        })

        # 执行侦察工具
        recon_results = await _run_reconnaissance(state)

        await emit(task_id, "orchestrator", "tool_result", {
            "tool_name": "reconnaissance_suite",
            "success": True,
            "summary": f"发现 {len(recon_results['directories'])} 目录, "
                       f"{len(recon_results.get('crawled_pages', []))} 页面已爬取, "
                       f"{len(recon_results.get('parameters', []))} 参数, "
                       f"{len(recon_results.get('forms', []))} 表单",
        })

        recon_event_data = {
            "tools_run": recon_results["tools_run"],
            "dirs_found": len(recon_results["directories"]),
            "pages_crawled": len(recon_results.get("crawled_pages", [])),
            "params_found": len(recon_results.get("parameters", [])),
            "forms_found": len(recon_results.get("forms", [])),
            "homepage_status": recon_results["homepage_info"].get("status_code"),
            "errors": recon_results["errors"],
        }
        await emit(task_id, "orchestrator", "recon_complete", recon_event_data)
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "orchestrator",
            "type": "recon_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": recon_event_data,
        })

        # 将工具结果交给 LLM 生成结构化画像
        task_config = state.get("task_config", {}) or {}
        target_url = task_config.get("target_url", "")

        await emit(task_id, "orchestrator", "thinking", {
            "content": "正在分析侦察数据，生成目标画像和攻击面...",
        })

        messages = [
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"这是一个新的 SRC 漏洞挖掘任务 (ID: {task_id})。目标: {target_url}\n\n"
                f"以下是对目标的侦察结果：\n"
                f"- 发现目录/路径: {json.dumps(recon_results['directories'][:30], ensure_ascii=False)}\n"
                f"- 页面内链接: {json.dumps(recon_results['homepage_info'].get('links', [])[:40], ensure_ascii=False)}\n"
                f"- 首页响应头: {json.dumps(dict(list(recon_results['homepage_info'].get('headers', {}).items())[:15]), ensure_ascii=False)}\n"
                f"- 首页内容预览: {recon_results['homepage_info'].get('body_preview', '')[:1500]}\n"
                f"- 爬取页面数: {len(recon_results.get('crawled_pages', []))}\n"
                f"- 发现参数: {json.dumps(recon_results.get('parameters', [])[:30], ensure_ascii=False)}\n"
                f"- 发现表单: {json.dumps(recon_results.get('forms', [])[:15], ensure_ascii=False)}\n\n"
                f"请基于以上侦察数据，分析目标的技术栈和潜在攻击面。\n"
                f"注意：这是 SRC 精准漏洞挖掘，不要建议子域名枚举或端口扫描。\n"
                f"重点关注：\n"
                f"1. 发现的参数和表单（最可能存在注入漏洞）\n"
                f"2. 目录扫描中发现的敏感路径\n"
                f"3. 响应头暴露的技术栈信息\n"
                f"输出 JSON 格式，包含 target_profile, attack_surface, strategy, next_action 字段。"
            )},
        ]

        llm = _get_llm_client()
        response_text = await llm.call(agent="orchestrator", messages=messages)
        decision = _parse_orchestrator_response(response_text)

        await emit(task_id, "orchestrator", "progress", {
            "content": f"目标画像生成完成，策略: {decision.get('strategy', 'unknown')}",
            "step": "target_profiling",
        })

        # 更新黑板 —— 融合工具实际结果 + LLM 分析
        target_profile = decision.get("target_profile", {})
        target_profile["base_url"] = target_url
        target_profile["recon_data"] = {
            "directories": recon_results["directories"][:50],
            "homepage_info": recon_results["homepage_info"],
        }
        bb.target_profile = target_profile

        attack_surface = decision.get("attack_surface", {})
        existing_endpoints = attack_surface.get("endpoints", [])
        tool_endpoints = [{"path": d, "source": "dir_scan"} for d in recon_results["directories"][:20]]
        # 添加带参数的端点（高价值目标）
        param_endpoints = [
            {"path": p["url"], "params": [p["name"]], "source": "crawl"}
            for p in recon_results.get("parameters", [])[:30]
        ]
        # 添加表单端点
        form_endpoints = [
            {"path": f["action"], "method": f["method"], "params": f["params"], "source": "form"}
            for f in recon_results.get("forms", [])[:15]
            if f.get("action")
        ]
        attack_surface["endpoints"] = existing_endpoints + tool_endpoints + param_endpoints + form_endpoints
        attack_surface["parameters"] = recon_results.get("parameters", [])[:50]
        attack_surface["forms"] = recon_results.get("forms", [])[:20]
        bb.attack_surface = attack_surface

        bb.slot_status["target_profile"] = SlotStatus.READY
        bb.slot_status["attack_surface"] = SlotStatus.READY
        bb.version += 1

        profiled_data = {
            "target_profile": bb.target_profile,
            "attack_surface_endpoints": len(attack_surface.get("endpoints", [])),
            "strategy": decision.get("strategy", "comprehensive_scan"),
            "next_action": "hypothesize",
        }
        await emit(task_id, "orchestrator", "target_profiled", profiled_data)
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "orchestrator",
            "type": "target_profiled",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": profiled_data,
        })

        logger.info(
            "目标画像创建完成 (基于工具侦察), 策略: %s, 攻击面端点: %d",
            decision.get("strategy"),
            len(attack_surface.get("endpoints", [])),
        )

        await emit(task_id, "orchestrator", "agent_stopped", {"node": "orchestrator"})

        return {
            "blackboard": bb,
            "current_phase": "hypothesizing",
            "iteration_count": iteration,
            "events": events,
        }

    # ---- 场景 2: 达到最大迭代次数 → 结束 ----
    if iteration >= max_iter:
        logger.info("已达最大迭代次数 (%d)，转入报告阶段", max_iter)

        max_iter_data = {
            "iteration": iteration,
            "max_iterations": max_iter,
            "findings_count": len(bb.findings),
        }
        await emit(task_id, "orchestrator", "max_iterations_reached", max_iter_data)
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "orchestrator",
            "type": "max_iterations_reached",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": max_iter_data,
        })

        await emit(task_id, "orchestrator", "agent_stopped", {"node": "orchestrator"})

        return {
            "blackboard": bb,
            "current_phase": "reporting",
            "iteration_count": iteration,
            "events": events,
        }

    # ---- 场景 3: 有验证结果 → 评估进度 ----
    findings_count = len(bb.findings)
    pending_hypotheses = [h for h in bb.hypotheses if h.status == "pending"]
    tested_hypotheses = [h for h in bb.hypotheses if h.status in ("confirmed", "rejected")]

    # 检测连续无新发现的轮次
    if findings_count > bb.last_findings_count:
        bb.dry_rounds = 0
    else:
        bb.dry_rounds += 1
    bb.last_findings_count = findings_count

    # 连续 2 轮无新发现 → 自动结束
    if bb.dry_rounds >= 2 and findings_count > 0:
        logger.info("连续 %d 轮无新发现，转入报告阶段", bb.dry_rounds)
        await emit(task_id, "orchestrator", "decision", {
            "next_action": "report",
            "reasoning": f"连续 {bb.dry_rounds} 轮无新发现，攻击面已基本穷尽",
            "iteration": iteration,
            "findings_count": findings_count,
        })
        await emit(task_id, "orchestrator", "agent_stopped", {"node": "orchestrator"})
        return {
            "blackboard": bb,
            "current_phase": "reporting",
            "iteration_count": iteration,
            "events": events,
        }

    progress_context = {
        "iteration": iteration,
        "max_iterations": max_iter,
        "findings_count": findings_count,
        "pending_hypotheses": len(pending_hypotheses),
        "tested_hypotheses": len(tested_hypotheses),
        "total_hypotheses": len(bb.hypotheses),
        "rejected_count": len(bb.rejected_hypotheses),
        "false_positives_count": len(bb.false_positives),
        "target_profile": bb.target_profile,
    }

    await emit(task_id, "orchestrator", "thinking", {
        "content": f"评估进度: {findings_count} 发现, {len(pending_hypotheses)} 待验证假设...",
    })

    messages = [
        {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"当前任务进度评估：\n"
            f"{json.dumps(progress_context, ensure_ascii=False, default=str)}\n\n"
            f"请决定下一步行动：\n"
            f"- 如果还有未验证假设，继续验证\n"
            f"- 如果需要更多假设，生成新假设\n"
            f"- 如果已有足够发现或迭代已满，生成报告\n"
            f"请输出 JSON 格式的决策。"
        )},
    ]

    llm = _get_llm_client()
    response_text = await llm.call(agent="orchestrator", messages=messages)
    decision = _parse_orchestrator_response(response_text)

    next_action = decision.get("next_action", "hypothesize")
    reasoning = decision.get("reasoning", "")

    if next_action in ("report", "done"):
        phase = "reporting"
    elif next_action in ("hypothesize", "recon"):
        phase = "hypothesizing"
    else:
        phase = "verifying"

    bb.version += 1

    decision_data = {
        "next_action": next_action,
        "reasoning": reasoning,
        "iteration": iteration,
        "findings_count": findings_count,
    }
    await emit(task_id, "orchestrator", "decision", decision_data)
    events.append({
        "id": str(uuid.uuid4()),
        "agent": "orchestrator",
        "type": "decision",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": decision_data,
    })

    logger.info(
        "Orchestrator 决策: next_action=%s, phase=%s, 推理=%s",
        next_action,
        phase,
        reasoning[:100],
    )

    await emit(task_id, "orchestrator", "agent_stopped", {"node": "orchestrator"})

    return {
        "blackboard": bb,
        "current_phase": phase,
        "iteration_count": iteration,
        "events": events,
    }


def _parse_orchestrator_response(response_text: str) -> dict:
    """解析 Orchestrator LLM 响应为字典，解析失败返回安全默认值"""
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass

    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(response_text[start:end])
    except json.JSONDecodeError:
        pass

    logger.warning("无法解析 Orchestrator 响应，使用默认决策: %s", response_text[:200])
    return {
        "target_profile": {"tech_stack": ["unknown"]},
        "strategy": "comprehensive_scan",
        "next_action": "hypothesize",
        "reasoning": "响应解析失败，使用默认策略",
    }
