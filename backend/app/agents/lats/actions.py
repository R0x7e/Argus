"""
LATS 动作空间定义和执行映射

定义 ReAct Agent 可执行的所有原子动作类型，
以及将高层动作映射到底层工具调用的执行逻辑。
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from app.tools.base import ExecutionContext

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    # 侦察类
    CRAWL_PAGE = "crawl_page"
    DISCOVER_PARAMS = "discover_params"
    FINGERPRINT = "fingerprint"

    # 注入测试类
    INJECT_PAYLOAD = "inject_payload"
    MUTATE_PAYLOAD = "mutate_payload"
    PROBE_FILTER = "probe_filter"

    # 认证类
    TEST_NO_AUTH = "test_no_auth"
    TEST_IDOR = "test_idor"
    FORGE_TOKEN = "forge_token"

    # 深挖类
    ESCALATE = "escalate"
    CHAIN_VULN = "chain_vuln"
    EXTRACT_DATA = "extract_data"

    # 控制类
    BACKTRACK = "backtrack"
    REPORT_FINDING = "report_finding"
    GIVE_UP = "give_up"

    # 浏览器 & 高级侦察类
    RENDER_PAGE = "render_page"
    INTERACT_PAGE = "interact_page"
    DEEP_CRAWL = "deep_crawl"
    ANALYZE_TRAFFIC = "analyze_traffic"
    RUN_POC = "run_poc"


@dataclass
class Observation:
    """动作执行后的观察结果"""
    success: bool = False
    summary: str = ""

    # HTTP 响应信息
    status_code: int = 0
    response_body: str = ""
    response_headers: dict = field(default_factory=dict)
    response_time_ms: int = 0

    # 漏洞相关
    vuln_confirmed: bool = False
    severity: str = ""
    finding: dict = field(default_factory=dict)

    # 信息发现
    new_facts: list[str] = field(default_factory=list)
    new_info_gained: bool = False

    # 异常信号
    status_code_anomaly: bool = False
    response_time_anomaly: bool = False
    error_message_leaked: bool = False
    waf_blocked: bool = False
    same_as_baseline: bool = False
    endpoint_404: bool = False

    # 工具层
    tool_call: dict = field(default_factory=dict)

    # 变异相关
    next_payload: str = ""
    filter_rules: dict = field(default_factory=dict)


def _build_inject_url(url: str, param: str, payload: str, method: str = "GET") -> dict:
    """构造注入请求参数"""
    if method.upper() == "GET":
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        return {"url": full_url, "method": "GET", "follow_redirects": False}
    else:
        return {
            "url": url,
            "method": "POST",
            "body": f"{param}={payload}",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "follow_redirects": False,
        }


async def execute_action(
    action_type: str,
    params: dict,
    context: ExecutionContext,
    state: Any = None,
) -> Observation:
    """将 ReAct Agent 的高层动作映射到底层工具调用"""
    from app.tools import tool_registry

    try:
        action = ActionType(action_type)
    except ValueError:
        return Observation(success=False, summary=f"未知动作类型: {action_type}")

    try:
        if action == ActionType.INJECT_PAYLOAD:
            return await _execute_inject(params, context, tool_registry)
        elif action == ActionType.MUTATE_PAYLOAD:
            return await _execute_mutate(params, context, tool_registry)
        elif action == ActionType.PROBE_FILTER:
            return await _execute_probe_filter(params, context, tool_registry)
        elif action == ActionType.CRAWL_PAGE:
            return await _execute_crawl(params, context, tool_registry)
        elif action == ActionType.DISCOVER_PARAMS:
            return await _execute_discover_params(params, context, tool_registry)
        elif action == ActionType.FINGERPRINT:
            return await _execute_fingerprint(params, context, tool_registry)
        elif action == ActionType.TEST_NO_AUTH:
            return await _execute_no_auth(params, context, tool_registry)
        elif action == ActionType.TEST_IDOR:
            return await _execute_idor(params, context, tool_registry)
        elif action == ActionType.FORGE_TOKEN:
            return await _execute_forge_token(params, context, tool_registry)
        elif action == ActionType.EXTRACT_DATA:
            return await _execute_extract_data(params, context, tool_registry)
        elif action in (ActionType.BACKTRACK, ActionType.REPORT_FINDING, ActionType.GIVE_UP):
            return Observation(success=True, summary=f"控制动作: {action.value}")
        elif action == ActionType.RENDER_PAGE:
            return await _execute_render_page(params, context, tool_registry)
        elif action == ActionType.INTERACT_PAGE:
            return await _execute_interact_page(params, context, tool_registry)
        elif action == ActionType.DEEP_CRAWL:
            return await _execute_deep_crawl(params, context, tool_registry)
        elif action == ActionType.ANALYZE_TRAFFIC:
            return await _execute_analyze_traffic(params, context, tool_registry)
        elif action == ActionType.RUN_POC:
            return await _execute_run_poc(params, context, tool_registry)
        else:
            return Observation(success=False, summary=f"动作 {action.value} 尚未实现")
    except Exception as e:
        logger.error("动作执行异常 [%s]: %s", action_type, str(e))
        return Observation(success=False, summary=f"执行异常: {str(e)}")


async def _execute_inject(params: dict, context: ExecutionContext, registry) -> Observation:
    """注入 payload 并分析响应"""
    url = params.get("url", "")
    param = params.get("param", "")
    payload = params.get("payload", "")
    method = params.get("method", "GET")

    if not url or not param or not payload:
        return Observation(success=False, summary="inject_payload 缺少必要参数 (url/param/payload)")

    req_params = _build_inject_url(url, param, payload, method)
    tool = registry.get("http_request")
    result = await tool.execute(req_params, context)

    if not result.get("success"):
        return Observation(
            success=False,
            summary=f"请求失败: {result.get('error', 'unknown')}",
            tool_call={"tool": "http_request", "params": req_params, "result": result},
        )

    body = result.get("body", "") or ""
    status = result.get("status_code", 0)
    headers = result.get("headers", {})
    time_ms = result.get("response_time_ms", 0)

    obs = Observation(
        success=True,
        status_code=status,
        response_body=body[:2000],
        response_headers=headers,
        response_time_ms=time_ms,
        tool_call={"tool": "http_request", "params": req_params, "result": {"status_code": status, "body_len": len(body)}},
    )

    # 分析响应异常
    obs.status_code_anomaly = status in (500, 502, 503)
    obs.response_time_anomaly = time_ms > 3000
    obs.endpoint_404 = status == 404
    obs.waf_blocked = status == 403 or _is_waf_response(body)

    # 检测错误信息泄露
    error_patterns = [
        "sql syntax", "mysql", "postgresql", "ora-", "sqlite",
        "traceback", "exception", "stack trace", "debug",
        "undefined variable", "unexpected token",
    ]
    if any(p in body.lower() for p in error_patterns):
        obs.error_message_leaked = True
        obs.new_info_gained = True
        obs.new_facts.append(f"错误信息泄露: status={status}")

    # 检测 payload 反射
    if payload in body:
        obs.new_info_gained = True
        obs.new_facts.append(f"Payload 在响应中原样反射 (param={param})")

    # 检测关键指标
    _detect_vuln_indicators(obs, payload, body, status, headers, time_ms)

    obs.summary = (
        f"status={status}, time={time_ms}ms, "
        f"body_len={len(body)}, "
        f"{'REFLECTED' if payload in body else ''} "
        f"{'ERROR_LEAKED' if obs.error_message_leaked else ''} "
        f"{'WAF_BLOCKED' if obs.waf_blocked else ''} "
        f"{'VULN_CONFIRMED' if obs.vuln_confirmed else ''}"
    ).strip()

    return obs


def _detect_vuln_indicators(obs: Observation, payload: str, body: str, status: int, headers: dict, time_ms: int):
    """检测各类漏洞确认指标"""
    body_lower = body.lower()

    # LFI/Path Traversal
    lfi_indicators = ["root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:", "[boot loader]", "[extensions]"]
    if any(ind in body for ind in lfi_indicators):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "lfi", "evidence": "文件内容泄露", "payload": payload}
        obs.new_facts.append("LFI 确认: 系统文件内容出现在响应中")

    # XSS (reflected)
    xss_indicators = ["<script>alert(", "onerror=alert(", "<svg/onload=", "ontoggle=alert(", "<img src=x onerror="]
    if any(ind in body for ind in xss_indicators):
        obs.vuln_confirmed = True
        obs.severity = "medium"
        obs.finding = {"type": "xss", "evidence": "XSS payload 反射", "payload": payload}
        obs.new_facts.append("XSS 确认: payload 在响应中原样执行")

    # SSTI
    if "49" in body and "{{7*7}}" not in body and "${7*7}" not in body and ("7*7" in payload or "config" in payload):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "ssti", "evidence": "模板表达式被执行", "payload": payload}
        obs.new_facts.append("SSTI 确认: 表达式计算结果出现在响应中")
    if "SECRET_KEY" in body or ("DEBUG" in body and "True" in body):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "ssti", "evidence": "配置信息泄露", "payload": payload}

    # RCE
    rce_indicators = ["uid=", "gid=", "www-data", "root:x:0"]
    if any(ind in body for ind in rce_indicators):
        obs.vuln_confirmed = True
        obs.severity = "critical"
        obs.finding = {"type": "rce", "evidence": "命令执行输出", "payload": payload}
        obs.new_facts.append("RCE 确认: 命令执行结果出现在响应中")

    # SQL Injection (error-based)
    sqli_errors = ["sql syntax", "mysql_fetch", "unclosed quotation", "you have an error in your sql",
                   "pg_query", "ora-01756", "sqlite3.operationalerror"]
    if any(e in body_lower for e in sqli_errors):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "sql_injection", "evidence": "SQL 错误信息", "payload": payload}
        obs.new_facts.append("SQLi 确认 (error-based): SQL 错误消息出现在响应中")

    # SQL Injection (time-based)
    if time_ms > 3000 and ("sleep" in payload.lower() or "pg_sleep" in payload.lower() or "waitfor" in payload.lower()):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "sql_injection", "evidence": f"时间延迟 {time_ms}ms", "payload": payload}
        obs.new_facts.append(f"SQLi 确认 (time-based): 响应延迟 {time_ms}ms")

    # Open Redirect
    location = headers.get("location", "") or headers.get("Location", "")
    if "evil.com" in location and status in (301, 302, 303, 307, 308):
        obs.vuln_confirmed = True
        obs.severity = "medium"
        obs.finding = {"type": "open_redirect", "evidence": f"重定向到 {location}", "payload": payload}

    # Info Disclosure
    sensitive_patterns = ["password", "secret", "api_key", "private_key", "AWS_SECRET",
                          "DB_PASSWORD", "MYSQL_PASSWORD", "[core]", "repositoryformatversion"]
    if status == 200 and len(body) > 50 and any(p.lower() in body_lower for p in sensitive_patterns):
        obs.vuln_confirmed = True
        obs.severity = "medium"
        obs.finding = {"type": "info_disclosure", "evidence": "敏感信息泄露", "payload": payload}
        obs.new_facts.append("信息泄露确认: 敏感数据出现在响应中")


def _is_waf_response(body: str) -> bool:
    """检测是否为 WAF 拦截响应"""
    waf_indicators = [
        "access denied", "blocked", "forbidden", "security violation",
        "waf", "firewall", "not acceptable", "request rejected",
        "cloudflare", "ddos protection",
    ]
    body_lower = body.lower()
    return any(ind in body_lower for ind in waf_indicators)


async def _execute_mutate(params: dict, context: ExecutionContext, registry) -> Observation:
    """变异 payload 以绕过过滤"""
    original = params.get("original", "")
    technique = params.get("technique", "url_encode")

    if not original:
        return Observation(success=False, summary="mutate_payload 缺少 original 参数")

    tool = registry.get("payload_mutate")
    result = await tool.execute({"payload": original, "mutations": [technique]}, context)

    mutated_list = result.get("mutated_payloads", [])
    if mutated_list:
        mutated = mutated_list[0] if isinstance(mutated_list[0], str) else str(mutated_list[0])
    else:
        mutated = original

    return Observation(
        success=True,
        summary=f"变异完成: {technique} → {mutated[:80]}",
        new_info_gained=True,
        new_facts=[f"生成变异 payload ({technique}): {mutated[:80]}"],
        next_payload=mutated,
        tool_call={"tool": "payload_mutate", "params": params, "result": result},
    )


async def _execute_probe_filter(params: dict, context: ExecutionContext, registry) -> Observation:
    """探测过滤规则"""
    url = params.get("url", "")
    param = params.get("param", "")
    chars = params.get("chars", ["<", ">", "'", '"', "/", "\\", ";", "|", "(", ")", "{", "}"])

    if not url or not param:
        return Observation(success=False, summary="probe_filter 缺少 url/param")

    tool = registry.get("http_request")
    blocked = []
    allowed = []

    # 先发一个 baseline 请求
    baseline_params = _build_inject_url(url, param, "normaltest123", "GET")
    baseline_result = await tool.execute(baseline_params, context)
    baseline_status = baseline_result.get("status_code", 0)
    baseline_body_len = len(baseline_result.get("body", ""))

    for char in chars[:12]:
        test_value = f"test{char}probe"
        req = _build_inject_url(url, param, test_value, "GET")
        result = await tool.execute(req, context)

        test_status = result.get("status_code", 0)
        test_body = result.get("body", "")

        if test_status == 403 or _is_waf_response(test_body):
            blocked.append(char)
        elif test_status == baseline_status:
            allowed.append(char)
        else:
            blocked.append(char)

    return Observation(
        success=True,
        summary=f"过滤规则探测: blocked={blocked}, allowed={allowed}",
        new_info_gained=True,
        new_facts=[
            f"被过滤字符: {blocked}",
            f"允许字符: {allowed}",
        ],
        filter_rules={"blocked": blocked, "allowed": allowed},
        tool_call={"tool": "http_request", "params": {"probe_filter": True}, "result": {"blocked": blocked, "allowed": allowed}},
    )


async def _execute_crawl(params: dict, context: ExecutionContext, registry) -> Observation:
    """抓取页面内容"""
    import re

    url = params.get("url", "")
    if not url:
        return Observation(success=False, summary="crawl_page 缺少 url")

    tool = registry.get("http_request")
    result = await tool.execute({"url": url, "method": "GET"}, context)

    if not result.get("success"):
        return Observation(success=False, summary=f"抓取失败: {result.get('error')}", endpoint_404=result.get("status_code") == 404)

    body = result.get("body", "") or ""
    status = result.get("status_code", 0)

    # 提取链接
    links = set()
    for match in re.finditer(r'(?:href|action|src)=["\']([^"\'#]+)["\']', body, re.IGNORECASE):
        link = match.group(1)
        if not link.startswith(("javascript:", "mailto:", "data:")):
            links.add(link)

    # 提取表单参数
    form_params = re.findall(r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE)

    new_facts = []
    if links:
        new_facts.append(f"发现 {len(links)} 个链接")
    if form_params:
        new_facts.append(f"发现表单参数: {form_params[:10]}")

    return Observation(
        success=True,
        summary=f"status={status}, links={len(links)}, forms={len(form_params)}",
        status_code=status,
        response_body=body[:1500],
        new_info_gained=bool(links or form_params),
        new_facts=new_facts,
        tool_call={"tool": "http_request", "params": {"url": url}, "result": {"links": list(links)[:20], "params": form_params}},
    )


async def _execute_discover_params(params: dict, context: ExecutionContext, registry) -> Observation:
    """参数发现 — 通过常见参数名字典探测"""
    url = params.get("url", "")
    if not url:
        return Observation(success=False, summary="discover_params 缺少 url")

    common_params = [
        "id", "page", "q", "search", "query", "name", "user", "username",
        "email", "file", "path", "url", "redirect", "next", "callback",
        "action", "cmd", "type", "category", "sort", "order", "limit",
        "offset", "token", "key", "api_key", "debug", "test", "admin",
    ]

    tool = registry.get("http_request")

    # Baseline
    baseline = await tool.execute({"url": url, "method": "GET"}, context)
    baseline_len = len(baseline.get("body", ""))
    baseline_status = baseline.get("status_code", 0)

    discovered = []
    sep = "&" if "?" in url else "?"

    for p in common_params[:20]:
        test_url = f"{url}{sep}{p}=test123"
        result = await tool.execute({"url": test_url, "method": "GET"}, context)
        test_len = len(result.get("body", ""))
        test_status = result.get("status_code", 0)

        if test_status == baseline_status and abs(test_len - baseline_len) > 50:
            discovered.append(p)
        elif test_status != baseline_status and test_status not in (404, 403):
            discovered.append(p)

    return Observation(
        success=True,
        summary=f"参数发现: {discovered}" if discovered else "未发现有效参数",
        new_info_gained=bool(discovered),
        new_facts=[f"发现有效参数: {discovered}"] if discovered else [],
        tool_call={"tool": "http_request", "params": {"discover": True}, "result": {"found_params": discovered}},
    )


async def _execute_fingerprint(params: dict, context: ExecutionContext, registry) -> Observation:
    """技术栈指纹识别"""
    url = params.get("url", "")
    if not url:
        return Observation(success=False, summary="fingerprint 缺少 url")

    tool = registry.get("http_request")
    result = await tool.execute({"url": url, "method": "GET"}, context)

    if not result.get("success"):
        return Observation(success=False, summary="指纹识别请求失败")

    headers = result.get("headers", {})
    body = result.get("body", "") or ""
    facts = []

    # 从 headers 提取
    server = headers.get("server", "") or headers.get("Server", "")
    if server:
        facts.append(f"Server: {server}")

    x_powered = headers.get("x-powered-by", "") or headers.get("X-Powered-By", "")
    if x_powered:
        facts.append(f"X-Powered-By: {x_powered}")

    # 框架检测
    if "laravel" in body.lower() or "laravel_session" in str(headers):
        facts.append("Framework: Laravel (PHP)")
    elif "django" in body.lower() or "csrfmiddlewaretoken" in body:
        facts.append("Framework: Django (Python)")
    elif "spring" in body.lower() or "whitelabel error" in body.lower():
        facts.append("Framework: Spring Boot (Java)")
    elif "express" in str(headers).lower():
        facts.append("Framework: Express (Node.js)")
    elif "asp.net" in str(headers).lower():
        facts.append("Framework: ASP.NET")

    return Observation(
        success=True,
        summary=f"指纹: {', '.join(facts)}" if facts else "未识别到明确技术栈",
        new_info_gained=bool(facts),
        new_facts=facts,
        tool_call={"tool": "http_request", "params": {"url": url}, "result": {"fingerprint": facts}},
    )


async def _execute_no_auth(params: dict, context: ExecutionContext, registry) -> Observation:
    """无认证访问测试"""
    url = params.get("url", "")
    if not url:
        return Observation(success=False, summary="test_no_auth 缺少 url")

    tool = registry.get("http_request")
    result = await tool.execute({"url": url, "method": "GET", "follow_redirects": False}, context)

    status = result.get("status_code", 0)
    body = result.get("body", "") or ""

    obs = Observation(
        success=True,
        status_code=status,
        response_body=body[:1000],
        tool_call={"tool": "http_request", "params": {"url": url, "no_auth": True}, "result": {"status": status}},
    )

    if status == 200 and len(body) > 100:
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "auth_bypass", "evidence": f"无认证访问返回 200 (body={len(body)} bytes)", "url": url}
        obs.new_facts.append(f"未授权访问确认: {url} 无需认证即可访问")
        obs.summary = f"AUTH_BYPASS: {url} 返回 200 无需认证"
    elif status in (401, 403):
        obs.new_facts.append(f"{url} 需要认证 (status={status})")
        obs.summary = f"需要认证: status={status}"
    else:
        obs.new_facts.append(f"{url} 返回 status={status}")
        obs.summary = f"status={status}, body_len={len(body)}"

    return obs


async def _execute_idor(params: dict, context: ExecutionContext, registry) -> Observation:
    """IDOR 枚举测试"""
    url = params.get("url", "")
    param = params.get("param", "id")
    ids = params.get("ids", ["1", "2", "0", "999", "admin"])

    if not url:
        return Observation(success=False, summary="test_idor 缺少 url")

    tool = registry.get("http_request")
    responses = []

    for test_id in ids[:6]:
        req = _build_inject_url(url, param, str(test_id), "GET")
        result = await tool.execute(req, context)
        responses.append({
            "id": test_id,
            "status": result.get("status_code", 0),
            "body_len": len(result.get("body", "")),
            "body_preview": (result.get("body", "") or "")[:200],
        })

    # 分析：如果不同 ID 返回不同数据（200 + 不同 body）= IDOR
    successful = [r for r in responses if r["status"] == 200 and r["body_len"] > 50]
    unique_bodies = len(set(r["body_preview"] for r in successful))

    obs = Observation(
        success=True,
        tool_call={"tool": "http_request", "params": {"idor_test": True}, "result": {"responses": responses}},
    )

    if unique_bodies >= 2:
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "idor", "evidence": f"{unique_bodies} 不同用户数据可访问", "param": param, "url": url}
        obs.new_facts.append(f"IDOR 确认: 参数 {param} 可遍历不同用户数据")
        obs.summary = f"IDOR 确认: {unique_bodies} 个不同响应"
    elif successful:
        obs.new_facts.append(f"端点接受 {param} 参数，返回数据")
        obs.summary = f"端点有效但响应相同 (可能非 IDOR)"
    else:
        obs.summary = "IDOR 未确认: 请求失败或被拒绝"

    return obs


async def _execute_forge_token(params: dict, context: ExecutionContext, registry) -> Observation:
    """JWT/Token 伪造测试"""
    import base64
    import json as json_mod

    url = params.get("url", "")
    technique = params.get("technique", "none_algorithm")

    if not url:
        return Observation(success=False, summary="forge_token 缺少 url")

    tool = registry.get("http_request")

    forged_tokens = []
    if technique == "none_algorithm":
        # JWT with alg:none
        header = base64.urlsafe_b64encode(json_mod.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json_mod.dumps({"sub": "admin", "role": "admin"}).encode()).rstrip(b"=").decode()
        forged_tokens.append(f"{header}.{payload}.")
    elif technique == "empty_password":
        forged_tokens.append("admin")

    obs = Observation(success=True, tool_call={"tool": "http_request", "params": {"forge_token": technique}})

    for token in forged_tokens:
        result = await tool.execute({
            "url": url,
            "method": "GET",
            "headers": {"Authorization": f"Bearer {token}"},
            "follow_redirects": False,
        }, context)

        status = result.get("status_code", 0)
        body = result.get("body", "") or ""

        if status == 200 and len(body) > 100:
            obs.vuln_confirmed = True
            obs.severity = "critical"
            obs.finding = {"type": "auth_bypass", "evidence": f"伪造 token 成功访问 ({technique})", "url": url, "token": token[:50]}
            obs.new_facts.append(f"Token 伪造成功: {technique}")
            obs.summary = f"AUTH_BYPASS via {technique}: status=200"
            break
        else:
            obs.new_facts.append(f"Token 伪造 ({technique}) 失败: status={status}")

    if not obs.vuln_confirmed:
        obs.summary = f"Token 伪造未成功 ({technique})"

    return obs


async def _execute_extract_data(params: dict, context: ExecutionContext, registry) -> Observation:
    """数据提取 — 验证漏洞影响"""
    url = params.get("url", "")
    payload = params.get("payload", "")
    method = params.get("method", "GET")

    if not url:
        return Observation(success=False, summary="extract_data 缺少 url")

    tool = registry.get("http_request")
    req_params = {"url": url, "method": method, "follow_redirects": False}
    if payload:
        req_params["body"] = payload

    result = await tool.execute(req_params, context)
    body = result.get("body", "") or ""
    status = result.get("status_code", 0)

    return Observation(
        success=result.get("success", False),
        status_code=status,
        response_body=body[:2000],
        summary=f"数据提取: status={status}, body_len={len(body)}",
        new_info_gained=len(body) > 100,
        new_facts=[f"提取数据 {len(body)} bytes"] if len(body) > 100 else [],
        tool_call={"tool": "http_request", "params": req_params, "result": {"status": status, "len": len(body)}},
    )


async def _execute_render_page(params: dict, context: ExecutionContext, registry) -> Observation:
    """使用 Playwright 渲染页面，提取 JS 动态内容"""
    url = params.get("url", "")
    if not url:
        return Observation(success=False, summary="render_page 缺少 url")

    tool = registry.get("browser_request")
    result = await tool.execute({
        "url": url,
        "wait_for": params.get("wait_for", "networkidle"),
        "extract_links": True,
        "extract_forms": True,
    }, context)

    if not result.get("success"):
        return Observation(success=False, summary=f"渲染失败: {result.get('error', '')}")

    links = result.get("links", [])
    forms = result.get("forms", [])
    new_facts = []
    if links:
        new_facts.append(f"JS 渲染发现 {len(links)} 个链接")
    if forms:
        new_facts.append(f"JS 渲染发现 {len(forms)} 个表单")

    return Observation(
        success=True,
        summary=f"渲染完成: links={len(links)}, forms={len(forms)}",
        response_body=result.get("content_snippet", "")[:2000],
        new_info_gained=bool(links or forms),
        new_facts=new_facts,
        tool_call={"tool": "browser_request", "params": {"url": url}, "result": {"links": links[:20], "forms": forms}},
    )


async def _execute_interact_page(params: dict, context: ExecutionContext, registry) -> Observation:
    """浏览器交互 — 填写表单、点击、捕获请求"""
    url = params.get("url", "")
    actions = params.get("actions", [])
    if not url or not actions:
        return Observation(success=False, summary="interact_page 缺少 url 或 actions")

    tool = registry.get("browser_interact")
    result = await tool.execute({
        "url": url,
        "actions": actions,
        "capture_requests": True,
    }, context)

    if not result.get("success"):
        return Observation(success=False, summary=f"交互失败: {result.get('error', '')}")

    captured = result.get("captured_requests", [])
    action_results = result.get("action_results", [])
    new_facts = []
    if captured:
        new_facts.append(f"交互产生 {len(captured)} 个网络请求")
        api_calls = [r for r in captured if "/api/" in r.get("url", "")]
        if api_calls:
            new_facts.append(f"发现隐藏 API 调用: {[r['url'][:80] for r in api_calls[:5]]}")

    return Observation(
        success=True,
        summary=f"交互完成: {len(action_results)} actions, {len(captured)} requests captured",
        response_body=result.get("final_content_snippet", "")[:1500],
        new_info_gained=bool(captured),
        new_facts=new_facts,
        tool_call={"tool": "browser_interact", "params": {"url": url}, "result": {"captured": captured[:10]}},
    )


async def _execute_deep_crawl(params: dict, context: ExecutionContext, registry) -> Observation:
    """crawlergo 深度爬取"""
    url = params.get("url", "")
    if not url:
        return Observation(success=False, summary="deep_crawl 缺少 url")

    tool = registry.get("deep_crawl")
    result = await tool.execute({
        "url": url,
        "max_count": params.get("max_count", 500),
        "timeout": params.get("timeout", 120),
    }, context)

    if not result.get("success"):
        return Observation(success=False, summary=f"深度爬取失败: {result.get('error', '')}")

    urls = result.get("urls", [])
    forms = result.get("forms", [])
    parameters = result.get("parameters", [])
    new_facts = []
    if urls:
        new_facts.append(f"深度爬取发现 {len(urls)} 个 URL")
    if forms:
        new_facts.append(f"深度爬取发现 {len(forms)} 个表单")
    if parameters:
        new_facts.append(f"深度爬取发现 {len(parameters)} 个参数")

    return Observation(
        success=True,
        summary=f"深度爬取: urls={len(urls)}, forms={len(forms)}, params={len(parameters)}",
        new_info_gained=bool(urls or forms or parameters),
        new_facts=new_facts,
        tool_call={"tool": "deep_crawl", "params": {"url": url}, "result": {"urls": urls[:20], "forms": forms[:5]}},
    )


async def _execute_analyze_traffic(params: dict, context: ExecutionContext, registry) -> Observation:
    """分析 mitmproxy 捕获的流量"""
    tool = registry.get("proxy_flows")
    result = await tool.execute({
        "filter_host": params.get("filter_host", ""),
        "filter_path": params.get("filter_path", ""),
        "filter_method": params.get("filter_method", ""),
        "limit": params.get("limit", 50),
    }, context)

    if not result.get("success"):
        return Observation(success=False, summary=f"流量分析失败: {result.get('error', '')}")

    flows = result.get("flows", [])
    new_facts = []
    if flows:
        methods = set(f.get("method", "") for f in flows)
        new_facts.append(f"捕获 {len(flows)} 条流量 (methods: {list(methods)})")
        api_flows = [f for f in flows if "/api/" in f.get("url", "")]
        if api_flows:
            new_facts.append(f"发现 {len(api_flows)} 条 API 流量")

    return Observation(
        success=True,
        summary=f"流量分析: {len(flows)} 条记录",
        new_info_gained=bool(flows),
        new_facts=new_facts,
        tool_call={"tool": "proxy_flows", "params": params, "result": {"count": len(flows)}},
    )


async def _execute_run_poc(params: dict, context: ExecutionContext, registry) -> Observation:
    """在沙箱中执行 PoC 代码"""
    code = params.get("code", "")
    if not code:
        return Observation(success=False, summary="run_poc 缺少 code")

    tool = registry.get("run_poc")
    result = await tool.execute({
        "code": code,
        "timeout": params.get("timeout", 30),
    }, context)

    if not result.get("success"):
        return Observation(
            success=False,
            summary=f"PoC 执行失败: {result.get('error', '')}",
            tool_call={"tool": "run_poc", "params": {"code_len": len(code)}, "result": result},
        )

    output = result.get("output", "")
    new_facts = []
    vuln_confirmed = False
    severity = ""

    success_indicators = ["vulnerable", "exploited", "pwned", "200 ok", "success", "flag{"]
    if any(ind in output.lower() for ind in success_indicators):
        vuln_confirmed = True
        severity = "high"
        new_facts.append(f"PoC 执行成功确认漏洞: {output[:200]}")

    return Observation(
        success=True,
        summary=f"PoC 执行完成: exit={result.get('exit_code')}, time={result.get('execution_time_ms')}ms",
        response_body=output[:2000],
        vuln_confirmed=vuln_confirmed,
        severity=severity,
        finding={"type": "poc_verified", "evidence": output[:500], "code_snippet": code[:200]} if vuln_confirmed else {},
        new_info_gained=bool(output),
        new_facts=new_facts if new_facts else [f"PoC 输出: {output[:200]}"] if output else [],
        tool_call={"tool": "run_poc", "params": {"code_len": len(code)}, "result": {"exit_code": result.get("exit_code")}},
    )
