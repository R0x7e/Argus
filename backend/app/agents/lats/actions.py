"""
LATS 动作空间定义和执行映射

定义 ReAct Agent 可执行的所有原子动作类型，
以及将高层动作映射到底层工具调用的执行逻辑。
"""

import logging
import re
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
    BATCH_INJECT = "batch_inject"       # v7: 批量注入
    MUTATE_PAYLOAD = "mutate_payload"
    PROBE_FILTER = "probe_filter"
    SQLI_DETECT = "sqli_detect"         # P0-4: 专用 SQL 注入检测

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

    # v21: 基线快照 — 供盲检测引擎 BlindVerifier 使用
    baseline_body: str = ""
    baseline_len: int = 0
    baseline_status: int = 0
    baseline_time_ms: int = 0


def _build_inject_url(url: str, param: str, payload: str, method: str = "GET",
                      form_fields: list[str] | None = None) -> dict:
    """构造注入请求参数

    L2/PR-3: POST 时用完整表单字段重构 body — 旧实现只拼 `param=payload`,
    缺失 submit 等必填字段可能被后端校验拒收 / 参数未被处理。
    """
    if method.upper() == "GET":
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if param:
            qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        return {"url": full_url, "method": "GET", "follow_redirects": False}
    else:
        # POST: 用完整表单字段重构 body, 命中参数填 payload, 其余填空/默认
        fields = list(form_fields) if form_fields else ([param] if param else [])
        body_dict: dict[str, str] = {}
        if param:
            body_dict[param] = str(payload)
        for f in fields:
            if f and f not in body_dict:
                body_dict[f] = ""
        return {
            "url": url,
            "method": "POST",
            "body": urlencode(body_dict, doseq=True),
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
            return await _execute_inject(params, context, tool_registry, state)
        elif action == ActionType.BATCH_INJECT:
            return await _execute_batch_inject(params, context, tool_registry, state)
        elif action == ActionType.MUTATE_PAYLOAD:
            return await _execute_mutate(params, context, tool_registry)
        elif action == ActionType.PROBE_FILTER:
            return await _execute_probe_filter(params, context, tool_registry)
        elif action == ActionType.SQLI_DETECT:
            return await _execute_sqli_detect(params, context, tool_registry, state)
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


async def _execute_inject(params: dict, context: ExecutionContext, registry, state: Any = None) -> Observation:
    """注入 payload 并分析响应 (P0-3: 自动基线比较, 检测布尔型盲注)"""
    url = params.get("url", "")
    param = params.get("param", "")
    payload = params.get("payload", "")
    method = params.get("method", "GET")
    # P0-3: 可选自定义基线值, 默认 "1"
    baseline_value = params.get("baseline_value", "1")
    skip_baseline = params.get("skip_baseline", False)

    # v3-fix: 无参端点回退 — 直接在 URL 路径追加 payload 或使用 dummy 参数
    if not param and not payload:
        # 无参端点: 直接 GET 请求获取响应体
        req_params = {"url": url, "method": method or "GET", "follow_redirects": False}
    elif not payload:
        req_params = {"url": url, "method": method or "GET", "follow_redirects": False}
    elif not param:
        # 有 payload 但无参数名: 将 payload 作为 URL 路径后缀
        sep = "/" if url.endswith("/") else "/"
        req_params = {"url": f"{url}{sep}{payload}", "method": method or "GET", "follow_redirects": False}
    else:
        req_params = _build_inject_url(url, param, payload, method,
                                       form_fields=params.get("form_fields"))
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
    orig_len = result.get("original_body_length", len(body))

    # P0-3: 自动基线比较 — 有参数时自动发送基线请求
    baseline_diff_info = ""
    # v21: 基线快照默认值
    bl_body, bl_status, bl_time, bl_orig_len = "", 0, 0, 0
    if param and payload and not skip_baseline:
        try:
            bl_req = _build_inject_url(url, param, baseline_value, method,
                                       form_fields=params.get("form_fields"))
            bl_result = await tool.execute(bl_req, context)
            if bl_result.get("success"):
                bl_body = bl_result.get("body", "") or ""
                bl_status = bl_result.get("status_code", 0)
                bl_time = bl_result.get("response_time_ms", 0)
                bl_orig_len = bl_result.get("original_body_length", len(bl_body))

                # 使用原始长度比较 (避免截断归一化)
                len_diff = orig_len - bl_orig_len
                status_diff = status != bl_status
                time_diff = time_ms - bl_time

                if status_diff or abs(len_diff) > 10 or abs(time_diff) > 1000:
                    obs_baseline_diff = True
                    parts = []
                    if status_diff:
                        parts.append(f"status {bl_status}→{status}")
                    if abs(len_diff) > 10:
                        parts.append(f"len_diff {len_diff}")
                    if abs(time_diff) > 1000:
                        parts.append(f"time_diff {time_diff}ms")
                    baseline_diff_info = f" | BASELINE_DIFF: {', '.join(parts)}"
                    # 内容指纹比较
                    if bl_body != body:
                        import re as _re_bl
                        bl_fp = _re_bl.sub(r'\d+', '', bl_body)
                        r_fp = _re_bl.sub(r'\d+', '', body)
                        if bl_fp != r_fp:
                            baseline_diff_info += " (content differs)"
                else:
                    obs_baseline_diff = False
            else:
                obs_baseline_diff = False
        except Exception:
            obs_baseline_diff = False
    else:
        obs_baseline_diff = False

    obs = Observation(
        success=True,
        status_code=status,
        response_body=body[:2000],
        response_headers=headers,
        response_time_ms=time_ms,
        # v21: 基线快照 — 供 BlindVerifier 使用
        baseline_body=bl_body,
        baseline_len=bl_orig_len,
        baseline_status=bl_status,
        baseline_time_ms=bl_time,
        tool_call={"tool": "http_request", "params": req_params, "result": {"status_code": status, "body_len": orig_len, "orig_body_len": orig_len}},
    )

    # 分析响应异常
    obs.status_code_anomaly = status in (500, 502, 503)
    obs.response_time_anomaly = time_ms > 3000
    obs.endpoint_404 = status == 404
    obs.waf_blocked = status == 403 or _is_waf_response(body)

    # P0-3: 基线差异是重要信息
    if obs_baseline_diff:
        obs.new_info_gained = True
        obs.new_facts.append(f"基线差异: payload='{payload[:40]}' vs baseline='{baseline_value}'{baseline_diff_info}")
        obs.same_as_baseline = False
        # v22: 记录成功请求向量 (供其他Agent学习)
        if "len_diff" in baseline_diff_info and param and url:
            try:
                from .shared_knowledge import SuccessfulRequestVector
                import datetime as _dt
                len_diff_val = abs(bl_orig_len - orig_len) if bl_orig_len and orig_len else 0
                if len_diff_val > 0:
                    vector = SuccessfulRequestVector(
                        endpoint=url,
                        method=method or "GET",
                        param=param,
                        payload_class=getattr(state, 'vuln_type', 'unknown') if state else 'unknown',
                        length_diff=len_diff_val,
                        baseline_length=bl_orig_len,
                        body_length=orig_len,
                        evidence=baseline_diff_info,
                        timestamp=_dt.datetime.now(_dt.timezone.utc).isoformat(),
                    )
                    # 通过 context 获取 SharedKnowledge
                    if hasattr(context, '_shared_knowledge') and context._shared_knowledge:
                        import asyncio
                        asyncio.ensure_future(
                            context._shared_knowledge.record_successful_vector(vector)
                        )
            except Exception:
                pass  # 记录失败不影响主流程
    else:
        obs.same_as_baseline = True

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

    # v21-fix: 布尔盲注通用检测 — 基线差异 + 内容指纹变化 → 可复现差异信号
    if obs_baseline_diff and not obs.vuln_confirmed:
        if "content differs" in baseline_diff_info:
            obs.new_facts.append("布尔盲注信号: 基线vs注入内容指纹不同")
            obs.new_info_gained = True

    # 检测关键指标 (v21: 传入基线数据供 BlindVerifier 使用)
    _detect_vuln_indicators(obs, payload, body, status, headers, time_ms, state,
                            baseline_body=obs.baseline_body,
                            baseline_len=obs.baseline_len,
                            baseline_status=obs.baseline_status,
                            baseline_time_ms=obs.baseline_time_ms)

    # v21: DiagnosticProber — 连续 SAME_AS_BASELINE 时触发诊断
    if obs.same_as_baseline and not obs.vuln_confirmed and param:
        try:
            from .diagnostic_prober import DiagnosticProber
            # 使用 state 上的计数器跟踪连续失败
            if state is not None and hasattr(state, '_diag_counter'):
                state._diag_counter += 1
            elif state is not None:
                state._diag_counter = 1
            if state is not None and getattr(state, '_diag_counter', 0) >= 2:
                state._diag_counter = 0  # 重置
                vuln_type = getattr(state, 'vuln_type', 'rce')
                other_params = [p for p in (getattr(state, 'known_facts', []) or []) if '参数' in str(p)][:3]
                # 如果没有其他已知参数, 尝试常见参数名
                if not other_params:
                    other_params = ["cmd", "id", "q", "file", "url", "name", "page", "ipaddress", "submit"]
                prober = DiagnosticProber()
                diag = await prober.diagnose(
                    endpoint_url=url,
                    param=param,
                    original_payload=payload,
                    vuln_type=vuln_type,
                    baseline_response={"status": bl_status, "body": bl_body, "len": bl_orig_len,
                                       "time_ms": bl_time, "headers": {}},
                    other_params=[p for p in other_params if isinstance(p, str) and p != param][:3],
                    context=context,
                )
                obs.new_facts.append(f"[诊断] {diag.value}: 连续SAME_AS_BASELINE原因={diag.value}")
                obs.new_info_gained = True
        except Exception:
            pass  # 诊断失败不影响主流程

    obs.summary = (
        f"status={status}, time={time_ms}ms, "
        f"body_len={orig_len}, "
        f"{'REFLECTED' if payload in body else ''} "
        f"{'ERROR_LEAKED' if obs.error_message_leaked else ''} "
        f"{'WAF_BLOCKED' if obs.waf_blocked else ''} "
        f"{'SAME_AS_BASELINE' if obs.same_as_baseline else 'DIFF_FROM_BASELINE'} "
        f"{'VULN_CONFIRMED' if obs.vuln_confirmed else ''}"
        f"{baseline_diff_info}"
    ).strip()

    return obs


def _has_sleep_payload(payload: str) -> bool:
    """检查 payload 是否包含时间延迟命令 (v21: 供 RCE/SQLi 时间盲注检测复用)"""
    import re
    patterns = [
        r'sleep\s+\d+', r'ping\s+-[nc]\s+\d+', r'timeout\s+\d+',
        r'WAITFOR\s+DELAY', r'pg_sleep', r'BENCHMARK', r'DBMS_PIPE',
    ]
    return any(re.search(p, payload, re.IGNORECASE) for p in patterns)


def _detect_vuln_indicators(obs: Observation, payload: str, body: str, status: int, headers: dict, time_ms: int, state: Any = None,
                             baseline_body: str = "", baseline_len: int = 0,
                             baseline_status: int = 0, baseline_time_ms: int = 0):
    """检测各类漏洞确认指标 (v21: 两层架构 — Layer1类型特定 + Layer2 BlindVerifier)"""
    body_lower = body.lower()
    detected_type = None

    # LFI/Path Traversal
    lfi_indicators = ["root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:", "[boot loader]", "[extensions]"]
    if any(ind in body for ind in lfi_indicators):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "lfi", "evidence": "文件内容泄露", "payload": payload}
        obs.new_facts.append("LFI 确认: 系统文件内容出现在响应中")
        detected_type = "lfi"

    # XSS (reflected)
    xss_indicators = ["<script>alert(", "onerror=alert(", "<svg/onload=", "ontoggle=alert(", "<img src=x onerror="]
    if any(ind in body for ind in xss_indicators):
        obs.vuln_confirmed = True
        obs.severity = "medium"
        obs.finding = {"type": "xss", "evidence": "XSS payload 反射", "payload": payload}
        obs.new_facts.append("XSS 确认: payload 在响应中原样执行")
        detected_type = "xss"

    # SSTI
    if "49" in body and "{{7*7}}" not in body and "${7*7}" not in body and ("7*7" in payload or "config" in payload):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "ssti", "evidence": "模板表达式被执行", "payload": payload}
        obs.new_facts.append("SSTI 确认: 表达式计算结果出现在响应中")
        detected_type = "ssti"
    if "SECRET_KEY" in body or ("DEBUG" in body and "True" in body):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "ssti", "evidence": "配置信息泄露", "payload": payload}
        detected_type = "ssti"

    # RCE (output-based)
    rce_indicators = ["uid=", "gid=", "www-data", "root:x:0"]
    if any(ind in body for ind in rce_indicators):
        obs.vuln_confirmed = True
        obs.severity = "critical"
        obs.finding = {"type": "rce", "evidence": "命令执行输出", "payload": payload}
        obs.new_facts.append("RCE 确认: 命令执行结果出现在响应中")
        detected_type = "rce"

    # v21-fix: RCE 时间盲注检测 — 对无回显的命令注入通过时间延迟确认
    if not obs.vuln_confirmed and time_ms > 3000 and _has_sleep_payload(payload):
        obs.vuln_confirmed = True
        obs.severity = "critical"
        obs.finding = {"type": "rce", "evidence": f"命令执行时间延迟 {time_ms}ms", "payload": payload}
        obs.new_facts.append(f"RCE 确认 (time-based): 响应延迟 {time_ms}ms")
        detected_type = "rce"

    # SQL Injection (error-based)
    sqli_errors = ["sql syntax", "mysql_fetch", "unclosed quotation", "you have an error in your sql",
                   "pg_query", "ora-01756", "sqlite3.operationalerror"]
    if any(e in body_lower for e in sqli_errors):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "sql_injection", "evidence": "SQL 错误信息", "payload": payload}
        obs.new_facts.append("SQLi 确认 (error-based): SQL 错误消息出现在响应中")
        detected_type = "sql_injection"

    # SQL Injection (time-based)
    if time_ms > 3000 and ("sleep" in payload.lower() or "pg_sleep" in payload.lower() or "waitfor" in payload.lower()):
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "sql_injection", "evidence": f"时间延迟 {time_ms}ms", "payload": payload}
        obs.new_facts.append(f"SQLi 确认 (time-based): 响应延迟 {time_ms}ms")
        detected_type = "sql_injection"

    # Open Redirect
    location = headers.get("location", "") or headers.get("Location", "")
    if "evil.com" in location and status in (301, 302, 303, 307, 308):
        obs.vuln_confirmed = True
        obs.severity = "medium"
        obs.finding = {"type": "open_redirect", "evidence": f"重定向到 {location}", "payload": payload}
        detected_type = "open_redirect"

    # v21-fix: SSRF 确认 — 之前完全没有 SSRF 检测分支
    ssrf_indicators = ["root:", "/etc/passwd", "metadata", "169.254.169.254",
                       "localhost", "127.0.0.1", "internal", "intranet"]
    if not obs.vuln_confirmed and any(ind in body_lower for ind in ssrf_indicators) and status != 404:
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "ssrf", "evidence": "内网资源响应出现在body中", "payload": payload}
        obs.new_facts.append("SSRF 确认: 成功访问内网资源")
        detected_type = "ssrf"
    if not obs.vuln_confirmed and "file://" in payload and status == 200 and len(body) > 100:
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {"type": "ssrf", "evidence": "file:// 协议读取成功", "payload": payload}
        obs.new_facts.append("SSRF 确认: file://协议读取")
        detected_type = "ssrf"

    # Info Disclosure (v2: 基于实际敏感内容证据)
    _INFO_DISCLOSURE_STRONG = [
        (r'\[core\]\s*\n\s*repositoryformatversion', "git_config_exposed"),
        (r'ref:\s*refs/heads/', "git_head_exposed"),
        (r'\[remote\s+"origin"\]', "git_remote_exposed"),
        (r'(?:password|passwd|secret|api_key|private_key)\s*[:=]\s*[\'"]?\S+[\'"]?', "credential_leaked"),
        (r'(?:AWS_|DB_|MYSQL_|POSTGRES_|REDIS_)(?:PASSWORD|SECRET|KEY)\s*=\s*', "env_credential_leaked"),
    ]
    if status == 200 and len(body) > 20:
        for pattern, ev_type in _INFO_DISCLOSURE_STRONG:
            if re.search(pattern, body, re.I):
                obs.vuln_confirmed = True
                obs.severity = "high"
                obs.finding = {"type": "info_disclosure", "evidence": ev_type, "payload": payload}
                obs.new_facts.append(f"信息泄露确认 ({ev_type}): 敏感数据出现在响应中")
                detected_type = "info_disclosure"
                break
        # v2: 仅当端点本身是配置路径或版本控制路径时才提升弱信号
        if not obs.vuln_confirmed and state is not None:
            ep_path = (getattr(state, 'current_endpoint', '') or '').lower()
            is_cfg_path = any(p in ep_path for p in ('.git/', '.env', 'dockerfile', '.htaccess', 'backup', 'config'))
            if is_cfg_path and len(body) > 100:
                obs.vuln_confirmed = True
                obs.severity = "medium"
                obs.finding = {"type": "info_disclosure", "evidence": "config_path_accessible", "payload": payload}
                obs.new_facts.append("信息泄露确认: 配置路径可访问")
                detected_type = "info_disclosure"

    # v5: 自动升级节点 vuln_type — Agent 发现了与节点类型不同的漏洞信号
    if detected_type and state is not None and hasattr(state, 'vuln_type'):
        if state.vuln_type != detected_type and state.vuln_type in ("auth_bypass", "info_disclosure", ""):
            state.vuln_type = detected_type
            obs.new_facts.append(f"节点类型自动升级: {state.vuln_type} → {detected_type}")

    # v21: Layer 2 — 统一盲检测引擎 (类型无关的旁路分析)
    if not obs.vuln_confirmed and state is not None:
        try:
            from .blind_verifier import get_blind_verifier
            vuln_type = getattr(state, 'vuln_type', '')
            verifier = get_blind_verifier()
            result = verifier.verify(
                payload=payload, body=body,
                time_ms=time_ms, status=status,
                vuln_type=vuln_type,
                baseline_body=baseline_body,
                baseline_len=baseline_len,
                baseline_status=baseline_status,
                baseline_time_ms=baseline_time_ms,
            )
            if result and result.confirmed:
                obs.vuln_confirmed = True
                severity_map = {"rce": "critical", "sql_injection": "high",
                                "ssrf": "high", "lfi": "high", "ssti": "high"}
                obs.severity = severity_map.get(vuln_type, "high")
                obs.finding = {
                    "type": vuln_type,
                    "evidence": f"[{result.method}] {result.evidence}",
                    "payload": payload,
                    "blind_method": result.method,
                }
                obs.new_facts.append(
                    f"{vuln_type.upper()} 确认 (blind-{result.method}): {result.evidence}"
                )
        except Exception:
            pass  # 盲检测失败不影响主流程


async def _execute_batch_inject(params: dict, context: ExecutionContext, registry, state: Any = None) -> Observation:
    """v8: 批量注入 — 支持 preset 参数调用 payload 库"""
    url = params.get("url", "")
    param = params.get("param", "")
    payloads = params.get("payloads", [])
    preset = params.get("preset", "")
    method = params.get("method", "GET")

    # v8: preset 支持 — 从 payload 库加载
    if preset and not payloads:
        try:
            from .payload_library import get_payloads, get_preset_for_vuln_type
            vuln_type = get_preset_for_vuln_type(preset if preset != "auto" else "")
            if not vuln_type:
                vuln_type = preset
            loaded = get_payloads(vuln_type, "quick_scan")
            payloads = loaded if loaded else payloads
        except Exception:
            pass

    if not url or not param or not payloads:
        return Observation(success=False, summary="batch_inject 缺少 url/param/payloads")

    tool = registry.get("http_request")
    form_fields = params.get("form_fields") or []
    # Baseline — 使用中性参数值, 而非裸 URL (裸 URL 可能返回不同页面)
    baseline_url = _build_inject_url(url, param, "1", method, form_fields=form_fields)["url"]
    baseline = await tool.execute({"url": baseline_url, "method": method}, context)
    bl_status = baseline.get("status_code", 0)
    baseline_body = baseline.get("body", "") or ""
    bl_len = len(baseline_body)
    bl_time = baseline.get("response_time_ms", 0)

    results = []
    anomalies = []
    for payload in payloads[:8]:
        req_params = _build_inject_url(url, param, str(payload), method, form_fields=form_fields)
        r = await tool.execute(req_params, context)
        r_status = r.get("status_code", 0)
        r_body = r.get("body", "") or ""
        r_len = len(r_body)
        r_time = r.get("response_time_ms", 0)
        entry = {"payload": str(payload)[:80], "status": r_status, "len": r_len, "time_ms": r_time,
                 "body_preview": r_body[:150].replace('\n','\\n').replace('\r','')}
        results.append(entry)
        # 异常检测 (P0-2: 独立 if 检查, 不再用 elif 链)
        if r_status != bl_status and r_status not in (404, 403):
            anomalies.append(f"status {bl_status}→{r_status}: {payload[:40]}")
        # HTTP 500 状态码异常信号 — SQL 注入导致服务器 500 是常见信号
        if r_status == 500 and bl_status != 500:
            anomalies.append(f"server error 500 (baseline={bl_status}): {payload[:40]}")
        # P0-3: 降低长度差异阈值从 50 到 20，并添加 HTML 结构比较
        if abs(r_len - bl_len) > 20:  # 长度差异（降低阈值）
            anomalies.append(f"len diff {r_len - bl_len}: {payload[:40]}")
        if r_time - bl_time > 1500:  # 时间差异
            anomalies.append(f"time +{r_time - bl_time}ms: {payload[:40]}")
        # 内容指纹 — 去数字后对比完整 body (P0-2: 去掉 [:500] 限制)
        if r_body != baseline_body:
            import re as _re4
            bl_fp = _re4.sub(r'\d+', '', baseline_body)
            r_fp = _re4.sub(r'\d+', '', r_body)
            if bl_fp != r_fp:
                anomalies.append(f"content fingerprint diff: {payload[:40]}")
            # P0-3: 添加 HTML 结构比较（表格行数、列表项数）
            else:
                # 提取 HTML 结构特征
                bl_tables = len(_re4.findall(r'<tr[^>]*>', bl_fp, _re4.I))
                r_tables = len(_re4.findall(r'<tr[^>]*>', r_fp, _re4.I))
                bl_lists = len(_re4.findall(r'<li[^>]*>', bl_fp, _re4.I))
                r_lists = len(_re4.findall(r'<li[^>]*>', r_fp, _re4.I))
                if bl_tables != r_tables or bl_lists != r_lists:
                    anomalies.append(f"HTML structure diff (tables:{bl_tables}→{r_tables}, lists:{bl_lists}→{r_lists}): {payload[:40]}")
                # P0-3: 添加关键词匹配（检测“无结果”等提示）
                no_result_keywords = ['no result', 'empty', 'not found', 'no data', '无结果', '无数据', '未找到', 'no record']
                bl_has_no_result = any(kw in baseline_body.lower() for kw in no_result_keywords)
                r_has_no_result = any(kw in r_body.lower() for kw in no_result_keywords)
                if bl_has_no_result != r_has_no_result:
                    anomalies.append(f"no_result keyword diff (baseline:{bl_has_no_result}, injected:{r_has_no_result}): {payload[:40]}")
            # SQL 错误模式检测 — 复用 _detect_vuln_indicators 的错误模式
            r_body_lower = r_body.lower()
            sqli_error_keywords = [
                "sql syntax", "mysql_fetch", "unclosed quotation",
                "you have an error in your sql", "pg_query", "ora-01756",
                "sqlite3.operationalerror", "syntax error", "warning: mysql",
            ]
            for kw in sqli_error_keywords:
                if kw in r_body_lower:
                    anomalies.append(f"SQL error ('{kw}'): {payload[:40]}")
                    break

    summary = f"batch_inject: {len(results)} payloads"
    if anomalies:
        summary += f", ANOMALIES: {'; '.join(anomalies[:3])}"
    else:
        summary += ", all baseline (no diff)"

    # 自动后验证: batch_inject 无发现 + sqli 场景 → 自动调用专业 sqli_detect
    if not anomalies and (preset in ("sqli", "auto") or (state and getattr(state, 'vuln_type', '') == 'sql_injection')):
        sqli_tool = registry.get("sqli_detect")
        if sqli_tool:
            try:
                from urllib.parse import urlparse as _urlparse
                parsed = _urlparse(url)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                sqli_result = await sqli_tool.execute(
                    {"url": clean_url, "param": param, "method": method}, context
                )
                if sqli_result.get("vulnerable"):
                    return Observation(
                        success=True,
                        summary=f"batch_inject→sqli_detect 自动确认 SQLi: {sqli_result.get('technique')}",
                        vuln_confirmed=True, severity="high",
                        finding={"type": "sql_injection", "evidence": f"auto-confirmed: {sqli_result.get('technique')}",
                                 "payload": sqli_result.get("payload_used", ""), "url": clean_url, "param": param},
                        new_facts=[f"SQLi 自动确认: {sqli_result.get('technique')}"],
                        tool_call={"tool": "sqli_detect", "params": {"url": clean_url, "param": param}, "result": sqli_result},
                    )
            except Exception:
                pass  # 后验证失败不影响原始 batch_inject 结果

    return Observation(
        success=True,
        summary=summary,
        new_info_gained=bool(anomalies),
        new_facts=[f"批量注入 {len(results)} payloads: {anomalies if anomalies else '全部与基线相同'}"] if anomalies else [],
        tool_call={"tool": "http_request", "params": {"batch_inject": True},
                   "result": {"results": results, "baseline_status": bl_status, "baseline_len": bl_len}},
    )


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
    result = await tool.execute({"payload": original, "techniques": [technique]}, context)

    mutated_list = result.get("variants", [])
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
    method = params.get("method", "GET")
    form_fields = params.get("form_fields") or []
    chars = params.get("chars", ["<", ">", "'", '"', "/", "\\", ";", "|", "(", ")", "{", "}"])

    if not url or not param:
        return Observation(success=False, summary="probe_filter 缺少 url/param")

    tool = registry.get("http_request")
    blocked = []
    allowed = []

    # 先发一个 baseline 请求 (用端点能力 method/form_fields, L2/PR-3)
    baseline_params = _build_inject_url(url, param, "normaltest123", method, form_fields=form_fields)
    baseline_result = await tool.execute(baseline_params, context)
    baseline_status = baseline_result.get("status_code", 0)
    baseline_body_len = len(baseline_result.get("body", ""))

    for char in chars[:12]:
        test_value = f"test{char}probe"
        req = _build_inject_url(url, param, test_value, method, form_fields=form_fields)
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


async def _execute_sqli_detect(params: dict, context: ExecutionContext, registry, state: Any = None) -> Observation:
    """P0-4: 调用专用 SQL 注入检测工具 (错误型 + 时间盲注)"""
    url = params.get("url", "")
    param = params.get("param", "")
    method = params.get("method", "GET")

    if not url or not param:
        return Observation(success=False, summary="sqli_detect 缺少 url/param")

    # 从 URL 中剥离 query string (sqli_detect 工具自己构造参数)
    from urllib.parse import urlparse as _urlparse
    parsed = _urlparse(url)
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    # 如果 URL 中已有 query 参数, 尝试提取参数名
    if not param and parsed.query:
        from urllib.parse import parse_qs
        qs = parse_qs(parsed.query)
        if qs:
            param = list(qs.keys())[0]

    if not param:
        return Observation(success=False, summary="sqli_detect 缺少 param 参数")

    tool = registry.get("sqli_detect")
    if tool is None:
        return Observation(success=False, summary="sqli_detect 工具未注册")

    result = await tool.execute({
        "url": clean_url,
        "param": param,
        "method": method,
        "form_fields": params.get("form_fields") or [],
    }, context)

    if not result.get("success"):
        return Observation(
            success=False,
            summary=f"sqli_detect 失败: {result.get('error', 'unknown')}",
            tool_call={"tool": "sqli_detect", "params": {"url": clean_url, "param": param}, "result": result},
        )

    vulnerable = result.get("vulnerable", False)
    technique = result.get("technique", "")
    evidence = result.get("evidence", {})
    payload_used = result.get("payload_used", "")

    obs = Observation(
        success=True,
        summary=f"sqli_detect: {'VULNERABLE' if vulnerable else 'not vulnerable'} (technique={technique}, payload={payload_used[:50]})",
        tool_call={"tool": "sqli_detect", "params": {"url": clean_url, "param": param}, "result": result},
    )

    if vulnerable:
        obs.vuln_confirmed = True
        obs.severity = "high"
        obs.finding = {
            "type": "sql_injection",
            "evidence": f"sqli_detect 确认: technique={technique}",
            "payload": payload_used,
            "url": clean_url,
            "param": param,
            "detection_method": technique,
            "raw_evidence": evidence,
        }
        obs.new_facts.append(f"SQLi 确认 (sqli_detect): {technique}, payload={payload_used[:50]}")
    else:
        obs.new_facts.append(f"sqli_detect 未发现 SQL 注入 (technique={technique})")
        obs.new_info_gained = True

    return obs


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

    # v3: 多正则回退提取表单参数
    form_params = set()
    form_params.update(re.findall(r'<(?:input|textarea|select|button)[^>]*name="([^"]+)"', body, re.IGNORECASE))
    form_params.update(re.findall(r"<(?:input|textarea|select|button)[^>]*name='([^']+)'", body, re.IGNORECASE))
    form_params.update(re.findall(r'<(?:input|textarea|select|button)[^>]*name=(\w+)', body, re.IGNORECASE))
    form_params.update(re.findall(r'<(?:input|textarea|select|button)[^>]*id="([^"]+)"', body, re.IGNORECASE))
    form_params.update(re.findall(r'<(?:input|textarea)[^>]*placeholder="([^"]+)"', body, re.IGNORECASE))
    form_param_list = list(form_params)

    # 提取 form action
    form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.IGNORECASE)

    new_facts = []
    if links:
        link_samples = sorted(links)[:10]
        new_facts.append(f"发现 {len(links)} 个链接: {link_samples}")
    if form_param_list:
        new_facts.append(f"发现表单参数 ({len(form_param_list)}个): {form_param_list[:15]}")
    if form_actions:
        new_facts.append(f"发现表单提交目标: {form_actions[:5]}")

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
    """参数发现 (v3: GET长度 + 状态码 + POST探测三重检测)"""
    url = params.get("url", "")
    if not url:
        return Observation(success=False, summary="discover_params 缺少 url")

    common_params = [
        "id", "page", "q", "search", "query", "name", "user", "username",
        "email", "file", "path", "url", "redirect", "next", "callback",
        "action", "cmd", "type", "category", "sort", "order", "limit",
        "offset", "token", "key", "api_key", "debug", "test", "admin",
        "userId", "user_id", "password", "phone", "status", "role", "groupId",
        "per_page", "pageSize", "keyword", "access_token", "auth",
        "filename", "download", "upload", "dir", "folder",
        "lang", "format", "return", "return_url", "source", "target",
        "date", "startDate", "endDate",
    ]

    tool = registry.get("http_request")

    # Baseline: GET
    baseline = await tool.execute({"url": url, "method": "GET"}, context)
    baseline_len = len(baseline.get("body", ""))
    baseline_status = baseline.get("status_code", 0)

    # Baseline: POST (empty body)
    post_baseline = await tool.execute(
        {"url": url, "method": "POST", "body": "",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"}}, context)
    post_baseline_len = len(post_baseline.get("body", ""))
    post_baseline_status = post_baseline.get("status_code", 0)

    discovered = []
    sep = "&" if "?" in url else "?"

    for p in common_params[:30]:
        # ── 检测 1: GET 参数 + 长度差异 + 状态码 ──
        test_url = f"{url}{sep}{p}=test123"
        result = await tool.execute({"url": test_url, "method": "GET"}, context)
        test_len = len(result.get("body", ""))
        test_status = result.get("status_code", 0)
        get_len_diff = abs(test_len - baseline_len)
        get_status_changed = test_status != baseline_status and test_status not in (404, 403)

        # ── 检测 2: POST 参数探测 ──
        post_result = await tool.execute(
            {"url": url, "method": "POST", "body": f"{p}=test123",
             "headers": {"Content-Type": "application/x-www-form-urlencoded"}}, context)
        post_len = len(post_result.get("body", ""))
        post_status = post_result.get("status_code", 0)
        post_len_diff = abs(post_len - post_baseline_len)
        post_status_changed = post_status != post_baseline_status and post_status not in (404, 403)

        # ── 判定 ──
        if get_len_diff > 80:
            discovered.append({"name": p, "method": "GET", "evidence": f"len_diff={get_len_diff}"})
        elif get_status_changed:
            discovered.append({"name": p, "method": "GET", "evidence": f"status={baseline_status}->{test_status}"})
        elif post_len_diff > 80:
            discovered.append({"name": p, "method": "POST", "evidence": f"len_diff={post_len_diff}"})
        elif post_status_changed:
            discovered.append({"name": p, "method": "POST", "evidence": f"status={post_baseline_status}->{post_status}"})
        # v4-fix: 内容指纹 — 对固定长度页面检测局部内容变化
        elif get_len_diff > 0 and get_len_diff <= 80:
            import re as _re2
            bl_fp = _re2.sub(r'\d+', '', baseline.get("body", "")[:500])
            pr_fp = _re2.sub(r'\d+', '', result.get("body", "")[:500])
            if bl_fp != pr_fp:
                discovered.append({"name": p, "method": "GET", "evidence": "content_fingerprint_diff"})

    # 去重
    seen = set()
    unique = []
    for d in discovered:
        if d["name"] not in seen:
            seen.add(d["name"])
            unique.append(d)

    # v10: URL 推断参数合并到 found_params, 确保 Agent 将其视为有效参数
    inferred_hints = []
    try:
        from app.agents.lats.graph import _infer_params_from_url
        inferred = _infer_params_from_url(url)
        for p in inferred[:5]:
            pname = p["name"]
            if pname not in seen:
                seen.add(pname)
                unique.append({"name": pname, "method": "GET", "evidence": "url_inferred"})
                inferred_hints.append(pname)
    except Exception:
        inferred_hints = []

    return Observation(
        success=True,
        summary=f"参数发现: {[d['name'] for d in unique[:10]]}" if unique else "未发现有效参数",
        new_info_gained=bool(unique),
        new_facts=[f"发现有效参数 ({len(unique)}个): {[d['name'] for d in unique[:10]]}"] if unique else [],
        tool_call={"tool": "http_request", "params": {"discover": True},
                   "result": {"found_params": unique}},
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

    # v3: 端点敏感度分类 — 区分真正的认证绕过 vs 公开文件
    import re as _re
    _SENSITIVE = [
        r'\.git', r'\.env', r'\.htaccess', r'\.svn', r'\.hg',
        r'/admin', r'/dashboard', r'/config', r'/backup', r'/backups',
        r'/api/', r'/graphql', r'/actuator', r'/jmx',
        r'wp-admin', r'wp-config', r'phpmyadmin', r'phpinfo',
        r'/manage', r'/console', r'/debug', r'/server-status',
        r'\.sql$', r'\.bak$', r'\.old$', r'\.save$', r'\.orig$', r'\.swp$',
        r'/user', r'/account', r'/order', r'/internal',
    ]
    _NON_SENSITIVE = [
        r'README', r'LICENSE', r'CHANGELOG', r'\.md$', r'\.txt$',
        r'robots\.txt', r'sitemap', r'favicon', r'\.xml$',
        r'\.css$', r'\.js$', r'\.png$', r'\.jpg$', r'\.jpeg$',
        r'\.gif$', r'\.svg$', r'\.ico$', r'\.woff', r'\.ttf$',
    ]
    is_sensitive = any(_re.search(p, url, _re.IGNORECASE) for p in _SENSITIVE)
    is_non_sensitive = any(_re.search(p, url, _re.IGNORECASE) for p in _NON_SENSITIVE)

    if status == 200 and len(body) > 100:
        if is_sensitive and not is_non_sensitive:
            obs.vuln_confirmed = True
            obs.severity = "high"
            obs.finding = {"type": "auth_bypass", "evidence": f"敏感端点无认证访问: {url}", "url": url}
            obs.new_facts.append(f"未授权访问确认 (敏感端点): {url}")
            obs.summary = f"AUTH_BYPASS (敏感): {url} 返回 200 无需认证"
        elif is_non_sensitive:
            obs.summary = f"公开文件 (非漏洞): {url} 返回 200 (正常)"
            obs.new_facts.append(f"公开文件可访问 (非漏洞): {url}")
        else:
            obs.summary = f"端点可访问 (待确认): {url} 返回 200"
            obs.new_facts.append(f"端点可访问 (需进一步验证敏感度): {url}")
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

    # v3-fix: 在 summary 中附 body 前 200 字符，让 LLM 直接看到内容
    body_preview = body[:200].replace('\n', '\\n').replace('\r', '')
    return Observation(
        success=result.get("success", False),
        status_code=status,
        response_body=body[:2000],
        summary=f"数据提取: status={status}, body_len={len(body)}, preview={body_preview}",
        new_info_gained=len(body) > 100,
        new_facts=[f"提取数据 {len(body)} bytes: {body_preview}"] if len(body) > 100 else [],
        tool_call={"tool": "http_request", "params": req_params, "result": {"status": status, "len": len(body)}},
    )


async def _execute_render_page(params: dict, context: ExecutionContext, registry) -> Observation:
    """使用 Playwright 渲染页面，提取 JS 动态内容"""
    url = params.get("url", "")
    if not url:
        return Observation(success=False, summary="render_page 缺少 url")

    # v3-fix: wait_for 参数类型容错 — LLM 可能传整数(想设 timeout)
    wait_for_raw = params.get("wait_for", "networkidle")
    if isinstance(wait_for_raw, (int, float)):
        wait_for = "networkidle"  # 整数转为默认值
    elif isinstance(wait_for_raw, str) and wait_for_raw.strip():
        wait_for = wait_for_raw.strip()
    else:
        wait_for = "networkidle"

    tool = registry.get("browser_request")
    result = await tool.execute({
        "url": url,
        "wait_for": wait_for,
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
    # v4-fix: 提取具体参数名和 URL 列表传给 LLM
    param_names = []
    for p in (parameters or [])[:20]:
        if isinstance(p, dict):
            param_names.append(p.get("name", ""))
        elif isinstance(p, str):
            param_names.append(p)
    param_str = ", ".join([n for n in param_names if n]) or "无名称"

    url_samples = []
    for u in (urls or [])[:10]:
        if isinstance(u, dict):
            url_samples.append(u.get("url", "")[:80])
        elif isinstance(u, str):
            url_samples.append(u[:80])

    new_facts = []
    if urls:
        new_facts.append(f"深度爬取发现 {len(urls)} 个 URL: {url_samples}")
    if forms:
        new_facts.append(f"深度爬取发现 {len(forms)} 个表单")
    if parameters:
        new_facts.append(f"深度爬取发现参数 ({len(parameters)}个): {param_str}")

    return Observation(
        success=True,
        summary=f"深度爬取: urls={len(urls)}, forms={len(forms)}, params={len(parameters)} ({param_str})",
        new_info_gained=bool(urls or forms or parameters),
        new_facts=new_facts,
        tool_call={"tool": "deep_crawl", "params": {"url": url},
                   "result": {"urls": urls, "forms": forms, "parameters": parameters}},  # v10: 不截断, 全量传给扩展引擎
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

    output_lower = output.lower()
    # 排除否定模式（如 "Not vulnerable"、"not exploitable"、"no delay"）
    negation_patterns = [
        "not vulnerable", "not exploitable", "no vulnerability",
        "no delay", "not affected", "not susceptible",
    ]
    has_negation = any(neg in output_lower for neg in negation_patterns)
    # 正向指标（仅在无否定模式时才确认漏洞）
    success_indicators = ["vulnerable", "exploited", "pwned", "200 ok", "success", "flag{"]
    if not has_negation and any(ind in output_lower for ind in success_indicators):
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
