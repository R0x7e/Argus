"""
多层级探测器 (Multi-Level Prober)

Phase 3: Level 0 快速探测 — 3 次 HTTP 请求, 零 LLM 调用.
用于在投入昂贵的 Full ReAct 之前快速筛选分支.

未来可扩展: Level 1 LLM 辅助探测, Level 2 Full ReAct (复用现有逻辑).
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from app.tools.base import ExecutionContext

logger = logging.getLogger(__name__)


# ──── L2-fix: SQL 错误特征库 (error-based / 闭合检测确认信号) ────
# 旧 _classify/probe_round2 只看 长度差/5xx/时延, 漏掉 200+MySQL 报错这种
# 最常见的 error-based SQLi (Pikachu POST id=1' → 200 + "error in your SQL syntax")
_SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"error in your sql syntax",
    r"syntax error near ['`\"]",
    r"mysql_fetch",
    r"warning:\s*mysql",
    r"mysqli?",
    r"valid mysql result",
    r"odbc (sql|driver)",
    r"ora-\d{5}",
    r"pg_(query|exec|send_query)",
    r"sqlstate",
    r"sqlite3?\.",
    r"unclosed quotation mark",
    r"near ['`\"][^'\"]*['`\"]:\s*line",
]


def _detect_error_signal(body: str) -> str | None:
    """检测响应体中的 DB 错误字符串, 返回命中的模式描述 (None=未命中)"""
    if not body:
        return None
    lower = body.lower()
    for pat in _SQL_ERROR_PATTERNS:
        m = re.search(pat, lower)
        if m:
            # 提取上下文证据片段 (60 字符)
            idx = m.start()
            snippet = body[max(0, idx - 20): idx + 80].replace("\n", " ").strip()
            return f"SQL_ERROR[{pat}]: ...{snippet}..."
    return None


@dataclass
class ProbeResult:
    """Level 0 探测结果"""
    node_id: str
    endpoint: str
    param: str | None
    vuln_type: str

    # 探测结果
    verdict: str = "unknown"  # "promoted" | "killed" | "needs_retry"

    # 基线
    baseline_status: int = 0
    baseline_length: int = 0
    baseline_time_ms: int = 0

    # 探测字符
    probe_status: int = 0
    probe_length: int = 0
    probe_time_ms: int = 0

    # 注入 payload
    inject_status: int = 0
    inject_length: int = 0
    inject_time_ms: int = 0

    # 发现的信号
    signals: dict = field(default_factory=dict)
    error: str = ""



# ──── P3: 漏洞类型 → 多 payload 渐进探测 ────

# Round 1: 代表性 payload (快速筛选)
_VULN_TYPE_PROBE_PAYLOAD: dict[str, str] = {
    "sql_injection": "' OR '1'='1",
    "sql_injection_numeric": "1 OR 1=1",
    "xss": "<script>",
    "lfi": "/etc/passwd",
    "path_traversal": "/etc/passwd",
    "ssrf": "http://127.0.0.1:80",
    "ssti": "{{7*7}}",
    "rce": ";id",
    "open_redirect": "https://evil.com",
    "idor": "0",
    "auth_bypass": "",
    "info_disclosure": "",
    "file_upload": "",
}

# P3: Round 2 多样 payload (不同注入技术)
_VULN_TYPE_DIVERSE_PAYLOADS: dict[str, list[str]] = {
    "sql_injection": [
        "'",                          # 闭合探测
        "1 AND SLEEP(3)-- -",        # 时间盲注
        "-1 UNION SELECT 1,2,3--+",  # UNION 探测
    ],
    "rce": [
        "`id`",                       # 反引号
        "| sleep 3",                  # 管道 + 时间盲注
        "$(id)",                      # 命令替换
    ],
    "xss": [
        "'-alert(1)-'",
        "<img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
    ],
    "ssti": [
        "${7*7}",
        "<%= 7*7 %>",
        "{{config}}",
    ],
    "lfi": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=index",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:80/_",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
    ],
    "idor": [
        "1",
        "admin",
        "999999",
    ],
    "open_redirect": [
        "https://evil.com",
        "//evil.com",
        "javascript:alert(1)",
    ],
}


# ──── P1: 无参端点参数回退映射 ────
_PARAM_FALLBACK_BY_VULN_TYPE: dict[str, list[str]] = {
    "sql_injection": ["id", "q", "query", "search", "name", "username", "uid"],
    "rce": ["cmd", "exec", "command", "ping", "ip", "host"],
    "xss": ["q", "search", "name", "message", "comment", "input", "text"],
    "lfi": ["file", "path", "page", "include", "filename"],
    "path_traversal": ["file", "path", "dir", "folder", "download"],
    "ssrf": ["url", "link", "callback", "redirect", "fetch"],
    "ssti": ["template", "name", "message", "content", "text"],
    "idor": ["id", "uid", "user_id", "account", "order_id", "profile_id"],
    "open_redirect": ["url", "redirect", "next", "return", "goto"],
    "auth_bypass": ["username", "password", "user", "pass", "token"],
    "info_disclosure": [],
    "file_upload": ["file", "image", "upload"],
}


class QuickProber:
    """
    Level 0 快速探测器

    对单个节点执行 3 次 HTTP 请求, 基于简单规则输出 promoted/killed 判定.
    零 LLM 调用, 可在同一周期内批量完成.
    """

    def __init__(self):
        pass

    async def probe(
        self,
        node,
        context: ExecutionContext,
        base_url: str = "",
    ) -> ProbeResult:

        endpoint = self._build_url(node.state.current_endpoint, base_url)
        param = node.state.current_param
        vuln_type = node.state.vuln_type
        # L2-fix: 读取节点的 HTTP method 与完整表单字段 (PR-3)
        method, form_fields = self._node_probe_method(node)
        result = ProbeResult(
            node_id=node.id,
            endpoint=endpoint,
            param=param,
            vuln_type=vuln_type,
        )

        if not endpoint:
            result.verdict = "killed"
            result.error = "empty endpoint"
            return result

        # P1: 无参端点 — 尝试参数回退, 不直接杀死
        if not param and vuln_type in _PARAM_FALLBACK_BY_VULN_TYPE:
            fallback_params = _PARAM_FALLBACK_BY_VULN_TYPE[vuln_type]
            for fb_param in fallback_params[:2]:
                probe_req = await self._send_request(endpoint, context, param=fb_param,
                                                     payload="1", method=method,
                                                     form_fields=form_fields)
                if probe_req.get("success") and probe_req.get("status_code", 0) == 200:
                    probe_body = probe_req.get("body", "") or ""
                    # 检查是否与无参基线不同 (说明参数被处理了)
                    baseline_no_param = await self._send_request(endpoint, context, param=None,
                                                                 payload=None, method=method,
                                                                 form_fields=form_fields)
                    if probe_body != (baseline_no_param.get("body", "") or ""):
                        param = fb_param
                        node.state.current_param = fb_param
                        # 回退发现参数时同步补进 form_fields, 供后续 POST 重构 body
                        if fb_param and fb_param not in form_fields:
                            form_fields = form_fields + [fb_param]
                        logger.info("P1: 发现有效参数 %s → %s (method=%s)", endpoint, fb_param, method)
                        break

        # P1: 仍无参数 — 不杀死, 让 ReAct 自行发现
        if not param:
            result.verdict = "needs_deeper_probe"
            result.error = "no_param_available"
            return result

        try:
            # Step 1: 基线请求
            baseline = await self._send_request(endpoint, context, param=None, payload=None,
                                                method=method, form_fields=form_fields)
            result.baseline_status = baseline.get("status_code", 0)
            result.baseline_length = len(baseline.get("body", "") or "")
            result.baseline_time_ms = baseline.get("response_time_ms", 0)

            # 基线失败 → killed
            if result.baseline_status in (0, -1) or not baseline.get("success"):
                result.verdict = "killed"
                result.error = f"baseline failed: status={result.baseline_status}"
                return result

            # 基线 404 → killed
            if result.baseline_status == 404:
                result.verdict = "killed"
                result.error = "baseline 404"
                return result

            # Step 2: 探测字符
            probe_char = "'" if vuln_type in ("sql_injection", "xss", "ssti", "lfi") else "."
            probe = await self._send_request(endpoint, context, param=param, payload=probe_char,
                                             method=method, form_fields=form_fields)
            result.probe_status = probe.get("status_code", 0)
            result.probe_length = len(probe.get("body", "") or "")
            result.probe_time_ms = probe.get("response_time_ms", 0)

            if not probe.get("success"):
                result.signals["probe_failed"] = True

            # L2-fix: SQL 错误串检测 — probe_char (常用 '/') 触发 error-based 信号
            probe_body = probe.get("body", "") or ""
            err = _detect_error_signal(probe_body)
            if err and vuln_type in ("sql_injection", "sql_injection_numeric", "xss", "ssti", "lfi"):
                result.signals["sqli_error"] = err

            # Step 3: 代表性 payload
            probe_payload = _VULN_TYPE_PROBE_PAYLOAD.get(vuln_type, "test")
            if probe_payload:
                inject = await self._send_request(endpoint, context, param=param, payload=probe_payload,
                                                  method=method, form_fields=form_fields)
                result.inject_status = inject.get("status_code", 0)
                result.inject_length = len(inject.get("body", "") or "")
                result.inject_time_ms = inject.get("response_time_ms", 0)
                result.signals["inject_body"] = inject.get("body", "") or ""
                result.signals["baseline_body"] = baseline.get("body", "") or ""
                # L2-fix: inject payload 也检测错误串
                if "sqli_error" not in result.signals:
                    err2 = _detect_error_signal(inject.get("body", "") or "")
                    if err2:
                        result.signals["sqli_error"] = err2

            # 分类判定
            result.verdict = self._classify(result)

        except Exception as e:
            result.verdict = "needs_retry"
            result.error = str(e)[:200]
            logger.warning("Level 0 探测异常 [%s]: %s", endpoint, str(e))

        return result

    def _classify(self, r: ProbeResult) -> str:
        """P3: 基于探测结果的三分类 + 两轮探测

        verdicts: promoted | needs_deeper_probe | killed | low_signal
        """
        signals = r.signals

        # ── info_disclosure 特殊处理 (v2: 基于证据) ──
        if r.vuln_type == "info_disclosure":
            if r.baseline_status in (404, 403, 401):
                return "killed"
            if r.baseline_status == 200 and r.baseline_length < 20:
                return "killed"
            # v2: 检查弱证据 — 包含敏感内容才 promote
            inj_body = signals.get("inject_body", "")
            weak_evidence = any(
                re.search(p, inj_body, re.I) for p in [
                    r'\[core\]', r'ref:\s*refs/heads/', r'password', r'secret',
                    r'api_key', r'AWS_', r'DB_PASSWORD', r'<\?php',
                ]
            ) if inj_body else False
            if weak_evidence:
                return "promoted"
            # 配置路径 + 有内容 → low_signal (不自动 promote)
            is_cfg = any(p in r.endpoint.lower() for p in (
                '.git/', '.env', 'dockerfile', '.htaccess', 'backup', 'config'
            ))
            if is_cfg:
                return "low_signal"
            return "needs_deeper_probe"

        # ── auth_bypass 特殊处理 ──
        if r.vuln_type == "auth_bypass":
            if r.baseline_status in (401, 403):
                return "promoted"
            if r.baseline_status == 200:
                return "promoted"

        # ── L2-fix: SQL 错误串 → 直接 promoted (error-based SQLi 确认信号) ──
        if signals.get("sqli_error"):
            return "promoted"

        # ── 状态码异常 (5xx) → promoted ──
        if r.inject_status >= 500 and r.baseline_status < 500:
            signals["status_5xx"] = True
            return "promoted"

        # ── 响应长度显著差异 (>200 bytes 或 >30%) ──
        if r.baseline_length > 0:
            len_ratio = abs(r.inject_length - r.baseline_length) / r.baseline_length
            if abs(r.inject_length - r.baseline_length) > 200 or len_ratio > 0.3:
                signals["length_anomaly"] = True
                return "promoted"

        # ── 时间延迟 (>2000ms) ──
        if r.inject_time_ms - r.baseline_time_ms > 2000:
            signals["time_anomaly"] = True
            return "promoted"

        # ── 内容指纹变化 (数值归一化后不同) ──
        baseline_body = signals.get("baseline_body", "")
        inject_body = signals.get("inject_body", "")
        if baseline_body and inject_body:
            import re as _re_fp
            bl_fp = _re_fp.sub(r'\d+', '', baseline_body)
            inj_fp = _re_fp.sub(r'\d+', '', inject_body)
            if bl_fp != inj_fp and abs(len(baseline_body) - len(inject_body)) > 10:
                signals["fingerprint_diff"] = True
                return "promoted"

        # ── 微弱信号 → low_signal (不完全杀死, 让 ReAct 自行决定) ──
        if r.inject_status != r.baseline_status and r.baseline_status > 0:
            signals["status_diff_weak"] = True
            return "low_signal"

        # P3: 有小幅差异但不够显著 → needs_deeper_probe
        if abs(r.inject_length - r.baseline_length) > 20:
            signals["length_anomaly_weak"] = True
            return "needs_deeper_probe"

        if r.inject_time_ms - r.baseline_time_ms > 500:
            signals["time_anomaly_weak"] = True
            return "needs_deeper_probe"

        # ── P3: 无任何信号 → needs_deeper_probe (等第二轮再杀) ──
        return "needs_deeper_probe"

    async def probe_round2(
        self,
        node,
        context: ExecutionContext,
        base_url: str = "",
    ) -> ProbeResult:
        """P3: Round 2 深层探测 — 使用 3 种不同技术的 payload"""
        from app.tools.base import ExecutionContext as EC

        endpoint = self._build_url(node.state.current_endpoint, base_url)
        param = node.state.current_param
        vuln_type = node.state.vuln_type
        # L2-fix: 沿用 Level0 节点的 method/form_fields
        method, form_fields = self._node_probe_method(node)

        result = ProbeResult(
            node_id=node.id,
            endpoint=endpoint,
            param=param,
            vuln_type=vuln_type,
        )

        if not endpoint:
            result.verdict = "killed"
            result.error = "empty endpoint"
            return result

        try:
            # 基线请求
            baseline = await self._send_request(endpoint, context, param=None, payload=None,
                                                method=method, form_fields=form_fields)
            result.baseline_status = baseline.get("status_code", 0)
            result.baseline_length = len(baseline.get("body", "") or "")
            result.baseline_time_ms = baseline.get("response_time_ms", 0)

            if not baseline.get("success") or result.baseline_status in (0, -1, 404):
                result.verdict = "killed"
                result.error = f"baseline failed: status={result.baseline_status}"
                return result

            # P3: 使用 3 种不同 payload
            diverse_payloads = _VULN_TYPE_DIVERSE_PAYLOADS.get(vuln_type, ["test1", "test2", "test3"])
            had_signal = False

            for payload in diverse_payloads[:3]:
                if not payload:
                    continue
                inject = await self._send_request(endpoint, context, param=param, payload=payload,
                                                   method=method, form_fields=form_fields)
                inj_status = inject.get("status_code", 0)
                inj_len = len(inject.get("body", "") or "")
                inj_time = inject.get("response_time_ms", 0)
                inj_body = inject.get("body", "") or ""
                base_body = baseline.get("body", "") or ""

                # L2-fix: SQL 错误串 — error-based SQLi 确认信号 (最高优先级)
                err = _detect_error_signal(inj_body)
                if err:
                    result.signals["sqli_error"] = err
                    had_signal = True
                    break
                # 检查任一信号
                if inj_status >= 500:
                    had_signal = True
                    break
                if abs(inj_len - result.baseline_length) > 100:
                    had_signal = True
                    break
                if inj_time - result.baseline_time_ms > 2000:
                    had_signal = True
                    break
                # 内容指纹比较
                if inj_body and base_body:
                    import re as _re2
                    if _re2.sub(r'\d+', '', base_body) != _re2.sub(r'\d+', '', inj_body):
                        had_signal = True
                        break

            if had_signal:
                result.verdict = "promoted"
            else:
                result.verdict = "killed"
                result.error = "no_signal_after_6_probes"

        except Exception as e:
            result.verdict = "killed"
            result.error = str(e)[:200]

        return result

    def _build_url(self, endpoint: str, base_url: str) -> str:
        """构建完整 URL"""
        if not endpoint:
            return ""
        if endpoint.startswith("http"):
            return endpoint
        base = base_url.rstrip("/")
        path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        return f"{base}{path}"

    async def _send_request(
        self,
        url: str,
        context: ExecutionContext,
        param: str | None = None,
        payload: str | None = None,
        method: str = "GET",
        form_fields: list[str] | None = None,
    ) -> dict:
        """发送探测 HTTP 请求 (零 LLM, 纯 httpx)

        L2-fix: 支持 POST + 用侦察到的完整表单字段重构 body
        (旧实现只 GET, POST-only 形参端点永远打不到)。
        """
        import httpx

        if not url:
            return {"success": False, "status_code": -1, "error": "empty url"}

        method = (method or "GET").upper()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(min(context.timeout, 10)),
                verify=False,
                follow_redirects=False,
            ) as client:
                import time
                start = time.monotonic()

                if method == "POST":
                    # 用完整表单字段重构 body, 命中参数填 payload, 其余填空/默认
                    fields = list(form_fields) if form_fields else ([param] if param else [])
                    body_dict: dict[str, str] = {}
                    if param and payload is not None:
                        body_dict[param] = str(payload)
                    # 补全其余必填字段 (空值), 避免后端校验拒收
                    for f in fields:
                        if f and f not in body_dict:
                            body_dict[f] = ""
                    post_body = urlencode(body_dict, doseq=True)
                    resp = await client.post(
                        url, content=post_body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                else:
                    if param and payload is not None:
                        separator = "&" if "?" in url else "?"
                        full_url = f"{url}{separator}{param}={payload}"
                        resp = await client.get(full_url)
                    else:
                        resp = await client.get(url)

                elapsed_ms = int((time.monotonic() - start) * 1000)
                body = resp.text[:50000] if resp.text else ""  # P2-5: 从 3000 提高到 50000

                return {
                    "success": True,
                    "status_code": resp.status_code,
                    "body": body,
                    "response_time_ms": elapsed_ms,
                    "headers": dict(resp.headers),
                }
        except Exception as e:
            return {
                "success": False,
                "status_code": -1,
                "error": str(e)[:200],
                "response_time_ms": 0,
            }

    def _node_probe_method(self, node) -> tuple[str, list[str]]:
        """L2-fix: 从节点 endpoint_metadata 读取 http_method/form_fields"""
        meta = getattr(node, "endpoint_metadata", {}) or {}
        method = str(meta.get("http_method", "GET")).upper()
        fields = list(meta.get("form_fields", []) or [])
        return method, fields


# ──── 批量探测器 ────

class BatchProber:
    """批量执行 Level 0 探测 (并发控制)"""

    def __init__(self, max_concurrent: int = 5):
        self.prober = QuickProber()
        self.max_concurrent = max_concurrent

    async def probe_batch(
        self,
        nodes: list,
        context: ExecutionContext,
        base_url: str = "",
    ) -> list[ProbeResult]:
        """P3: 两轮探测 — Round1 快速筛选, Round2 深层探测"""
        import asyncio

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _probe_one(node):
            async with semaphore:
                return await self.prober.probe(node, context, base_url)

        async def _probe_round2(node):
            async with semaphore:
                return await self.prober.probe_round2(node, context, base_url)

        # Round 1
        tasks = [_probe_one(n) for n in nodes]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        probe_results = []
        needs_round2 = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                probe_results.append(ProbeResult(
                    node_id=nodes[i].id if i < len(nodes) else "unknown",
                    endpoint="", param=None, vuln_type="",
                    verdict="killed", error=str(r)[:200],
                ))
            else:
                probe_results.append(r)
                if r.verdict == "needs_deeper_probe":
                    needs_round2.append((i, nodes[i]))

        # P3: Round 2 — 对 needs_deeper_probe 的节点执行深层探测
        if needs_round2:
            logger.info("P3: Round 2 深层探测 %d 个节点...", len(needs_round2))
            r2_tasks = [_probe_round2(n) for _, n in needs_round2]
            r2_results = await asyncio.gather(*r2_tasks, return_exceptions=True)
            for (idx, _), r2 in zip(needs_round2, r2_results):
                if isinstance(r2, Exception):
                    probe_results[idx].verdict = "killed"
                    probe_results[idx].error = f"r2_error: {str(r2)[:200]}"
                else:
                    probe_results[idx] = r2  # 替换为 Round 2 结果

        promoted = sum(1 for r in probe_results if r.verdict == "promoted")
        killed = sum(1 for r in probe_results if r.verdict == "killed")
        low_signal = sum(1 for r in probe_results if r.verdict == "low_signal")
        logger.info("Batch Level 0 探测完成 (P3): %d promoted, %d killed, %d low_signal (of %d)",
                    promoted, killed, low_signal, len(probe_results))

        return probe_results
