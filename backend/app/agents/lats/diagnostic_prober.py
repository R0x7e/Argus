"""
诊断探测器 (v21 — HDE 架构 Phase 1)

在 Agent 遇到 SAME_AS_BASELINE 时，通过一系列诊断 payload 精确判定失败原因。
区分六种情况: FILTERED_BYPASSABLE, FILTERED_HARD, WRONG_PARAM, WRONG_METHOD,
BLIND_EXEC, NO_VULN.

关键设计: ECHO_MARKER 使用反引号 `echo MARKER` 和 $(echo MARKER)
而非 ; echo MARKER，因为前者不被 escapeshellcmd() 转义。
"""

import asyncio
import uuid
from enum import Enum

from app.tools.base import ExecutionContext


class DiagResult(str, Enum):
    """诊断结果分类"""
    FILTERED_BYPASSABLE = "filtered_bypassable"  # 过滤可绕过(编码/分隔符)
    FILTERED_HARD = "filtered_hard"               # 过滤不可绕过
    WRONG_PARAM = "wrong_param"                    # 参数未被处理
    WRONG_METHOD = "wrong_method"                  # 需切换 HTTP 方法
    BLIND_EXEC = "blind_exec"                      # 命令执行但无回显
    NO_VULN = "no_vuln"                            # 确定无漏洞


# 诊断 MARKER 前缀 (确保唯一性)
def _diag_marker() -> str:
    return f"DIAG_{uuid.uuid4().hex[:8].upper()}"


# ── 漏洞类型特定的回显 payload ──

_VULN_TYPE_ECHO_PAYLOADS: dict[str, list[str]] = {
    "rce": [
        "`echo {MARKER}`",        # 反引号, 不被 escapeshellcmd 转义
        "$(echo {MARKER})",        # 命令替换, 不被 escapeshellcmd 转义
    ],
    "sql_injection": [
        "' UNION SELECT '{MARKER}'-- ",
        "' AND 1=2 UNION SELECT '{MARKER}'-- ",
    ],
    "ssti": [
        "{{ '{MARKER}' }}",
        "${ '{MARKER}' }",
    ],
    "xss": [
        "<script>document.write('{MARKER}')</script>",
        "'-alert('{MARKER}')-'",
    ],
    "lfi": [
        "php://filter/convert.base64-encode/resource={MARKER}",
    ],
    "*": [
        "{MARKER}",  # 通用回退: 直接注入 MARKER 字符串
    ],
}


class DiagnosticProber:
    """诊断探测器

    在 Agent 连续 2 次遇到 SAME_AS_BASELINE 后触发。
    通过 5 步诊断精确判定失败原因，反馈给 HypothesisAgent 修正假设。
    """

    def __init__(self):
        # 诊断结果缓存: (endpoint, param) → DiagResult
        self._cache: dict[str, DiagResult] = {}

    def _cache_key(self, endpoint_url: str, param: str, payload_class: str) -> str:
        return f"{endpoint_url}|{param}|{payload_class}"

    async def diagnose(
        self,
        endpoint_url: str,
        param: str,
        original_payload: str,
        vuln_type: str,
        baseline_response: dict,
        other_params: list[str],
        context: ExecutionContext,
    ) -> DiagResult:
        """主诊断入口 — 依次执行诊断步骤，首个匹配即返回

        Args:
            endpoint_url: 目标完整 URL
            param: 当前测试的参数名
            original_payload: 原始(失败的) payload
            vuln_type: 当前假设的漏洞类型
            baseline_response: 基线响应 {status, body, len, time_ms, headers}
            other_params: 其他可用参数名列表
            context: 执行上下文

        Returns:
            DiagResult 诊断分类
        """
        # 检查缓存
        cache_key = self._cache_key(endpoint_url, param, vuln_type)
        if cache_key in self._cache:
            return self._cache[cache_key]

        marker = _diag_marker()

        # ── 步骤 0: FILTER_PROBE (仅 RCE) ──
        if vuln_type == "rce":
            result = await self._step_filter_probe(
                endpoint_url, param, marker, baseline_response, context
            )
            if result is not None:
                self._cache[cache_key] = result
                return result

        # ── 步骤 1: ECHO_MARKER ──
        result = await self._step_echo_marker(
            endpoint_url, param, marker, vuln_type, baseline_response, context
        )
        if result is not None:
            self._cache[cache_key] = result
            return result

        # ── 步骤 2: METHOD_SWITCH ──
        result = await self._step_method_switch(
            endpoint_url, param, original_payload, baseline_response, context
        )
        if result is not None:
            self._cache[cache_key] = result
            return result

        # ── 步骤 3: PARAM_SWITCH ──
        if other_params:
            result = await self._step_param_switch(
                endpoint_url, param, other_params, original_payload,
                baseline_response, context
            )
            if result is not None:
                self._cache[cache_key] = result
                return result

        # ── 步骤 4: ENCODING_TEST ──
        result = await self._step_encoding_test(
            endpoint_url, param, original_payload, baseline_response, context
        )
        if result is not None:
            self._cache[cache_key] = result
            return result

        # ── 步骤 5: DEFAULT ──
        result = DiagResult.NO_VULN
        self._cache[cache_key] = result
        return result

    # ──── 诊断步骤实现 ────

    async def _step_filter_probe(
        self, endpoint_url: str, param: str, marker: str,
        baseline: dict, context: ExecutionContext,
    ) -> DiagResult | None:
        """步骤 0: 探测 escapeshellcmd 过滤 — 使用反引号/命令替换"""
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
                # 测试反引号 (不被 escapeshellcmd 转义)
                payload_bt = f"`echo {marker}`"
                url_bt = self._build_url(endpoint_url, param, payload_bt)
                resp_bt = await client.get(url_bt)
                body_bt = resp_bt.text[:50000] if resp_bt.text else ""

                if marker in body_bt:
                    return DiagResult.FILTERED_BYPASSABLE

                # 测试命令替换 (不被 escapeshellcmd 转义)
                payload_ds = f"$(echo {marker})"
                url_ds = self._build_url(endpoint_url, param, payload_ds)
                resp_ds = await client.get(url_ds)
                body_ds = resp_ds.text[:50000] if resp_ds.text else ""

                if marker in body_ds:
                    return DiagResult.FILTERED_BYPASSABLE
        except Exception:
            pass
        return None

    async def _step_echo_marker(
        self, endpoint_url: str, param: str, marker: str,
        vuln_type: str, baseline: dict, context: ExecutionContext,
    ) -> DiagResult | None:
        """步骤 1: ECHO_MARKER — 检测命令是否被执行但无回显"""
        import httpx
        payloads = _VULN_TYPE_ECHO_PAYLOADS.get(
            vuln_type, _VULN_TYPE_ECHO_PAYLOADS["*"]
        )
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
                for payload_template in payloads[:3]:
                    payload = payload_template.replace("{MARKER}", marker)
                    url = self._build_url(endpoint_url, param, payload)
                    resp = await client.get(url)
                    body = resp.text[:50000] if resp.text else ""

                    if marker in body:
                        return DiagResult.BLIND_EXEC
        except Exception:
            pass
        return None

    async def _step_method_switch(
        self, endpoint_url: str, param: str, original_payload: str,
        baseline: dict, context: ExecutionContext,
    ) -> DiagResult | None:
        """步骤 2: METHOD_SWITCH — 改用 POST 测试"""
        import httpx
        baseline_body = baseline.get("body", "")
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
                resp = await client.post(
                    endpoint_url,
                    data={param: original_payload},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                body = resp.text[:50000] if resp.text else ""
                if body != baseline_body and resp.status_code == 200:
                    return DiagResult.WRONG_METHOD
        except Exception:
            pass
        return None

    async def _step_param_switch(
        self, endpoint_url: str, current_param: str,
        other_params: list[str], original_payload: str,
        baseline: dict, context: ExecutionContext,
    ) -> DiagResult | None:
        """步骤 3: PARAM_SWITCH — 测试其他参数"""
        import httpx
        baseline_body = baseline.get("body", "")
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
                for alt_param in other_params[:3]:  # 最多测试 3 个替代参数
                    if alt_param == current_param:
                        continue
                    url = self._build_url(endpoint_url, alt_param, original_payload)
                    resp = await client.get(url)
                    body = resp.text[:50000] if resp.text else ""
                    if body != baseline_body:
                        return DiagResult.WRONG_PARAM
        except Exception:
            pass
        return None

    async def _step_encoding_test(
        self, endpoint_url: str, param: str, original_payload: str,
        baseline: dict, context: ExecutionContext,
    ) -> DiagResult | None:
        """步骤 4: ENCODING_TEST — URL编码/双编码绕过"""
        import httpx
        from urllib.parse import quote
        baseline_body = baseline.get("body", "")
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
                # 单次 URL 编码
                encoded_once = quote(original_payload, safe="")
                url1 = self._build_url(endpoint_url, param, encoded_once)
                resp1 = await client.get(url1)
                if resp1.text and resp1.text[:50000] != baseline_body:
                    return DiagResult.FILTERED_BYPASSABLE

                # 双次 URL 编码
                encoded_twice = quote(encoded_once, safe="")
                url2 = self._build_url(endpoint_url, param, encoded_twice)
                resp2 = await client.get(url2)
                if resp2.text and resp2.text[:50000] != baseline_body:
                    return DiagResult.FILTERED_BYPASSABLE
        except Exception:
            pass
        return None

    def _build_url(self, endpoint_url: str, param: str, payload: str) -> str:
        """构造带参数的 URL"""
        sep = "&" if "?" in endpoint_url else "?"
        return f"{endpoint_url}{sep}{param}={payload}"
