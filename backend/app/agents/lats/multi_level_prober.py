"""
多层级探测器 (Multi-Level Prober)

Phase 3: Level 0 快速探测 — 3 次 HTTP 请求, 零 LLM 调用.
用于在投入昂贵的 Full ReAct 之前快速筛选分支.

未来可扩展: Level 1 LLM 辅助探测, Level 2 Full ReAct (复用现有逻辑).
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from app.tools.base import ExecutionContext

logger = logging.getLogger(__name__)


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


# ──── 漏洞类型 → 代表性探测 payload ────

_VULN_TYPE_PROBE_PAYLOAD: dict[str, str] = {
    "sql_injection": "' OR '1'='1",
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
        node,  # SearchNode
        context: ExecutionContext,
        base_url: str = "",
    ) -> ProbeResult:
        """
        执行 Level 0 探测

        步骤:
        1. 发送基线请求 (无注入, 不含探测参数)
        2. 发送探测字符请求 (注入一个无害探测字符, 如 ')
        3. 发送代表性 payload 请求 (根据 vuln_type 选一个代表性 payload)

        Args:
            node: SearchNode
            context: ExecutionContext
            base_url: 目标基础 URL

        Returns:
            ProbeResult (含 verdict: "promoted" | "killed")
        """
        endpoint = self._build_url(node.state.current_endpoint, base_url)
        param = node.state.current_param
        vuln_type = node.state.vuln_type

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
            # Step 1: 基线请求
            baseline = await self._send_request(endpoint, context, param=None, payload=None)
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

            # Step 2: 探测字符 (泛用探测)
            probe_char = "'" if vuln_type in ("sql_injection", "xss", "ssti", "lfi") else "."
            probe = await self._send_request(endpoint, context, param=param, payload=probe_char)
            result.probe_status = probe.get("status_code", 0)
            result.probe_length = len(probe.get("body", "") or "")
            result.probe_time_ms = probe.get("response_time_ms", 0)

            # 探测字符请求失败 → 标记但继续
            if not probe.get("success"):
                result.signals["probe_failed"] = True

            # Step 3: 代表性 payload
            probe_payload = _VULN_TYPE_PROBE_PAYLOAD.get(vuln_type, "test")
            if probe_payload:
                inject = await self._send_request(endpoint, context, param=param, payload=probe_payload)
                result.inject_status = inject.get("status_code", 0)
                result.inject_length = len(inject.get("body", "") or "")
                result.inject_time_ms = inject.get("response_time_ms", 0)

            # ── 分类判定 ──
            result.verdict = self._classify(result)

        except Exception as e:
            result.verdict = "needs_retry"
            result.error = str(e)[:200]
            logger.warning("Level 0 探测异常 [%s]: %s", endpoint, str(e))

        return result

    def _classify(self, r: ProbeResult) -> str:
        """基于探测结果的三分类 (v2-fix: 收紧阈值 + vuln_type 特化)"""
        signals = r.signals

        # ── info_disclosure 特殊处理 ──
        if r.vuln_type == "info_disclosure":
            # baseline 200 + 有内容 (>500 bytes) → 值得探索
            if r.baseline_status == 200 and r.baseline_length > 500:
                signals["info_disclosure_content"] = True
                return "promoted"
            # baseline 404/403/401 → 不可访问, 直接 killed
            if r.baseline_status in (404, 403, 401):
                return "killed"
            # baseline 200 但内容很少 (<100 bytes) → 可能无价值
            if r.baseline_status == 200 and r.baseline_length < 100:
                return "killed"

        # ── auth_bypass 特殊处理 ──
        if r.vuln_type == "auth_bypass":
            # 401/403 → 需要认证, 值得测试绕过
            if r.baseline_status in (401, 403):
                return "promoted"
            # 200 → 无需认证即可访问, done
            if r.baseline_status == 200 and r.baseline_length > 200:
                signals["already_accessible"] = True
                return "promoted"

        # ── 明确死路 ──
        if r.baseline_status == 404:
            signals["endpoint_404"] = True
            return "killed"
        # v4-fix: 403 细化 — auth_bypass 可能绕过, 其他类型直接 killed
        if r.baseline_status == 403:
            if r.vuln_type == "auth_bypass":
                signals["waf_or_auth"] = True  # auth_bypass 节点: 403 值得尝试绕过
            else:
                return "killed"  # 非 auth_bypass: 403 拿不到内容, 无法测试
        # v4-fix: 401 → killed (需要凭据, 无凭据无法测试)
        if r.baseline_status == 401:
            return "killed"
        if r.probe_status == 403 and r.baseline_status != 403:
            signals["waf_triggered"] = True
            if r.vuln_type != "auth_bypass":
                return "killed"
        if r.inject_status == 0 and r.probe_status == 0:
            return "killed"
        # v4-fix: baseline+probe+inject 全部返回相同 403 → killed
        if (r.baseline_status == 403 and r.probe_status == 403 and r.inject_status == 403):
            return "killed"
        if r.baseline_status in (500, 502, 503):
            signals["server_error"] = True

        # ── 有信号 → promoted (v2-fix: 收紧阈值) ──
        if r.probe_status != r.baseline_status:
            signals["status_change"] = True
        # v2-fix: 长度差异阈值从 50→100 bytes
        if abs(r.probe_length - r.baseline_length) > 100:
            signals["length_change"] = True
        # v2-fix: 时间差异阈值保持 2000ms (时间盲注有意义)
        if r.probe_time_ms - r.baseline_time_ms > 2000:
            signals["time_anomaly"] = True
        if r.inject_status != r.baseline_status and r.inject_status > 0:
            signals["inject_status_change"] = True
        # v2-fix: 注入长度差异阈值从 100→200 bytes
        if abs(r.inject_length - r.baseline_length) > 200:
            signals["inject_length_change"] = True
        if r.inject_time_ms - r.baseline_time_ms > 2000:
            signals["inject_time_anomaly"] = True

        # v2-fix: 收紧无变化条件 — 长度阈值 20→80 bytes, 时间 1000→2000ms
        no_change = (
            r.probe_status == r.baseline_status
            and abs(r.probe_length - r.baseline_length) < 80
            and abs(r.inject_length - r.baseline_length) < 80
            and r.probe_time_ms - r.baseline_time_ms < 2000
            and r.inject_time_ms - r.baseline_time_ms < 2000
        )

        if no_change:
            signals["no_response_change"] = True
            # v7: 三态判定 — 基线 200 但无差异 → low_signal (不杀, 降级保留)
            if r.baseline_status == 200 and r.vuln_type not in ("info_disclosure",):
                return "low_signal"
            return "killed"

        if any(signals.values()):
            return "promoted"

        return "killed"

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
    ) -> dict:
        """发送探测 HTTP 请求 (零 LLM, 纯 httpx)"""
        import httpx

        if not url:
            return {"success": False, "status_code": -1, "error": "empty url"}

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(min(context.timeout, 10)),
                verify=False,
                follow_redirects=False,
            ) as client:
                import time
                start = time.monotonic()

                if param and payload:
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


# ──── 批量探测器 ────

class BatchProber:
    """批量执行 Level 0 探测 (并发控制)"""

    def __init__(self, max_concurrent: int = 5):
        self.prober = QuickProber()
        self.max_concurrent = max_concurrent

    async def probe_batch(
        self,
        nodes: list,  # list[SearchNode]
        context: ExecutionContext,
        base_url: str = "",
    ) -> list[ProbeResult]:
        """批量探测一批节点 (在被选为 Full ReAct 之前快速筛选)"""
        import asyncio

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _probe_one(node) -> ProbeResult:
            async with semaphore:
                return await self.prober.probe(node, context, base_url)

        tasks = [_probe_one(n) for n in nodes]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        probe_results = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                probe_results.append(ProbeResult(
                    node_id=nodes[i].id if i < len(nodes) else "unknown",
                    endpoint="", param=None, vuln_type="",
                    verdict="killed", error=str(r)[:200],
                ))
            else:
                probe_results.append(r)

        promoted = sum(1 for r in probe_results if r.verdict == "promoted")
        killed = sum(1 for r in probe_results if r.verdict == "killed")
        logger.info("Batch Level 0 探测完成: %d promoted, %d killed (of %d)",
                    promoted, killed, len(probe_results))

        return probe_results
