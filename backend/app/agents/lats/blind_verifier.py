"""
统一盲漏洞验证引擎 (v21)

提供四种通用的旁路检测方法，对任何漏洞类型适用：
1. Time-based:  通过响应时间异常确认
2. Boolean-based: 通过真/假条件响应差异确认
3. Error-based: 通过错误消息触发确认
4. OOB callback: 通过外部回调确认 (Phase 2)

将盲检测从 _detect_vuln_indicators 中解耦，
实现"漏洞类型特定检测"与"通用旁路检测"的分层架构。
"""

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class BlindResult:
    """盲检测结果"""
    confirmed: bool = False
    method: str = ""          # "time" | "boolean" | "error" | "oob"
    confidence: float = 0.0
    evidence: str = ""
    vuln_type: str = ""


class BlindVerifier:
    """统一盲漏洞验证器 — 对所有漏洞类型提供旁路检测"""

    # ── 时间盲注配置 ──
    TIME_THRESHOLD_MS: int = 3000
    TIME_ANOMALY_CONFIDENCE: float = 0.85

    # ── 布尔盲注配置 ──
    BOOLEAN_LEN_DIFF_THRESHOLD: int = 50
    BOOLEAN_CONFIDENCE: float = 0.7
    BOOLEAN_MIN_SIGNALS: int = 2  # 至少需要几个独立信号才确认

    # ── 各漏洞类型的时间延迟 payload 模式 ──
    VULN_TYPE_SLEEP_PATTERNS: dict = {
        "rce": [r'sleep\s+\d+', r'ping\s+-[nc]\s+\d+', r'timeout\s+\d+'],
        "sql_injection": [r'sleep\s+\d+', r'pg_sleep', r'WAITFOR\s+DELAY', r'BENCHMARK'],
        "lfi": [r'/dev/zero', r'/dev/urandom'],
        "ssti": [r'sleep\s+\d+'],
        "ssrf": [r'timeout\s+\d+'],
        "*": [r'sleep\s+\d+', r'timeout\s+\d+'],
    }

    # ── 各漏洞类型的错误触发模式 ──
    VULN_TYPE_ERROR_PATTERNS: dict = {
        "sql_injection": ["sql syntax", "mysql_fetch", "unclosed quotation",
                          "you have an error in your sql", "ora-01756", "sqlite3"],
        "rce": ["traceback", "stack trace", "fatal error",
                "command not found", "sh:", "bash:", "Traceback"],
        "lfi": ["failed to open stream", "no such file", "include(",
                "require(", "warning: include", "warning: require"],
        "ssti": ["undefined variable", "unexpected token", "template error",
                 "jinja2", "werkzeug", "TemplateSyntaxError"],
        "xss": [],
        "ssrf": ["connection refused", "name resolution", "could not connect",
                 "No address associated", "getaddrinfo"],
        "idor": ["unauthorized", "forbidden", "access denied"],
        "*": ["traceback", "exception", "stack trace", "debug", "error"],
    }

    def detect_time_based(
        self,
        response_time_ms: int,
        baseline_time_ms: int,
        payload: str,
        vuln_type: str = "",
    ) -> BlindResult:
        """时间盲注检测 — 响应时间显著超过阈值"""
        time_diff = response_time_ms - baseline_time_ms
        if time_diff < self.TIME_THRESHOLD_MS:
            return BlindResult()

        patterns = self.VULN_TYPE_SLEEP_PATTERNS.get(
            vuln_type, self.VULN_TYPE_SLEEP_PATTERNS["*"]
        )
        has_sleep = any(re.search(p, payload, re.IGNORECASE) for p in patterns)
        if not has_sleep:
            return BlindResult()

        return BlindResult(
            confirmed=True,
            method="time",
            confidence=self.TIME_ANOMALY_CONFIDENCE,
            evidence=f"响应时间异常: baseline={baseline_time_ms}ms → injected={response_time_ms}ms (diff={time_diff}ms)",
            vuln_type=vuln_type,
        )

    def detect_boolean_based(
        self,
        body: str,
        baseline_body: str,
        body_len: int,
        baseline_len: int,
        status_code: int,
        baseline_status: int,
    ) -> BlindResult:
        """布尔盲注检测 — true/false 条件产生可复现的结构性差异"""
        signals = []

        # 1. 状态码差异
        if status_code != baseline_status and baseline_status != 0:
            signals.append(f"status {baseline_status}→{status_code}")

        # 2. 长度差异
        len_diff = abs(body_len - baseline_len)
        if len_diff > self.BOOLEAN_LEN_DIFF_THRESHOLD:
            signals.append(f"len_diff={len_diff}")

        # 3. 内容指纹差异（去数字后比较）
        if body and baseline_body and body != baseline_body:
            bl_fp = re.sub(r'\d+', '', baseline_body)
            r_fp = re.sub(r'\d+', '', body)
            if bl_fp != r_fp:
                signals.append("content_fingerprint_diff")

        # 4. HTML 结构差异（表格行数、列表项数）
        if body and baseline_body:
            bl_tables = len(re.findall(r'<tr[^>]*>', baseline_body, re.IGNORECASE))
            r_tables = len(re.findall(r'<tr[^>]*>', body, re.IGNORECASE))
            if bl_tables != r_tables:
                signals.append(f"tables {bl_tables}→{r_tables}")
            bl_lists = len(re.findall(r'<li[^>]*>', baseline_body, re.IGNORECASE))
            r_lists = len(re.findall(r'<li[^>]*>', body, re.IGNORECASE))
            if bl_lists != r_lists:
                signals.append(f"lists {bl_lists}→{r_lists}")

        if len(signals) >= self.BOOLEAN_MIN_SIGNALS:
            return BlindResult(
                confirmed=True,
                method="boolean",
                confidence=self.BOOLEAN_CONFIDENCE,
                evidence=", ".join(signals),
            )
        return BlindResult()

    def detect_error_based(
        self, body: str, vuln_type: str = ""
    ) -> BlindResult:
        """错误触发检测 — 注入触发特定错误消息"""
        body_lower = body.lower()
        patterns = self.VULN_TYPE_ERROR_PATTERNS.get(
            vuln_type, self.VULN_TYPE_ERROR_PATTERNS["*"]
        )
        for pattern in patterns:
            if pattern in body_lower:
                return BlindResult(
                    confirmed=True,
                    method="error",
                    confidence=0.8,
                    evidence=f"错误消息: '{pattern}'",
                    vuln_type=vuln_type,
                )
        return BlindResult()

    def verify(
        self,
        payload: str = "",
        body: str = "",
        time_ms: int = 0,
        status: int = 0,
        vuln_type: str = "",
        baseline_body: str = "",
        baseline_len: int = 0,
        baseline_status: int = 0,
        baseline_time_ms: int = 0,
    ) -> BlindResult | None:
        """综合验证 — 依次尝试三种盲检测方法，返回第一个确认的结果

        检测顺序按置信度降序排列：
        1. 时间盲注 (最高置信度 0.85)
        2. 错误触发 (置信度 0.8)
        3. 布尔差异 (置信度 0.7)
        """
        # 1. 时间盲注 (对 RCE/SSRF/LFI 都适用)
        result = self.detect_time_based(
            time_ms, baseline_time_ms, payload, vuln_type
        )
        if result.confirmed:
            return result

        # 2. 错误触发 (对 SQLi/RCE/LFI/SSTI 适用)
        result = self.detect_error_based(body, vuln_type)
        if result.confirmed:
            return result

        # 3. 布尔差异 (通用，但需要基线数据)
        if baseline_body and baseline_len > 0:
            result = self.detect_boolean_based(
                body, baseline_body,
                len(body) if body else 0, baseline_len,
                status, baseline_status,
            )
            if result.confirmed:
                return result

        return None


# 全局单例
_blind_verifier: BlindVerifier | None = None


def get_blind_verifier() -> BlindVerifier:
    """获取全局 BlindVerifier 单例"""
    global _blind_verifier
    if _blind_verifier is None:
        _blind_verifier = BlindVerifier()
    return _blind_verifier
