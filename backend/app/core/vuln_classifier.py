"""
上下文感知漏洞类型分类器 (v3)

综合多维度信息将参数+端点映射到最可能的漏洞类型。

信号源:
1. URL路径语义 (weight=0.40, 可自适应)
2. HTTP方法语义 (weight=0.15)
3. 参数名语义 (weight=0.40)
4. 页面上下文 (weight=0.05, 可选)

设计原则:
- 每种信号源独立计算 → 加权融合 → 输出排序得分列表
- 权重可根据网站类型自适应调整
- 纯静态分类, 不产生HTTP请求

解决根本问题: 参数→漏洞类型关联断裂 (ipaddress→sqli 而非 rce)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VulnTypeScore:
    """漏洞类型得分"""
    vuln_type: str
    score: float         # 0.0-1.0
    reasoning: str = ""  # 分类理由


# ──── 信号映射表 ────

# URL路径片段 → 漏洞类型 (高置信度信号)
URL_VULN_SIGNALS: dict[str, list[str]] = {
    "rce":     ["rce", "command_injection"],
    "sqli":    ["sql_injection"],
    "sql":     ["sql_injection"],
    "xss":     ["xss"],
    "ssrf":    ["ssrf"],
    "lfi":     ["lfi", "path_traversal"],
    "fileinclude": ["lfi", "path_traversal"],
    "file":    ["lfi", "path_traversal"],
    "upload":  ["file_upload", "rce"],
    "csrf":    ["csrf"],
    "idor":    ["idor"],
    "burteforce": ["auth_bypass"],
    "overpermission": ["idor", "auth_bypass"],
    "xxe":     ["xxe"],
    "unser":   ["deserialization"],
    "ssti":    ["ssti"],
    "redirect":["open_redirect"],
    "urlredirect": ["open_redirect"],
    "download":["path_traversal"],
    "infoleak": ["info_disclosure"],
    "dir":     ["path_traversal"],
    "exec":    ["rce"],
    "cmd":     ["rce"],
    "ping":    ["rce", "ssrf"],         # ← Pikachu案例关键!
    "shell":   ["rce"],
    "run":     ["rce"],
    "eval":    ["rce", "ssti"],
}

# 参数名 → 漏洞类型 (高置信度信号)
PARAM_VULN_SIGNALS: dict[str, list[str]] = {
    "ipaddress": ["rce", "ssrf"],
    "ip":        ["rce", "ssrf"],
    "host":      ["rce", "ssrf"],
    "target":    ["rce", "ssrf"],
    "domain":    ["ssrf"],
    "address":   ["rce", "ssrf"],
    "cmd":       ["rce"],
    "command":   ["rce"],
    "exec":      ["rce"],
    "code":      ["rce", "ssti"],
    "file":      ["lfi", "path_traversal", "file_upload"],
    "filename":  ["lfi", "path_traversal"],
    "path":      ["lfi", "path_traversal"],
    "include":   ["lfi"],
    "page":      ["lfi", "path_traversal"],
    "template":  ["ssti", "lfi"],
    "url":       ["ssrf", "open_redirect"],
    "link":      ["ssrf", "open_redirect"],
    "redirect":  ["open_redirect"],
    "next":      ["open_redirect"],
    "to":        ["open_redirect"],
    "callback":  ["ssrf"],
    "hook":      ["ssrf"],
    "webhook":   ["ssrf"],
    "id":        ["idor", "sql_injection", "xss"],
    "uid":       ["idor"],
    "user_id":   ["idor"],
    "user":      ["idor", "auth_bypass"],
    "username":  ["auth_bypass", "sql_injection"],
    "password":  ["auth_bypass"],
    "passwd":    ["auth_bypass"],
    "pwd":       ["auth_bypass"],
    "token":     ["auth_bypass", "csrf"],
    "jwt":       ["auth_bypass"],
    "auth":      ["auth_bypass"],
    "api_key":   ["info_disclosure"],
    "apikey":    ["info_disclosure"],
    "q":         ["xss", "sql_injection"],
    "query":     ["xss", "sql_injection"],
    "search":    ["xss", "sql_injection"],
    "keyword":   ["xss", "sql_injection"],
    "name":      ["xss", "sql_injection"],
    "title":     ["xss"],
    "message":   ["xss"],
    "comment":   ["xss"],
    "body":      ["xss"],
    "content":   ["xss"],
    "description": ["xss"],
    "email":     ["xss", "idor"],
    "phone":     ["idor"],
    "order":     ["idor"],
    "order_id":  ["idor"],
    "amount":    ["idor"],
    "price":     ["idor"],
    "submit":    [],  # 提交按钮, 无直接漏洞关联
    "debug":     ["info_disclosure"],
    "test":      ["info_disclosure"],
}

# HTTP方法 → 漏洞类型提示
METHOD_VULN_HINTS: dict[str, list[str]] = {
    "GET":     ["idor", "xss", "open_redirect"],
    "POST":    ["sql_injection", "rce", "xss", "file_upload", "auth_bypass"],
    "PUT":     ["idor", "mass_assignment"],
    "PATCH":   ["idor", "mass_assignment"],
    "DELETE":  ["idor"],
    "OPTIONS": ["info_disclosure"],
}


class ContextAwareVulnClassifier:
    """
    上下文感知漏洞类型分类器

    Usage:
        scores = ContextAwareVulnClassifier.classify(
            url="http://target.com/vul/rce/rce_ping.php",
            param_name="ipaddress",
        )
        for vs in scores:
            print(f"{vs.vuln_type}: {vs.score:.2f} - {vs.reasoning}")
    """

    # 默认权重 (传统HTML站点)
    URL_WEIGHT = 0.40
    PARAM_WEIGHT = 0.40
    METHOD_WEIGHT = 0.15
    CONTEXT_WEIGHT = 0.05

    @classmethod
    def classify(
        cls,
        url: str,
        param_name: str,
        method: str = "GET",
        parent_vuln_type: str | None = None,
        page_type: str | None = None,
        tech_stack: list[str] | None = None,
        form_type: str | None = None,
    ) -> list[VulnTypeScore]:
        """
        主分类入口。

        Args:
            url: 端点URL
            param_name: 参数名
            method: HTTP方法 (GET/POST/PUT...)
            parent_vuln_type: 父节点的漏洞类型 (仅作微弱参考)
            page_type: 页面类型 (login/form/api_doc/static)
            tech_stack: 技术栈指纹列表
            form_type: 表单类型 (login/search/upload/command)

        Returns:
            按score降序排列的漏洞类型得分列表
        """
        # 自适应权重: 根据网站类型调整
        weights = cls._adaptive_weights(page_type, url)

        scores: dict[str, float] = {}
        reasonings: dict[str, list[str]] = {}

        # 1. URL语义 (通常最强信号)
        url_signals = cls._from_url(url)
        for vt, conf in url_signals:
            scores[vt] = scores.get(vt, 0) + conf * weights["url"]
            reasonings.setdefault(vt, []).append(f"URL: {vt}({conf:.2f})")

        # 2. 参数语义
        param_signals = cls._from_param(param_name, method)
        for vt, conf in param_signals:
            scores[vt] = scores.get(vt, 0) + conf * weights["param"]
            reasonings.setdefault(vt, []).append(f"PARAM:{param_name}→{vt}({conf:.2f})")

        # 3. HTTP方法语义
        method_signals = cls._from_method(method)
        for vt, conf in method_signals:
            scores[vt] = scores.get(vt, 0) + conf * weights["method"]
            reasonings.setdefault(vt, []).append(f"METHOD:{method}→{vt}({conf:.2f})")

        # 4. 页面上下文
        if form_type or page_type:
            ctx_signals = cls._from_context(form_type, page_type)
            for vt, conf in ctx_signals:
                scores[vt] = scores.get(vt, 0) + conf * weights["context"]
                reasonings.setdefault(vt, []).append(f"CTX:{form_type or page_type}→{vt}({conf:.2f})")

        # 5. 父节点类型 (微弱参考, 仅在无其他信号时生效)
        if parent_vuln_type and parent_vuln_type not in scores:
            scores[parent_vuln_type] = 0.03
            reasonings.setdefault(parent_vuln_type, []).append("PARENT:inherited(0.03)")

        # 6. 技术栈调整
        if tech_stack:
            adjustment = cls._from_tech_stack(tech_stack)
            for vt, adj in adjustment.items():
                if vt in scores:
                    scores[vt] = min(1.0, scores[vt] + adj)
                    reasonings.setdefault(vt, []).append(f"TECH:{tech_stack}(+{adj:.2f})")

        # 排序输出
        sorted_scores = sorted(
            [
                VulnTypeScore(
                    vuln_type=vt,
                    score=min(1.0, round(s, 4)),
                    reasoning="; ".join(reasonings.get(vt, [])),
                )
                for vt, s in scores.items()
                if s > 0.0
            ],
            key=lambda x: x.score,
            reverse=True,
        )

        return sorted_scores

    @classmethod
    def _adaptive_weights(cls, page_type: str | None, url: str) -> dict[str, float]:
        """根据网站类型自适应调整权重"""
        if page_type == "api_doc":
            return {"url": 0.30, "param": 0.45, "method": 0.20, "context": 0.05}
        if page_type in ("spa",):
            return {"url": 0.15, "param": 0.50, "method": 0.25, "context": 0.10}
        if "/graphql" in url.lower():
            return {"url": 0.05, "param": 0.60, "method": 0.30, "context": 0.05}
        return {
            "url": cls.URL_WEIGHT,
            "param": cls.PARAM_WEIGHT,
            "method": cls.METHOD_WEIGHT,
            "context": cls.CONTEXT_WEIGHT,
        }

    @classmethod
    def _from_url(cls, url: str) -> list[tuple[str, float]]:
        """从URL路径提取漏洞类型信号"""
        path = url.split("?")[0].lower()
        segments = re.split(r'[/_.\-]', path)
        signals: dict[str, float] = {}

        for seg in segments:
            if seg in URL_VULN_SIGNALS:
                # 路径越深层级, 信号越强
                strength = 0.7 + 0.1 * min(3, segments.count(seg))
                for vt in URL_VULN_SIGNALS[seg]:
                    current = signals.get(vt, 0)
                    signals[vt] = max(current, strength)

        return [(vt, min(1.0, s)) for vt, s in signals.items()]

    @classmethod
    def _from_param(cls, param_name: str, method: str) -> list[tuple[str, float]]:
        """从参数名提取漏洞类型信号"""
        param_lower = param_name.lower().strip()
        signals: list[tuple[str, float]] = []

        # 精确匹配
        if param_lower in PARAM_VULN_SIGNALS:
            vuln_types = PARAM_VULN_SIGNALS[param_lower]
            if not vuln_types:
                return []
            weight = 0.95 / len(vuln_types)
            for vt in vuln_types:
                signals.append((vt, weight))
            return signals

        # 模糊匹配: 参数名包含已知关键词
        for known_param, vuln_types in PARAM_VULN_SIGNALS.items():
            if not vuln_types:
                continue
            if known_param in param_lower or param_lower in known_param:
                weight = 0.6 / len(vuln_types)
                for vt in vuln_types:
                    signals.append((vt, weight))

        # POST + 无已知匹配 → 补充通用类型
        if not signals and method.upper() == "POST":
            signals.append(("rce", 0.15))
            signals.append(("sql_injection", 0.15))
            signals.append(("xss", 0.10))

        return signals

    @classmethod
    def _from_method(cls, method: str) -> list[tuple[str, float]]:
        """从HTTP方法提取漏洞类型提示"""
        hints = METHOD_VULN_HINTS.get(method.upper(), [])
        if not hints:
            return []
        weight = 0.3 / len(hints)
        return [(vt, weight) for vt in hints]

    @classmethod
    def _from_context(
        cls, form_type: str | None, page_type: str | None
    ) -> list[tuple[str, float]]:
        """从页面上下文提取漏洞类型提示"""
        signals: list[tuple[str, float]] = []

        if form_type == "command":
            signals.append(("rce", 0.4))
            signals.append(("ssrf", 0.2))
        elif form_type == "login":
            signals.append(("auth_bypass", 0.5))
            signals.append(("sql_injection", 0.3))
        elif form_type == "search":
            signals.append(("xss", 0.3))
            signals.append(("sql_injection", 0.3))
        elif form_type == "upload":
            signals.append(("file_upload", 0.5))
            signals.append(("rce", 0.2))

        if page_type == "login":
            signals.append(("auth_bypass", 0.3))
            signals.append(("sql_injection", 0.2))

        return signals

    @classmethod
    def _from_tech_stack(cls, tech_stack: list[str]) -> dict[str, float]:
        """从技术栈指纹调整得分"""
        adj: dict[str, float] = {}
        ts_lower = [t.lower() for t in tech_stack]

        if "wordpress" in ts_lower:
            adj["sql_injection"] = 0.05
            adj["auth_bypass"] = 0.03
        if "laravel" in ts_lower:
            adj["ssti"] = 0.05
            adj["sql_injection"] = 0.03
        if "php" in ts_lower:
            adj["lfi"] = 0.03
            adj["rce"] = 0.02
        if "apache" in ts_lower:
            adj["path_traversal"] = 0.03
        if "nginx" in ts_lower:
            adj["path_traversal"] = 0.02

        return adj
