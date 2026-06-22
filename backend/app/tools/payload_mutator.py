"""
Payload 变异器工具模块

对测试载荷进行多种编码变异以绕过 WAF 和输入过滤。
支持 URL 编码、Unicode 转义、大小写变异、注释注入等多种技术。
"""

import base64
import html
import logging
import urllib.parse
from typing import Any

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

# 支持的变异技术列表
AVAILABLE_TECHNIQUES = [
    "url_encode",
    "double_encode",
    "unicode_escape",
    "case_variation",
    "comment_injection",
    "html_encode",
    "hex_encode",
    "base64_encode",
]


class PayloadMutatorTool(BaseTool):
    """
    Payload 变异器

    对漏洞测试载荷应用多种编码和变异技术，
    生成可绕过 WAF 和输入过滤的变体。
    风险等级 L0（仅做字符串变换，不发送请求）。
    """

    name = "payload_mutate"
    description = "Payload 变异器 - 对测试载荷进行编码变异以绕过过滤"
    risk_level = RiskLevel.L0

    def get_schema(self) -> dict:
        """返回 Payload 变异器的参数 JSON Schema"""
        return {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "string",
                    "description": "原始测试载荷",
                },
                "techniques": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": AVAILABLE_TECHNIQUES,
                    },
                    "description": "要应用的变异技术列表（为空时应用全部技术）",
                    "default": None,
                },
            },
            "required": ["payload"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行载荷变异

        对输入载荷应用指定的变异技术，生成所有变体。

        Args:
            params: {payload, techniques}
            context: 执行上下文

        Returns:
            {
                success: bool,
                original: str,
                variants: list[{technique, payload}],
                count: int,
            }
        """
        payload = params.get("payload", "")
        techniques = params.get("techniques") or AVAILABLE_TECHNIQUES

        # 参数校验
        if not payload:
            return self._make_error_result("payload 参数不能为空")

        # 校验技术名称
        invalid_techniques = [t for t in techniques if t not in AVAILABLE_TECHNIQUES]
        if invalid_techniques:
            return self._make_error_result(
                f"不支持的变异技术: {', '.join(invalid_techniques)}。"
                f"可用技术: {', '.join(AVAILABLE_TECHNIQUES)}"
            )

        # 技术名称到变异函数的映射
        technique_map = {
            "url_encode": self._url_encode,
            "double_encode": self._double_encode,
            "unicode_escape": self._unicode_escape,
            "case_variation": self._case_variation,
            "comment_injection": self._comment_injection,
            "html_encode": self._html_encode,
            "hex_encode": self._hex_encode,
            "base64_encode": self._base64_encode,
        }

        variants = []
        for technique in techniques:
            try:
                func = technique_map.get(technique)
                if func:
                    mutated = func(payload)
                    variants.append({
                        "technique": technique,
                        "payload": mutated,
                    })
            except Exception as e:
                logger.warning("变异技术 %s 执行失败: %s", technique, str(e))
                variants.append({
                    "technique": technique,
                    "payload": f"[变异失败: {str(e)}]",
                })

        return {
            "success": True,
            "original": payload,
            "variants": variants,
            "count": len(variants),
        }

    @staticmethod
    def _url_encode(payload: str) -> str:
        """
        URL 编码

        将载荷中的特殊字符进行 URL 百分比编码。
        """
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def _double_encode(payload: str) -> str:
        """
        双重 URL 编码

        对载荷进行两次 URL 编码，用于绕过只解码一次的过滤器。
        """
        first = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first, safe="")

    @staticmethod
    def _unicode_escape(payload: str) -> str:
        """
        Unicode 转义

        将载荷中的每个字符转换为 \\uXXXX 格式。
        """
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def _case_variation(payload: str) -> str:
        """
        大小写交替变异

        将载荷中的字母进行大小写交替，用于绕过大小写敏感的过滤。
        例如: "script" -> "sCrIpT"
        """
        result = []
        for i, c in enumerate(payload):
            if c.isalpha():
                result.append(c.upper() if i % 2 else c.lower())
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def _comment_injection(payload: str) -> str:
        """
        SQL 注释注入

        在载荷的关键位置插入 SQL 内联注释 /**/，用于绕过关键词检测。
        例如: "UNION SELECT" -> "UN/**/ION SEL/**/ECT"
        """
        # 在 SQL 关键词中间插入注释
        sql_keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
                        "WHERE", "FROM", "ORDER", "GROUP", "HAVING"]
        result = payload
        for keyword in sql_keywords:
            # 不区分大小写替换
            lower_kw = keyword.lower()
            upper_kw = keyword.upper()
            if len(keyword) > 3:
                mid = len(keyword) // 2
                # 处理大写版本
                commented = keyword[:mid] + "/**/" + keyword[mid:]
                result = result.replace(keyword, commented)
                result = result.replace(lower_kw, lower_kw[:mid] + "/**/" + lower_kw[mid:])
        return result

    @staticmethod
    def _html_encode(payload: str) -> str:
        """
        HTML 实体编码

        将载荷中的字符转换为 HTML 数字实体（&#xHH; 格式）。
        """
        return "".join(f"&#x{ord(c):02x};" for c in payload)

    @staticmethod
    def _hex_encode(payload: str) -> str:
        """
        十六进制编码

        将载荷中的每个字符转换为 \\xHH 格式。
        """
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def _base64_encode(payload: str) -> str:
        """
        Base64 编码

        将载荷进行 Base64 编码。
        """
        return base64.b64encode(payload.encode("utf-8")).decode("utf-8")
