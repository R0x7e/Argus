"""
HTTP 请求工具模块

发送 HTTP 请求并返回完整响应信息，用于 Web 应用探测和漏洞验证。
支持自定义请求方法、请求头、请求体和重定向跟踪。
"""

import logging
import time
from typing import Any

import httpx

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)


class HTTPRequesterTool(BaseTool):
    """
    HTTP 请求工具

    发送 HTTP 请求并返回响应的状态码、响应头、响应体等信息。
    风险等级 L0（只读、被动扫描）。
    """

    name = "http_request"
    description = "发送 HTTP 请求并返回响应（状态码、响应头、响应体）"
    risk_level = RiskLevel.L0

    def get_schema(self) -> dict:
        """返回 HTTP 请求工具的参数 JSON Schema"""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "目标 URL 地址",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP 请求方法",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    "default": "GET",
                },
                "headers": {
                    "type": "object",
                    "description": "自定义请求头",
                    "default": {},
                },
                "body": {
                    "type": "string",
                    "description": "请求体内容",
                    "default": "",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "是否跟踪重定向",
                    "default": True,
                },
            },
            "required": ["url"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行 HTTP 请求

        Args:
            params: 请求参数 {url, method, headers, body, follow_redirects}
            context: 执行上下文

        Returns:
            {
                success: bool,
                status_code: int,
                headers: dict,
                body: str,           # 响应体（截断至 50000 字符）
                response_time_ms: int,
                redirect_history: list,
            }
        """
        # 参数提取与默认值
        url = params.get("url", "")
        method = params.get("method", "GET").upper()
        headers = params.get("headers", {})
        body = params.get("body", "")
        follow_redirects = params.get("follow_redirects", True)

        # 参数校验
        if not url:
            return self._make_error_result("url 参数不能为空")

        # 目标白名单校验
        if not self._validate_target(url, context):
            return self._make_error_result(
                f"目标 URL 不在允许的主机白名单内: {url}"
            )

        # 校验 HTTP 方法
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if method not in valid_methods:
            return self._make_error_result(f"不支持的 HTTP 方法: {method}")

        try:
            start_time = time.monotonic()

            # 构建并发送请求
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(context.timeout),
                follow_redirects=follow_redirects,
                verify=False,  # 安全测试场景下允许自签名证书
            ) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body if body else None,
                )

            # 计算响应时间
            elapsed_ms = int((time.monotonic() - start_time) * 1000)

            # 提取重定向历史
            redirect_history = []
            if response.history:
                for redirect_resp in response.history:
                    redirect_history.append({
                        "url": str(redirect_resp.url),
                        "status_code": redirect_resp.status_code,
                    })

            # 提取响应头（转为普通字典）
            response_headers = dict(response.headers)

            # 响应体截断处理（提高到 50000 字符，保留足够内容用于漏洞检测）
            original_body_length = len(response.text)
            body_text = response.text
            body_truncated = original_body_length > 50000
            if body_truncated:
                body_text = body_text[:50000] + "\n...[响应体已截断，原始长度: {}]".format(
                    original_body_length
                )

            return {
                "success": True,
                "status_code": response.status_code,
                "headers": response_headers,
                "body": body_text,
                "body_truncated": body_truncated,
                "original_body_length": original_body_length,
                "response_time_ms": elapsed_ms,
                "redirect_history": redirect_history,
                "url": str(response.url),
            }

        except httpx.TimeoutException:
            logger.warning("HTTP 请求超时: %s %s", method, url)
            return self._make_error_result(f"请求超时（{context.timeout}秒）: {url}")

        except httpx.ConnectError as e:
            logger.warning("HTTP 连接失败: %s %s - %s", method, url, str(e))
            return self._make_error_result(f"连接失败: {url} - {str(e)}")

        except httpx.TooManyRedirects:
            logger.warning("HTTP 重定向次数过多: %s", url)
            return self._make_error_result(f"重定向次数过多: {url}")

        except Exception as e:
            logger.error("HTTP 请求异常: %s %s - %s", method, url, str(e))
            return self._make_error_result(f"请求异常: {str(e)}")
