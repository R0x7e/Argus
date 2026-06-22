"""
越权检测工具模块

检测水平越权（IDOR）和垂直越权（权限提升）漏洞。
通过对比不同身份认证状态下的响应来判断是否存在越权访问。
"""

import difflib
import logging
import time
from typing import Any

import httpx

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)


class AuthTesterTool(BaseTool):
    """
    越权检测工具

    通过对比以下三种场景的请求响应来检测越权漏洞：
    1. 用户 A 的认证令牌（正常访问）
    2. 用户 B 的认证令牌（水平越权测试）
    3. 无认证（垂直越权/未授权访问测试）

    风险等级 L1（主动探测）。
    """

    name = "auth_test"
    description = "越权检测 - 检测水平/垂直越权访问漏洞"
    risk_level = RiskLevel.L1

    def get_schema(self) -> dict:
        """返回越权检测工具的参数 JSON Schema"""
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
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                    "default": "GET",
                },
                "user_a_token": {
                    "type": "string",
                    "description": "用户 A 的认证令牌（资源所有者）",
                },
                "user_b_token": {
                    "type": "string",
                    "description": "用户 B 的认证令牌（其他用户，用于水平越权测试）",
                    "default": "",
                },
                "no_auth": {
                    "type": "boolean",
                    "description": "是否测试无认证访问（垂直越权测试）",
                    "default": True,
                },
            },
            "required": ["url", "user_a_token"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行越权检测

        1. 使用用户 A 的令牌发送正常请求
        2. 使用用户 B 的令牌发送请求（水平越权）
        3. 无认证发送请求（垂直越权）
        4. 对比响应差异，判断是否存在越权

        Args:
            params: {url, method, user_a_token, user_b_token, no_auth}
            context: 执行上下文

        Returns:
            {
                success: bool,
                idor_detected: bool,
                unauth_access: bool,
                evidence: {
                    authed_status: int,
                    unauthed_status: int,
                    response_similarity: float,
                    user_b_status: int,
                    user_b_similarity: float,
                },
            }
        """
        url = params.get("url", "")
        method = params.get("method", "GET").upper()
        user_a_token = params.get("user_a_token", "")
        user_b_token = params.get("user_b_token", "")
        no_auth = params.get("no_auth", True)

        # 参数校验
        if not url:
            return self._make_error_result("url 参数不能为空")
        if not user_a_token:
            return self._make_error_result("user_a_token 参数不能为空")

        # 目标白名单校验
        if not self._validate_target(url, context):
            return self._make_error_result(
                f"目标 URL 不在允许的主机白名单内: {url}"
            )

        evidence = {
            "authed_status": 0,
            "unauthed_status": 0,
            "response_similarity": 0.0,
            "user_b_status": 0,
            "user_b_similarity": 0.0,
        }

        idor_detected = False
        unauth_access = False

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(context.timeout),
                verify=False,
            ) as client:

                # 第一步：用户 A 正常请求（基线）
                user_a_response = await self._send_request(
                    client, url, method, user_a_token
                )
                if user_a_response is None:
                    return self._make_error_result(f"用户 A 请求失败: {url}")

                evidence["authed_status"] = user_a_response.status_code
                user_a_body = user_a_response.text

                # 如果用户 A 本身就无法访问，直接返回
                if user_a_response.status_code in (401, 403):
                    return {
                        "success": True,
                        "idor_detected": False,
                        "unauth_access": False,
                        "evidence": evidence,
                        "note": "用户 A 本身无法访问该资源，无法进行越权测试",
                    }

                # 第二步：用户 B 水平越权测试
                if user_b_token:
                    user_b_response = await self._send_request(
                        client, url, method, user_b_token
                    )
                    if user_b_response is not None:
                        evidence["user_b_status"] = user_b_response.status_code
                        user_b_body = user_b_response.text

                        # 计算响应相似度
                        similarity = self._calculate_similarity(user_a_body, user_b_body)
                        evidence["user_b_similarity"] = similarity

                        # 判断水平越权：用户 B 能获取用户 A 的数据（状态码 2xx 且响应相似）
                        if (
                            user_b_response.status_code == user_a_response.status_code
                            and similarity > 0.8
                        ):
                            idor_detected = True
                            logger.info(
                                "发现水平越权（IDOR）: url=%s, similarity=%.2f",
                                url, similarity,
                            )

                # 第三步：无认证访问测试
                if no_auth:
                    noauth_response = await self._send_request(
                        client, url, method, ""
                    )
                    if noauth_response is not None:
                        evidence["unauthed_status"] = noauth_response.status_code
                        noauth_body = noauth_response.text

                        # 计算无认证响应与正常响应的相似度
                        similarity = self._calculate_similarity(user_a_body, noauth_body)
                        evidence["response_similarity"] = similarity

                        # 判断未授权访问：无认证也能获取数据（状态码 2xx 且响应相似）
                        if (
                            noauth_response.status_code == user_a_response.status_code
                            and similarity > 0.8
                        ):
                            unauth_access = True
                            logger.info(
                                "发现未授权访问: url=%s, similarity=%.2f",
                                url, similarity,
                            )

            return {
                "success": True,
                "idor_detected": idor_detected,
                "unauth_access": unauth_access,
                "evidence": evidence,
            }

        except httpx.TimeoutException:
            return self._make_error_result(f"请求超时: {url}")
        except Exception as e:
            logger.error("越权检测异常: %s - %s", url, str(e))
            return self._make_error_result(f"检测异常: {str(e)}")

    @staticmethod
    async def _send_request(
        client: httpx.AsyncClient,
        url: str,
        method: str,
        token: str,
    ) -> httpx.Response | None:
        """
        发送 HTTP 请求

        Args:
            client: HTTP 客户端
            url: 目标 URL
            method: HTTP 方法
            token: Bearer 令牌（为空则不添加认证头）

        Returns:
            HTTP 响应对象，失败时返回 None
        """
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            return await client.request(method=method, url=url, headers=headers)
        except Exception as e:
            logger.debug("请求失败: %s %s - %s", method, url, str(e))
            return None

    @staticmethod
    def _calculate_similarity(text_a: str, text_b: str) -> float:
        """
        计算两段文本的相似度

        使用 SequenceMatcher 计算相似度比率。
        为避免性能问题，长文本截断后再比较。

        Args:
            text_a: 文本 A
            text_b: 文本 B

        Returns:
            相似度比率（0.0 ~ 1.0）
        """
        # 截断过长的文本（避免 SequenceMatcher 性能问题）
        max_len = 5000
        a = text_a[:max_len]
        b = text_b[:max_len]

        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0

        return difflib.SequenceMatcher(None, a, b).ratio()
