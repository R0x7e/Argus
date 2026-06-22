"""
SSRF 检测工具模块

检测服务端请求伪造（Server-Side Request Forgery）漏洞。
通过注入内网地址并对比响应差异来判断是否存在 SSRF。
"""

import logging
import time
from typing import Any

import httpx

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

# SSRF 测试用内网地址列表
INTERNAL_URLS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    # AWS 元数据服务地址
    "http://169.254.169.254/latest/meta-data/",
    # 常见内网段
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.0.1",
    "http://192.168.1.1",
    # 云服务元数据地址
    "http://169.254.169.254/computeMetadata/v1/",  # GCP
    "http://100.100.100.200/latest/meta-data/",     # 阿里云
]

# SSRF 响应中的可疑关键词（表明成功访问了内部资源）
SSRF_INDICATORS = [
    "ami-id",                    # AWS 元数据
    "instance-id",               # AWS 元数据
    "local-hostname",            # AWS 元数据
    "meta-data",                 # 云服务元数据
    "computeMetadata",           # GCP 元数据
    "root:x:0:0",               # /etc/passwd 内容
    "localhost",                 # 内网访问标志
    "127.0.0.1",                # 回环地址
    "internal server",           # 内部服务器标志
    "private",                   # 私有网络标志
]


class SSRFDetectorTool(BaseTool):
    """
    SSRF 检测工具

    通过向目标参数注入内网地址，对比正常响应和注入后响应的差异，
    判断是否存在服务端请求伪造漏洞。
    风险等级 L1（主动探测）。
    """

    name = "ssrf_detect"
    description = "SSRF 检测 - 检测服务端请求伪造漏洞"
    risk_level = RiskLevel.L1

    def get_schema(self) -> dict:
        """返回 SSRF 检测工具的参数 JSON Schema"""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "目标 URL 地址",
                },
                "param": {
                    "type": "string",
                    "description": "可能存在 SSRF 的参数名称",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP 请求方法",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                },
                "callback_url": {
                    "type": "string",
                    "description": "外部回调 URL（用于带外检测，可选）",
                    "default": "",
                },
            },
            "required": ["url", "param"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        """
        执行 SSRF 检测

        1. 发送正常请求获取基线响应
        2. 逐一注入内网地址，对比响应差异
        3. 检查响应中是否包含内部资源特征

        Args:
            params: {url, param, method, callback_url}
            context: 执行上下文

        Returns:
            {
                success: bool,
                vulnerable: bool,
                evidence: {response_diff, internal_url_tested},
                payload_used: str,
            }
        """
        url = params.get("url", "")
        param = params.get("param", "")
        method = params.get("method", "GET").upper()
        callback_url = params.get("callback_url", "")

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

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(context.timeout),
                verify=False,
                follow_redirects=True,
            ) as client:

                # 获取基线响应（使用合法外部 URL）
                baseline_value = "https://www.example.com"
                baseline_response = await self._send_request(
                    client, url, param, baseline_value, method
                )
                baseline_text = baseline_response.text if baseline_response else ""
                baseline_status = baseline_response.status_code if baseline_response else 0

                # 构建测试 URL 列表
                test_urls = list(INTERNAL_URLS)
                if callback_url:
                    test_urls.insert(0, callback_url)

                # 逐一测试内网地址
                for internal_url in test_urls:
                    try:
                        inject_response = await self._send_request(
                            client, url, param, internal_url, method
                        )

                        if inject_response is None:
                            continue

                        inject_text = inject_response.text
                        inject_status = inject_response.status_code

                        # 分析响应差异
                        is_vulnerable, diff_info = self._analyze_response(
                            baseline_text, baseline_status,
                            inject_text, inject_status,
                            internal_url,
                        )

                        if is_vulnerable:
                            logger.info(
                                "发现 SSRF 漏洞: url=%s, param=%s, internal=%s",
                                url, param, internal_url,
                            )
                            return {
                                "success": True,
                                "vulnerable": True,
                                "evidence": {
                                    "response_diff": diff_info,
                                    "internal_url_tested": internal_url,
                                    "baseline_status": baseline_status,
                                    "inject_status": inject_status,
                                },
                                "payload_used": internal_url,
                            }

                    except Exception as e:
                        logger.debug(
                            "SSRF 测试载荷发送失败: %s - %s", internal_url, str(e)
                        )
                        continue

                # 未发现漏洞
                return {
                    "success": True,
                    "vulnerable": False,
                    "evidence": {
                        "response_diff": "",
                        "internal_url_tested": "",
                    },
                    "payload_used": "",
                }

        except httpx.TimeoutException:
            return self._make_error_result(f"请求超时: {url}")
        except Exception as e:
            logger.error("SSRF 检测异常: %s - %s", url, str(e))
            return self._make_error_result(f"检测异常: {str(e)}")

    @staticmethod
    async def _send_request(
        client: httpx.AsyncClient,
        url: str,
        param: str,
        value: str,
        method: str,
    ) -> httpx.Response | None:
        """
        发送带有注入参数的 HTTP 请求

        Args:
            client: HTTP 客户端
            url: 目标 URL
            param: 参数名
            value: 参数值（注入的内网地址）
            method: HTTP 方法

        Returns:
            HTTP 响应对象，失败时返回 None
        """
        try:
            if method == "GET":
                separator = "&" if "?" in url else "?"
                full_url = f"{url}{separator}{param}={value}"
                return await client.get(full_url)
            else:
                data = {param: value}
                return await client.post(url, data=data)
        except Exception:
            return None

    @staticmethod
    def _analyze_response(
        baseline_text: str,
        baseline_status: int,
        inject_text: str,
        inject_status: int,
        internal_url: str,
    ) -> tuple[bool, str]:
        """
        分析基线响应和注入响应的差异

        通过以下特征判断 SSRF：
        1. 响应中包含内部资源特征关键词
        2. 响应状态码显著不同
        3. 响应长度显著不同

        Args:
            baseline_text: 基线响应体
            baseline_status: 基线状态码
            inject_text: 注入后响应体
            inject_status: 注入后状态码
            internal_url: 注入的内网地址

        Returns:
            (是否存在漏洞, 差异描述)
        """
        inject_lower = inject_text.lower()

        # 检查响应中是否包含 SSRF 特征关键词
        for indicator in SSRF_INDICATORS:
            if indicator.lower() in inject_lower and indicator.lower() not in baseline_text.lower():
                return True, f"响应中发现内部资源特征: '{indicator}'"

        # 检查状态码差异（基线返回错误但注入返回成功，可能是 SSRF）
        if baseline_status >= 400 and inject_status == 200:
            return True, (
                f"状态码异常变化: 基线={baseline_status}, 注入={inject_status}"
            )

        # 检查响应长度显著差异（注入后内容明显增多）
        len_diff = abs(len(inject_text) - len(baseline_text))
        if len_diff > 500 and len(inject_text) > len(baseline_text):
            # 再确认注入响应中包含敏感内容
            if any(kw in inject_lower for kw in ["root:", "admin", "password", "token", "secret"]):
                return True, (
                    f"响应长度异常增大（差异 {len_diff} 字节）且包含敏感关键词"
                )

        return False, ""
