"""
Katana 爬虫工具 (L0)

调用 Katana sidecar HTTP API 进行 headless 动态渲染爬取，
提取目标网站的所有 URL、表单、JS 端点。
"""

import logging
import os

import httpx

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)

KATANA_URL = os.environ.get("KATANA_URL", "http://katana:7778")


class KatanaCrawlerTool(BaseTool):
    """Katana 爬虫工具 — headless 动态渲染 + JS 端点发现"""

    name = "katana_crawl"
    description = "Katana headless 爬虫: 动态渲染 + JS 端点提取 + 表单发现"
    risk_level = RiskLevel.L0

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
                "depth": {"type": "integer", "default": 2, "description": "爬取深度"},
                "headless": {"type": "boolean", "default": True},
                "max_count": {"type": "integer", "default": 200},
                "timeout": {"type": "integer", "default": 90},
            },
            "required": ["url"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        url = params.get("url", "")
        if not url:
            return self._make_error_result("url 参数不能为空")

        if not self._validate_target(url, context):
            return self._make_error_result(f"目标不在白名单内: {url}")

        try:
            request_timeout = params.get("timeout", 90) + 15
            async with httpx.AsyncClient(timeout=request_timeout) as client:
                resp = await client.post(
                    f"{KATANA_URL}/crawl",
                    json={
                        "url": url,
                        "depth": params.get("depth", 2),
                        "headless": params.get("headless", True),
                        "max_count": params.get("max_count", 200),
                        "timeout": params.get("timeout", 90),
                    },
                )

                if resp.status_code != 200:
                    return self._make_error_result(
                        f"Katana 返回 {resp.status_code}: {resp.text[:200]}"
                    )

                data = resp.json()
                urls = data.get("urls", [])
                forms = data.get("forms", [])
                js_endpoints = data.get("js_endpoints", [])

                logger.info(
                    "Katana: %d URLs, %d forms, %d JS endpoints",
                    len(urls), len(forms), len(js_endpoints),
                )

                return {
                    "success": True,
                    "urls": urls,
                    "forms": forms,
                    "js_endpoints": js_endpoints,
                    "params": data.get("params", []),
                    "total_urls": data.get("total_urls", len(urls)),
                    "total_forms": data.get("total_forms", len(forms)),
                    "total_js_endpoints": data.get("total_js_endpoints", len(js_endpoints)),
                }

        except httpx.TimeoutException:
            return self._make_error_result("Katana 请求超时")
        except Exception as e:
            logger.error("Katana 异常: %s", str(e))
            return self._make_error_result(f"Katana 异常: {str(e)}")
