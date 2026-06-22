"""
深度爬虫工具 (L0)

调用 crawlergo sidecar 进行智能深度爬取，
自动填充表单、触发 JS 事件、发现完整攻击面。
"""

import logging

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)


class DeepCrawlTool(BaseTool):
    name = "deep_crawl"
    description = "crawlergo 深度爬虫 - 自动填充表单和触发事件，发现完整攻击面"
    risk_level = RiskLevel.L0

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "起始 URL"},
                "max_count": {"type": "integer", "default": 500, "description": "最大爬取 URL 数"},
                "timeout": {"type": "integer", "description": "最大爬取时间(秒)", "default": 120},
            },
            "required": ["url"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        url = params.get("url", "")
        if not url:
            return self._make_error_result("url 参数不能为空")
        if not self._validate_target(url, context):
            return self._make_error_result(f"目标不在白名单内: {url}")

        max_count = params.get("max_count", 500)
        timeout = params.get("timeout", 120)

        try:
            from app.config import get_settings
            from app.core.crawlergo_client import CrawlergoClient

            settings = get_settings()
            client = CrawlergoClient(settings.CRAWLERGO_URL)

            result = await client.crawl(
                target_url=url,
                max_count=max_count,
                timeout=timeout,
            )

            return {
                "success": True,
                "urls": result.get("urls", [])[:200],
                "forms": result.get("forms", [])[:50],
                "parameters": result.get("parameters", [])[:100],
                "subdomains": result.get("subdomains", []),
                "total_urls": result.get("total_urls", 0),
            }
        except Exception as e:
            logger.warning("deep_crawl 失败: %s", str(e))
            return self._make_error_result(f"深度爬取失败: {str(e)}")
