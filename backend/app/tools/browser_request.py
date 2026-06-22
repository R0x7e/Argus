"""
浏览器页面渲染工具 (L1)

使用 Playwright 渲染 JS 页面，提取 DOM 中动态生成的链接、表单和参数。
"""

import logging

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)


class BrowserRequestTool(BaseTool):
    name = "browser_request"
    description = "使用 Headless 浏览器渲染页面，提取 JS 动态生成的链接、表单和参数"
    risk_level = RiskLevel.L1

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
                "wait_for": {
                    "type": "string",
                    "description": "等待策略: 'networkidle' 或 CSS 选择器",
                    "default": "networkidle",
                },
                "timeout": {"type": "integer", "description": "页面加载超时(ms)", "default": 15000},
                "extract_links": {"type": "boolean", "default": True},
                "extract_forms": {"type": "boolean", "default": True},
            },
            "required": ["url"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        url = params.get("url", "")
        if not url:
            return self._make_error_result("url 参数不能为空")
        if not self._validate_target(url, context):
            return self._make_error_result(f"目标不在白名单内: {url}")

        wait_for = params.get("wait_for", "networkidle")
        timeout = params.get("timeout", 15000)

        try:
            from app.core.playwright_manager import get_browser

            browser = get_browser()
            browser_ctx = await browser.new_context(ignore_https_errors=True)
            page = await browser_ctx.new_page()

            if context.task_id:
                await page.set_extra_http_headers({"X-Argus-Task-Id": context.task_id})

            try:
                wait_until = "networkidle" if wait_for == "networkidle" else "domcontentloaded"
                await page.goto(url, wait_until=wait_until, timeout=timeout)

                if wait_for not in ("networkidle", "domcontentloaded", "load"):
                    await page.wait_for_selector(wait_for, timeout=5000)

                links = []
                if params.get("extract_links", True):
                    links = await page.evaluate("""() => {
                        return [...document.querySelectorAll('a[href]')]
                            .map(a => a.href)
                            .filter(h => h && h.startsWith('http'))
                            .slice(0, 100);
                    }""")

                forms = []
                if params.get("extract_forms", True):
                    forms = await page.evaluate("""() => {
                        return [...document.querySelectorAll('form')].map(f => ({
                            action: f.action,
                            method: f.method || 'GET',
                            inputs: [...f.querySelectorAll('input,textarea,select')]
                                .map(i => ({name: i.name, type: i.type, id: i.id}))
                                .filter(i => i.name)
                        })).slice(0, 30);
                    }""")

                content = await page.content()
                title = await page.title()

                return {
                    "success": True,
                    "title": title,
                    "url": page.url,
                    "links": links[:100],
                    "forms": forms,
                    "content_length": len(content),
                    "content_snippet": content[:3000],
                }
            finally:
                await browser_ctx.close()

        except Exception as e:
            logger.warning("browser_request 失败: %s", str(e))
            return self._make_error_result(f"浏览器渲染失败: {str(e)}")
