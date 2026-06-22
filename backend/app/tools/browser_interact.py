"""
浏览器交互工具 (L2)

填写表单、点击按钮、触发 JS 事件，捕获交互产生的网络请求和响应。
"""

import logging

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)


class BrowserInteractTool(BaseTool):
    name = "browser_interact"
    description = "浏览器交互 - 填写表单、点击按钮、捕获网络请求和响应变化"
    risk_level = RiskLevel.L2

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标页面 URL"},
                "actions": {
                    "type": "array",
                    "description": "交互动作序列",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["fill", "click", "select", "wait"]},
                            "selector": {"type": "string"},
                            "value": {"type": "string"},
                        },
                    },
                },
                "capture_requests": {"type": "boolean", "default": True},
                "timeout": {"type": "integer", "default": 15000},
            },
            "required": ["url", "actions"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        url = params.get("url", "")
        actions = params.get("actions", [])
        if not url:
            return self._make_error_result("url 参数不能为空")
        if not self._validate_target(url, context):
            return self._make_error_result(f"目标不在白名单内: {url}")
        if not actions:
            return self._make_error_result("actions 不能为空")

        timeout = params.get("timeout", 15000)
        capture_requests = params.get("capture_requests", True)

        try:
            from app.core.playwright_manager import get_browser

            browser = get_browser()
            browser_ctx = await browser.new_context(ignore_https_errors=True)
            page = await browser_ctx.new_page()

            if context.task_id:
                await page.set_extra_http_headers({"X-Argus-Task-Id": context.task_id})

            captured_requests = []
            if capture_requests:
                page.on("response", lambda resp: captured_requests.append({
                    "url": resp.url,
                    "status": resp.status,
                    "method": resp.request.method,
                }))

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout)

                results = []
                for action in actions[:20]:
                    act_type = action.get("type")
                    selector = action.get("selector", "")
                    value = action.get("value", "")

                    try:
                        if act_type == "fill" and selector:
                            await page.fill(selector, value)
                            results.append({"action": "fill", "selector": selector, "ok": True})
                        elif act_type == "click" and selector:
                            await page.click(selector, timeout=5000)
                            results.append({"action": "click", "selector": selector, "ok": True})
                        elif act_type == "select" and selector:
                            await page.select_option(selector, value)
                            results.append({"action": "select", "selector": selector, "ok": True})
                        elif act_type == "wait":
                            await page.wait_for_timeout(int(value) if value else 1000)
                            results.append({"action": "wait", "ok": True})
                    except Exception as e:
                        results.append({"action": act_type, "selector": selector, "ok": False, "error": str(e)[:100]})

                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

                final_content = await page.content()

                return {
                    "success": True,
                    "action_results": results,
                    "final_url": page.url,
                    "captured_requests": captured_requests[-50:],
                    "final_content_length": len(final_content),
                    "final_content_snippet": final_content[:3000],
                }
            finally:
                await browser_ctx.close()

        except Exception as e:
            logger.warning("browser_interact 失败: %s", str(e))
            return self._make_error_result(f"浏览器交互失败: {str(e)}")
