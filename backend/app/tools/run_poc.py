"""
PoC 沙箱执行工具 (L2)

将动态生成的 Python PoC 代码提交到隔离沙箱容器中执行，
用于验证漏洞的可利用性和实际影响。
"""

import logging

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)


class RunPocTool(BaseTool):
    name = "run_poc"
    description = "在隔离沙箱中执行 Python PoC 代码，验证漏洞可利用性"
    risk_level = RiskLevel.L2

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python PoC 源代码（可使用 TARGET_HOST 变量）"},
                "timeout": {"type": "integer", "description": "执行超时(秒)", "default": 30},
            },
            "required": ["code"],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        code = params.get("code", "")
        if not code:
            return self._make_error_result("code 参数不能为空")
        if len(code) > 10000:
            return self._make_error_result("代码长度超过限制 (10000 字符)")

        timeout = params.get("timeout", 30)

        try:
            from app.config import get_settings
            from app.core.poc_sandbox_client import PocSandboxClient

            settings = get_settings()
            client = PocSandboxClient(settings.POC_SANDBOX_URL)

            result = await client.execute(
                code=code,
                target_host=context.target_host,
                timeout=timeout,
                allowed_hosts=context.allowed_hosts or [context.target_host],
            )

            return {
                "success": result.get("success", False),
                "output": result.get("output", "")[:5000],
                "error": result.get("error", ""),
                "execution_time_ms": result.get("execution_time_ms", 0),
                "exit_code": result.get("exit_code", -1),
            }
        except Exception as e:
            logger.warning("run_poc 失败: %s", str(e))
            return self._make_error_result(f"PoC 执行失败: {str(e)}")
