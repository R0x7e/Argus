"""
代理流量查询工具 (L0)

查询 mitmproxy 通过 Redis pub/sub 捕获的 HTTP 流量，发现隐藏 API 端点。
"""

import logging

from .base import BaseTool, ExecutionContext, RiskLevel

logger = logging.getLogger(__name__)


class ProxyFlowsTool(BaseTool):
    name = "proxy_flows"
    description = "查询 mitmproxy 捕获的 HTTP 流量，发现浏览器产生的隐藏 API 调用"
    risk_level = RiskLevel.L0

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "filter_host": {"type": "string", "description": "按主机名过滤"},
                "filter_path": {"type": "string", "description": "路径包含关键字过滤"},
                "filter_method": {"type": "string", "description": "HTTP 方法过滤 (GET/POST/PUT等)"},
                "limit": {"type": "integer", "default": 50, "description": "返回最大条数"},
            },
            "required": [],
        }

    async def execute(self, params: dict, context: ExecutionContext) -> dict:
        try:
            from app.core.proxy_client import _proxy_consumer

            if _proxy_consumer is None:
                return self._make_error_result("ProxyFlowConsumer 未初始化（mitmproxy 可能未连接）")

            flows = _proxy_consumer.get_flows(
                task_id=context.task_id,
                limit=params.get("limit", 50),
            )

            filter_host = params.get("filter_host", "")
            filter_path = params.get("filter_path", "")
            filter_method = params.get("filter_method", "")

            if filter_host:
                flows = [f for f in flows if filter_host in f.get("host", "")]
            if filter_path:
                flows = [f for f in flows if filter_path in f.get("path", "")]
            if filter_method:
                flows = [f for f in flows if f.get("method", "").upper() == filter_method.upper()]

            summary = []
            for f in flows:
                summary.append({
                    "method": f.get("method"),
                    "url": f.get("url", "")[:200],
                    "status_code": f.get("status_code"),
                    "content_type": f.get("content_type", "")[:50],
                })

            return {
                "success": True,
                "flows": summary,
                "count": len(summary),
            }
        except Exception as e:
            return self._make_error_result(f"获取代理流量失败: {str(e)}")
