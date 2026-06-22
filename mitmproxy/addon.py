"""
mitmproxy addon — 将拦截的 HTTP 流量推送到 Redis pub/sub

每个完成的请求/响应对被序列化为 JSON 并发布到 Redis 频道，
供后端 ProxyFlowConsumer 消费分析。
"""

import json
import os

import redis

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
CHANNEL = os.environ.get("PROXY_CHANNEL", "proxy:flows")

_redis = redis.from_url(REDIS_URL, decode_responses=True)


class FlowPublisher:
    def response(self, flow):
        try:
            request = flow.request
            response = flow.response

            data = {
                "method": request.method,
                "url": request.pretty_url,
                "host": request.host,
                "path": request.path,
                "request_headers": dict(request.headers),
                "request_body": request.get_text()[:2000] if request.content else "",
                "status_code": response.status_code,
                "response_headers": dict(response.headers),
                "response_body": response.get_text()[:2000] if response.content else "",
                "content_type": response.headers.get("content-type", ""),
                "task_id": request.headers.get("X-Argus-Task-Id", ""),
            }
            _redis.publish(CHANNEL, json.dumps(data, ensure_ascii=False))
        except Exception:
            pass


addons = [FlowPublisher()]
