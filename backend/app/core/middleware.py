"""
中间件模块

提供请求日志记录中间件、全局异常处理器和速率限制。
"""

import logging
import time
from collections import defaultdict
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.exceptions import ArgusBaseError

logger = logging.getLogger("argus.middleware")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    请求日志中间件

    记录每个 HTTP 请求的方法、路径、状态码和耗时，
    便于监控和调试。
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """处理请求并记录日志"""
        start_time = time.monotonic()

        # 执行请求处理链
        try:
            response = await call_next(request)
        except Exception:
            # 如果请求处理过程中发生未捕获的异常，记录错误日志
            duration = time.monotonic() - start_time
            logger.error(
                "请求处理异常",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": round(duration * 1000, 2),
                },
            )
            raise

        # 计算请求耗时
        duration = time.monotonic() - start_time
        duration_ms = round(duration * 1000, 2)

        # 记录请求日志
        logger.info(
            "请求完成: %s %s -> %d (%.2fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )

        return response


def register_exception_handlers(app: FastAPI) -> None:
    """
    注册全局异常处理器

    将 ArgusBaseError 子类异常转换为统一的 JSON 错误响应，
    避免向客户端暴露内部堆栈信息。
    """

    @app.exception_handler(ArgusBaseError)
    async def argus_error_handler(request: Request, exc: ArgusBaseError) -> JSONResponse:
        """处理 Argus 业务异常，返回统一格式的错误响应"""
        # 根据错误码映射 HTTP 状态码
        status_code_map: dict[str, int] = {
            "TASK_NOT_FOUND": 404,
            "FINDING_NOT_FOUND": 404,
            "TASK_STATE_ERROR": 409,
            "BUDGET_EXCEEDED": 429,
            "AGENT_ERROR": 500,
            "TOOL_EXECUTION_ERROR": 500,
            "SANDBOX_ERROR": 500,
            "INTERNAL_ERROR": 500,
        }
        http_status = status_code_map.get(exc.code, 500)

        logger.warning(
            "业务异常: [%s] %s",
            exc.code,
            exc.message,
            extra={
                "error_code": exc.code,
                "error_message": exc.message,
                "path": request.url.path,
            },
        )

        return JSONResponse(
            status_code=http_status,
            content={
                "code": http_status,
                "message": exc.message,
                "data": None,
            },
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    简单的内存速率限制中间件

    针对认证端点 (登录/注册) 限制请求频率，防止暴力破解。
    """

    def __init__(self, app: FastAPI, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # IP -> [(timestamp, ...)]
        self._requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """对 /api/v1/auth/ 路径应用速率限制"""
        path = request.url.path
        if path.startswith("/api/v1/auth/") and request.method == "POST":
            client_ip = request.client.host if request.client else "unknown"
            now = time.monotonic()

            # 清除过期记录
            window_start = now - self.window_seconds
            self._requests[client_ip] = [
                t for t in self._requests[client_ip] if t > window_start
            ]

            if len(self._requests[client_ip]) >= self.max_requests:
                logger.warning(
                    "速率限制触发: IP=%s, path=%s, count=%d/%d",
                    client_ip, path, len(self._requests[client_ip]), self.max_requests,
                )
                return JSONResponse(
                    status_code=429,
                    content={"code": 429, "message": "请求过于频繁，请稍后再试", "data": None},
                )

            self._requests[client_ip].append(now)

        return await call_next(request)
