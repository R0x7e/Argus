"""
API 主路由模块

汇聚所有 v1 子路由，统一挂载到 /api/v1 前缀下。
包含 REST API 和 WebSocket 实时推送端点。
"""

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.events import router as events_router
from app.api.v1.findings import router as findings_router
from app.api.v1.reports import router as reports_router
from app.api.v1.settings import router as settings_router
from app.api.v1.steps import router as steps_router
from app.api.v1.system import router as system_router
from app.api.v1.tasks import router as tasks_router
from app.api.v1.ws import router as ws_router

# 主 API 路由
api_router = APIRouter(prefix="/api/v1")

# 认证路由（公开，无需 Token）
api_router.include_router(auth_router, prefix="/auth", tags=["认证"])

# 业务路由
api_router.include_router(tasks_router, prefix="/tasks", tags=["任务管理"])
api_router.include_router(events_router, tags=["任务管理"])
api_router.include_router(steps_router, tags=["执行可视化"])
api_router.include_router(findings_router, prefix="/findings", tags=["漏洞发现"])
api_router.include_router(reports_router, tags=["报告"])
api_router.include_router(system_router, prefix="/system", tags=["系统"])
api_router.include_router(settings_router, prefix="/settings", tags=["设置"])
api_router.include_router(ws_router, tags=["WebSocket 实时推送"])
