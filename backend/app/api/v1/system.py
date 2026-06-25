"""
系统管理路由

提供健康检查和系统统计 API 端点。
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.dependencies import get_db
from app.models.finding import Finding
from app.models.task import Task
from app.models.user import User
from app.schemas.common import ApiResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health", response_model=ApiResponse, summary="健康检查")
async def health_check(
    db: AsyncSession = Depends(get_db),
) -> ApiResponse:
    """
    系统健康检查

    检测数据库和 Redis 的连接状态，返回各服务的健康状况。
    """
    try:
        services: dict[str, str] = {
            "database": "ok",
            "redis": "ok",
        }

        # 检测数据库连接
        try:
            await db.execute(text("SELECT 1"))
        except Exception as e:
            logger.warning("数据库健康检查失败: %s", e)
            services["database"] = "unhealthy"

        # 检测 Redis 连接
        try:
            from app.core.redis import get_redis_client
            redis_client = get_redis_client()
            await redis_client.ping()
        except Exception as e:
            logger.warning("Redis 健康检查失败: %s", e)
            services["redis"] = "unhealthy"

        # 判断整体健康状态
        overall = "healthy" if all(v == "ok" for v in services.values()) else "degraded"

        return ApiResponse(
            data={
                "status": overall,
                "services": services,
            }
        )
    except Exception as e:
        logger.exception("健康检查失败: %s", str(e))
        raise HTTPException(status_code=500, detail="健康检查时发生内部错误")


@router.get("/stats", response_model=ApiResponse, summary="系统统计")
async def system_stats(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> ApiResponse:
    """
    系统统计信息

    返回各状态任务数量、漏洞发现总数、事件总数等统计数据。
    """
    try:
        # 按状态统计任务数量
        task_count_stmt = (
            select(Task.status, func.count().label("count"))
            .group_by(Task.status)
        )
        task_result = await db.execute(task_count_stmt)
        task_counts = {row.status: row.count for row in task_result}

        # 统计漏洞发现总数
        finding_count_stmt = select(func.count()).select_from(Finding)
        finding_result = await db.execute(finding_count_stmt)
        total_findings = finding_result.scalar() or 0

        # 统计高危漏洞数量
        critical_stmt = (
            select(func.count()).select_from(Finding)
            .where(Finding.severity == "critical")
        )
        critical_result = await db.execute(critical_stmt)
        critical_findings = critical_result.scalar() or 0

        return ApiResponse(
            data={
                "total_tasks": sum(task_counts.values()),
                "running_tasks": task_counts.get("running", 0),
                "total_findings": total_findings,
                "critical_findings": critical_findings,
            }
        )
    except Exception as e:
        logger.exception("获取系统统计失败: %s", str(e))
        raise HTTPException(status_code=500, detail="获取系统统计时发生内部错误")
