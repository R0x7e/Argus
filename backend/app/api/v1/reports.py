"""
报告路由

提供报告的查询 API 端点。
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.dependencies import get_db
from app.models.report import Report
from app.models.user import User
from app.schemas.common import ApiResponse
from app.schemas.report import ReportResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/tasks/{task_id}/report",
    response_model=ApiResponse[ReportResponse],
    summary="获取任务报告",
)
async def get_task_report(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[ReportResponse]:
    """获取指定任务的汇总报告"""
    try:
        stmt = select(Report).where(Report.task_id == task_id).order_by(Report.created_at.desc())
        result = await db.execute(stmt)
        report = result.scalar_one_or_none()
        if report is None:
            raise HTTPException(status_code=404, detail="该任务暂无报告")
        return ApiResponse(data=ReportResponse.model_validate(report))
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("获取任务报告失败: %s", str(e))
        raise HTTPException(status_code=500, detail="获取报告时发生内部错误")
