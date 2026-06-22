"""
漏洞发现路由

提供漏洞发现的查询和更新 API 端点。
所有端点需要 JWT 认证。
"""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.core.exceptions import ArgusBaseError
from app.dependencies import get_db
from app.models.user import User
from app.schemas.common import ApiResponse, PaginatedResponse
from app.schemas.finding import FindingResponse, FindingUpdate
from app.services.finding_service import FindingService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "",
    response_model=ApiResponse[PaginatedResponse[FindingResponse]],
    summary="漏洞列表",
)
async def list_findings(
    task_id: Optional[uuid.UUID] = Query(default=None, description="按任务ID筛选"),
    page: int = Query(default=1, ge=1, description="页码"),
    page_size: int = Query(default=20, ge=1, le=100, description="每页大小"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[PaginatedResponse[FindingResponse]]:
    """分页查询漏洞发现列表，支持按任务筛选"""
    try:
        service = FindingService(db)
        if task_id:
            findings, total = await service.get_findings_by_task(
                task_id=task_id, page=page, page_size=page_size,
            )
        else:
            findings, total = await service.get_all_findings(
                page=page, page_size=page_size,
            )
        paginated = PaginatedResponse(
            items=[FindingResponse.model_validate(f) for f in findings],
            total=total,
            page=page,
            page_size=page_size,
        )
        return ApiResponse(data=paginated)
    except ArgusBaseError:
        raise
    except Exception as e:
        logger.exception("查询漏洞列表失败: %s", str(e))
        raise HTTPException(status_code=500, detail="查询漏洞列表时发生内部错误")


@router.get(
    "/{finding_id}",
    response_model=ApiResponse[FindingResponse],
    summary="漏洞详情",
)
async def get_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[FindingResponse]:
    """获取单个漏洞发现的详细信息"""
    try:
        service = FindingService(db)
        finding = await service.get_finding(finding_id)
        return ApiResponse(data=FindingResponse.model_validate(finding))
    except ArgusBaseError:
        raise
    except Exception as e:
        logger.exception("获取漏洞详情失败: %s", str(e))
        raise HTTPException(status_code=500, detail="获取漏洞详情时发生内部错误")


@router.put(
    "/{finding_id}",
    response_model=ApiResponse[FindingResponse],
    summary="更新漏洞",
)
async def update_finding(
    finding_id: uuid.UUID,
    data: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[FindingResponse]:
    """更新漏洞发现信息"""
    try:
        service = FindingService(db)
        finding = await service.update_finding(finding_id, data)
        return ApiResponse(message="漏洞信息更新成功", data=FindingResponse.model_validate(finding))
    except ArgusBaseError:
        raise
    except Exception as e:
        logger.exception("更新漏洞失败: %s", str(e))
        raise HTTPException(status_code=500, detail="更新漏洞时发生内部错误")
