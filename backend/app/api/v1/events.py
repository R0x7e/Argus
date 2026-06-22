"""
事件流路由

提供任务事件的查询 API 端点。
"""

import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ArgusBaseError
from app.dependencies import get_db
from app.schemas.common import ApiResponse, PaginatedResponse
from app.schemas.event import EventFilter, EventResponse
from app.services.event_service import EventService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/tasks/{task_id}/events",
    response_model=ApiResponse[PaginatedResponse[EventResponse]],
    summary="事件列表",
)
async def list_events(
    task_id: uuid.UUID,
    page: int = Query(default=1, ge=1, description="页码"),
    page_size: int = Query(default=50, ge=1, le=200, description="每页大小"),
    agent: Optional[str] = Query(default=None, description="按 Agent 名称筛选"),
    type: Optional[str] = Query(default=None, description="按事件类型筛选"),
    after: Optional[datetime] = Query(default=None, description="起始时间（不含）"),
    before: Optional[datetime] = Query(default=None, description="截止时间（不含）"),
    db: AsyncSession = Depends(get_db),
) -> ApiResponse[PaginatedResponse[EventResponse]]:
    """
    分页查询指定任务的事件列表

    支持按 Agent、事件类型、时间范围筛选。
    """
    try:
        filters = EventFilter(agent=agent, type=type, after=after, before=before)
        service = EventService(db)
        events, total = await service.get_events(
            task_id=task_id,
            page=page,
            page_size=page_size,
            filters=filters,
        )
        paginated = PaginatedResponse(
            items=[EventResponse.model_validate(e) for e in events],
            total=total,
            page=page,
            page_size=page_size,
        )
        return ApiResponse(data=paginated)
    except ArgusBaseError:
        raise
    except Exception as e:
        logger.exception("查询事件列表失败: %s", str(e))
        raise HTTPException(status_code=500, detail="查询事件列表时发生内部错误")
