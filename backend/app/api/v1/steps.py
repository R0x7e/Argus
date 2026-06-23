"""
执行可视化路由

提供 LATS 搜索树快照和 ReAct 步骤查询 API。
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db
from app.models.event import Event
from app.schemas.common import ApiResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/tasks/{task_id}/steps",
    response_model=ApiResponse[list[dict]],
    summary="ReAct 执行步骤",
)
async def list_steps(
    task_id: uuid.UUID,
    node_id: str | None = Query(default=None, description="按搜索树节点 ID 过滤"),
    limit: int = Query(default=50, ge=1, le=200, description="返回条数上限"),
    db: AsyncSession = Depends(get_db),
) -> ApiResponse[list[dict]]:
    """查询指定任务的 ReAct 执行步骤（思维链数据）"""
    try:
        stmt = (
            select(Event)
            .where(Event.task_id == task_id)
            .where(Event.type == "react_step")
        )

        if node_id:
            stmt = stmt.where(Event.data["node_id"].astext == node_id)

        stmt = stmt.order_by(Event.timestamp).limit(limit)
        result = await db.execute(stmt)
        events = result.scalars().all()

        steps = []
        for e in events:
            step = dict(e.data) if e.data else {}
            step["id"] = str(e.id)
            step["timestamp"] = e.timestamp.isoformat() if e.timestamp else None
            steps.append(step)

        return ApiResponse(data=steps)
    except Exception as e:
        logger.exception("查询执行步骤失败: %s", str(e))
        raise HTTPException(status_code=500, detail="查询执行步骤失败")


@router.get(
    "/tasks/{task_id}/tree",
    response_model=ApiResponse[dict],
    summary="MCTS 搜索树快照",
)
async def get_tree(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ApiResponse[dict]:
    """返回最新一轮的 MCTS 搜索树快照"""
    try:
        stmt = (
            select(Event)
            .where(Event.task_id == task_id)
            .where(Event.type == "cycle_summary")
            .order_by(desc(Event.timestamp))
            .limit(1)
        )
        result = await db.execute(stmt)
        event = result.scalar_one_or_none()

        if not event or not event.data:
            return ApiResponse(data={"tree_snapshot": [], "cycle": 0})

        return ApiResponse(data={
            "tree_snapshot": event.data.get("tree_snapshot", []),
            "cycle": event.data.get("cycle", 0),
            "tree_stats": event.data.get("tree_stats", {}),
        })
    except Exception as e:
        logger.exception("查询搜索树快照失败: %s", str(e))
        raise HTTPException(status_code=500, detail="查询搜索树快照失败")
