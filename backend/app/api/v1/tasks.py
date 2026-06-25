"""
任务管理路由

提供任务的 CRUD 操作和状态转换 API 端点。
start/pause/resume/terminate 端点同时控制 AgentRunner 的后台执行。
所有端点需要 JWT 认证。
"""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user, verify_task_ownership
from app.core.exceptions import ArgusBaseError
from app.dependencies import get_db
from app.models.user import User
from app.schemas.common import ApiResponse, PaginatedResponse
from app.schemas.task import TaskCreate, TaskListFilter, TaskResponse, TaskUpdate
from app.services.task_service import TaskService

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_agent_runner(request: Request):
    """从 app.state 获取 AgentRunner 实例"""
    runner = getattr(request.app.state, "agent_runner", None)
    if runner is None:
        raise HTTPException(status_code=503, detail="AgentRunner 未就绪")
    return runner


@router.post("", response_model=ApiResponse[TaskResponse], summary="创建任务")
async def create_task(
    data: TaskCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[TaskResponse]:
    """创建新的漏洞挖掘任务，初始状态为 created"""
    try:
        service = TaskService(db)
        task = await service.create_task(data)
        # 记录创建者
        task.created_by = user.id
        await db.commit()
        await db.refresh(task)
        return ApiResponse(
            code=201,
            message="任务创建成功",
            data=TaskResponse.model_validate(task),
        )
    except ArgusBaseError:
        raise
    except Exception as e:
        logger.exception("创建任务失败: %s", str(e))
        raise HTTPException(status_code=500, detail="创建任务时发生内部错误")


@router.get("", response_model=ApiResponse[PaginatedResponse[TaskResponse]], summary="任务列表")
async def list_tasks(
    page: int = Query(default=1, ge=1, description="页码"),
    page_size: int = Query(default=20, ge=1, le=100, description="每页大小"),
    status: Optional[str] = Query(default=None, description="按状态筛选"),
    target_type: Optional[str] = Query(default=None, description="按目标类型筛选"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[PaginatedResponse[TaskResponse]]:
    """分页查询任务列表，支持按状态和目标类型筛选"""
    try:
        filters = TaskListFilter(status=status, target_type=target_type)
        service = TaskService(db)
        tasks, total = await service.list_tasks(page=page, page_size=page_size, filters=filters)
        paginated = PaginatedResponse(
            items=[TaskResponse.model_validate(t) for t in tasks],
            total=total,
            page=page,
            page_size=page_size,
        )
        return ApiResponse(data=paginated)
    except ArgusBaseError:
        raise
    except Exception as e:
        logger.exception("查询任务列表失败: %s", str(e))
        raise HTTPException(status_code=500, detail="查询任务列表时发生内部错误")


@router.get("/{task_id}", response_model=ApiResponse[TaskResponse], summary="任务详情")
async def get_task(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[TaskResponse]:
    """获取单个任务的详细信息"""
    try:
        service = TaskService(db)
        task = await service.get_task(task_id)
        return ApiResponse(data=TaskResponse.model_validate(task))
    except ArgusBaseError:
        raise
    except Exception as e:
        logger.exception("获取任务详情失败: %s", str(e))
        raise HTTPException(status_code=500, detail="获取任务详情时发生内部错误")


@router.put("/{task_id}", response_model=ApiResponse[TaskResponse], summary="更新任务")
async def update_task(
    task_id: uuid.UUID,
    data: TaskUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[TaskResponse]:
    """更新任务信息，仅更新传入的非空字段"""
    try:
        await verify_task_ownership(str(task_id), user, db)
        service = TaskService(db)
        task = await service.update_task(task_id, data)
        return ApiResponse(message="任务更新成功", data=TaskResponse.model_validate(task))
    except ArgusBaseError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("更新任务失败: %s", str(e))
        raise HTTPException(status_code=500, detail="更新任务时发生内部错误")


@router.delete("/{task_id}", response_model=ApiResponse, summary="删除任务")
async def delete_task(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse:
    """删除指定任务及其关联数据"""
    try:
        await verify_task_ownership(str(task_id), user, db)
        service = TaskService(db)
        await service.delete_task(task_id)
        return ApiResponse(message="任务删除成功")
    except ArgusBaseError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("删除任务失败: %s", str(e))
        raise HTTPException(status_code=500, detail="删除任务时发生内部错误")


@router.post("/{task_id}/start", response_model=ApiResponse[TaskResponse], summary="启动任务")
async def start_task(
    task_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[TaskResponse]:
    """启动任务：更新状态为 running 并启动后台 Agent 执行"""
    try:
        await verify_task_ownership(str(task_id), user, db)
        service = TaskService(db)
        task = await service.transition_status(task_id, "running")

        # 启动 AgentRunner 后台执行
        runner = _get_agent_runner(request)
        task_config = {
            **(task.target_config or {}),
            **(task.config or {}),
            "target_type": task.target_type,
            "strategy": task.strategy,
        }
        # v2-fix: 从任务配置中提取 max_iterations，默认 15，避免参数丢失
        max_iterations = int(task_config.get("max_iterations", 15))
        await runner.start_task(
            task_id=str(task_id),
            task_config=task_config,
            max_iterations=max_iterations,
            mode=task_config.get("mode", "lats"),
        )

        return ApiResponse(message="任务已启动", data=TaskResponse.model_validate(task))
    except ArgusBaseError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("启动任务失败: %s", str(e))
        raise HTTPException(status_code=500, detail="启动任务时发生内部错误")


@router.post("/{task_id}/pause", response_model=ApiResponse[TaskResponse], summary="暂停任务")
async def pause_task(
    task_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[TaskResponse]:
    """暂停正在运行的任务"""
    try:
        await verify_task_ownership(str(task_id), user, db)
        service = TaskService(db)
        task = await service.transition_status(task_id, "paused")

        # 暂停后台 Agent 执行
        runner = _get_agent_runner(request)
        await runner.pause_task(str(task_id))

        return ApiResponse(message="任务已暂停", data=TaskResponse.model_validate(task))
    except ArgusBaseError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("暂停任务失败: %s", str(e))
        raise HTTPException(status_code=500, detail="暂停任务时发生内部错误")


@router.post("/{task_id}/resume", response_model=ApiResponse[TaskResponse], summary="恢复任务")
async def resume_task(
    task_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[TaskResponse]:
    """恢复已暂停的任务"""
    try:
        await verify_task_ownership(str(task_id), user, db)
        service = TaskService(db)
        task = await service.transition_status(task_id, "running")

        # 恢复后台 Agent 执行
        runner = _get_agent_runner(request)
        await runner.resume_task(str(task_id))

        return ApiResponse(message="任务已恢复", data=TaskResponse.model_validate(task))
    except ArgusBaseError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("恢复任务失败: %s", str(e))
        raise HTTPException(status_code=500, detail="恢复任务时发生内部错误")


@router.post("/{task_id}/terminate", response_model=ApiResponse[TaskResponse], summary="终止任务")
async def terminate_task(
    task_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiResponse[TaskResponse]:
    """终止任务并停止后台 Agent 执行"""
    try:
        await verify_task_ownership(str(task_id), user, db)
        service = TaskService(db)
        task = await service.transition_status(task_id, "terminated")

        # 终止后台 Agent 执行
        runner = _get_agent_runner(request)
        await runner.terminate_task(str(task_id))

        return ApiResponse(message="任务已终止", data=TaskResponse.model_validate(task))
    except ArgusBaseError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("终止任务失败: %s", str(e))
        raise HTTPException(status_code=500, detail="终止任务时发生内部错误")
