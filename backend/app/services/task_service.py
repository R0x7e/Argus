"""
任务服务层

封装任务的增删改查和状态转换逻辑，处理业务规则校验。
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import TaskNotFoundError, TaskStateError
from app.models.task import Task
from app.schemas.task import TaskCreate, TaskListFilter, TaskUpdate


# 合法的状态转换映射表
VALID_TRANSITIONS: dict[str, set[str]] = {
    "created": {"running"},
    "running": {"paused", "done", "failed", "partial_done", "terminated"},
    "paused": {"running", "terminated"},
    "failed": {"running", "terminated"},
    "partial_done": {"running", "terminated"},
}

# 终态集合（进入终态时需要设置 completed_at）
TERMINAL_STATES = {"done", "failed", "partial_done", "terminated"}


class TaskService:
    """
    任务服务类

    提供任务的创建、查询、更新、删除和状态转换功能。
    通过构造函数注入异步数据库会话。
    """

    def __init__(self, db: AsyncSession) -> None:
        """初始化任务服务，注入数据库会话"""
        self.db = db

    async def create_task(self, data: TaskCreate) -> Task:
        """
        创建新任务

        根据请求数据创建任务记录并持久化到数据库。
        """
        task = Task(
            name=data.name,
            target_type=data.target_type,
            target_config=data.target_config,
            strategy=data.strategy,
            config={**data.config, "max_iterations": data.max_iterations},
            status="created",
        )
        self.db.add(task)
        await self.db.flush()
        await self.db.refresh(task)
        return task

    async def get_task(self, task_id: uuid.UUID) -> Task:
        """
        根据 ID 获取任务

        如果任务不存在则抛出 TaskNotFoundError。
        """
        stmt = select(Task).where(Task.id == task_id)
        result = await self.db.execute(stmt)
        task = result.scalar_one_or_none()
        if task is None:
            raise TaskNotFoundError(str(task_id))
        return task

    async def list_tasks(
        self,
        page: int = 1,
        page_size: int = 20,
        filters: Optional[TaskListFilter] = None,
    ) -> tuple[list[Task], int]:
        """
        分页查询任务列表

        支持按状态和目标类型筛选，返回任务列表和总数。
        """
        # 构建基础查询
        stmt = select(Task)
        count_stmt = select(func.count()).select_from(Task)

        # 应用过滤条件
        if filters:
            if filters.status is not None:
                stmt = stmt.where(Task.status == filters.status)
                count_stmt = count_stmt.where(Task.status == filters.status)
            if filters.target_type is not None:
                stmt = stmt.where(Task.target_type == filters.target_type)
                count_stmt = count_stmt.where(Task.target_type == filters.target_type)

        # 查询总数
        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar() or 0

        # 分页查询
        offset = (page - 1) * page_size
        stmt = stmt.order_by(Task.created_at.desc()).offset(offset).limit(page_size)
        result = await self.db.execute(stmt)
        tasks = list(result.scalars().all())

        return tasks, total

    async def update_task(self, task_id: uuid.UUID, data: TaskUpdate) -> Task:
        """
        更新任务信息

        仅更新请求中包含的非空字段。
        """
        task = await self.get_task(task_id)

        # 仅更新非 None 的字段
        update_data = data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            if field == "max_iterations":
                # max_iterations 存储在 config 中
                current_config = task.config or {}
                current_config["max_iterations"] = value
                task.config = current_config
            else:
                setattr(task, field, value)

        await self.db.flush()
        await self.db.refresh(task)
        return task

    async def delete_task(self, task_id: uuid.UUID) -> None:
        """
        删除任务

        根据 ID 删除任务，不存在时抛出 TaskNotFoundError。
        """
        task = await self.get_task(task_id)
        await self.db.delete(task)
        await self.db.flush()

    async def transition_status(
        self,
        task_id: uuid.UUID,
        new_status: str,
        error_info: dict | None = None,
    ) -> Task:
        """
        执行任务状态转换

        校验状态转换是否合法，并自动设置 started_at / completed_at 时间戳。
        非法转换将抛出 TaskStateError。

        Args:
            task_id: 任务 ID
            new_status: 目标状态
            error_info: 可选的错误信息，在转入失败状态时写入 task.error_info 字段
        """
        task = await self.get_task(task_id)
        current_status = task.status

        # 校验状态转换合法性
        allowed = VALID_TRANSITIONS.get(current_status, set())
        if new_status not in allowed:
            raise TaskStateError(current_status, new_status)

        # 更新状态
        task.status = new_status
        now = datetime.now(timezone.utc)

        # 转换到 running 时设置开始时间
        if new_status == "running" and task.started_at is None:
            task.started_at = now

        # 转换到终态时设置完成时间
        if new_status in TERMINAL_STATES:
            task.completed_at = now

        # 写入错误信息（如有）
        if error_info is not None:
            task.error_info = error_info

        await self.db.flush()
        await self.db.refresh(task)
        return task
