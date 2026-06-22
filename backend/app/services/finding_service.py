"""
漏洞发现服务层

封装漏洞发现的增删改查逻辑。
"""

import uuid
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ArgusBaseError
from app.models.finding import Finding
from app.schemas.finding import FindingUpdate


class FindingNotFoundError(ArgusBaseError):
    """漏洞发现未找到异常"""

    def __init__(self, finding_id: str) -> None:
        super().__init__(
            message=f"漏洞发现不存在: {finding_id}",
            code="FINDING_NOT_FOUND",
        )
        self.finding_id = finding_id


class FindingService:
    """
    漏洞发现服务类

    提供漏洞发现的创建、查询、更新功能。
    通过构造函数注入异步数据库会话。
    """

    def __init__(self, db: AsyncSession) -> None:
        """初始化漏洞发现服务，注入数据库会话"""
        self.db = db

    async def create_finding(
        self,
        task_id: uuid.UUID,
        hypothesis_id: Optional[uuid.UUID],
        type: str,
        severity: str,
        title: str,
        description: str,
        trigger_path: Optional[dict] = None,
        payload: Optional[str] = None,
        reproduction_steps: Optional[dict] = None,
        evidence: Optional[dict] = None,
    ) -> Finding:
        """
        创建漏洞发现记录

        记录 Agent 在扫描过程中发现的漏洞，关联到指定任务和假设。
        """
        finding = Finding(
            task_id=task_id,
            hypothesis_id=hypothesis_id,
            type=type,
            severity=severity,
            title=title,
            description=description,
            trigger_path=trigger_path,
            payload=payload,
            reproduction_steps=reproduction_steps,
            evidence=evidence,
            status="draft",
        )
        self.db.add(finding)
        await self.db.flush()
        await self.db.refresh(finding)
        return finding

    async def get_finding(self, finding_id: uuid.UUID) -> Finding:
        """
        根据 ID 获取漏洞发现

        如果不存在则抛出 FindingNotFoundError。
        """
        stmt = select(Finding).where(Finding.id == finding_id)
        result = await self.db.execute(stmt)
        finding = result.scalar_one_or_none()
        if finding is None:
            raise FindingNotFoundError(str(finding_id))
        return finding

    async def get_findings_by_task(
        self,
        task_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Finding], int]:
        """
        分页查询指定任务的漏洞发现列表

        按创建时间降序排列。
        """
        # 构建查询
        stmt = select(Finding).where(Finding.task_id == task_id)
        count_stmt = (
            select(func.count()).select_from(Finding).where(Finding.task_id == task_id)
        )

        # 查询总数
        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar() or 0

        # 分页查询
        offset = (page - 1) * page_size
        stmt = stmt.order_by(Finding.created_at.desc()).offset(offset).limit(page_size)
        result = await self.db.execute(stmt)
        findings = list(result.scalars().all())

        return findings, total

    async def get_all_findings(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Finding], int]:
        """分页查询所有漏洞发现，按创建时间降序排列。"""
        count_stmt = select(func.count()).select_from(Finding)
        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar() or 0

        offset = (page - 1) * page_size
        stmt = select(Finding).order_by(Finding.created_at.desc()).offset(offset).limit(page_size)
        result = await self.db.execute(stmt)
        findings = list(result.scalars().all())

        return findings, total

    async def update_finding(
        self, finding_id: uuid.UUID, data: FindingUpdate
    ) -> Finding:
        """
        更新漏洞发现

        仅更新请求中包含的非空字段。
        """
        finding = await self.get_finding(finding_id)

        # 仅更新非 None 的字段
        update_data = data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(finding, field, value)

        await self.db.flush()
        await self.db.refresh(finding)
        return finding
