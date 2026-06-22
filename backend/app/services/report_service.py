"""
报告服务 - 漏洞报告生成与导出

基于漏洞发现生成结构化的 Markdown/HTML/JSON 报告，
支持 Jinja2 模板渲染和多格式导出。
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.report import Report

logger = structlog.get_logger()

# 报告模板目录
TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class ReportService:
    """
    报告服务：基于漏洞发现生成 Markdown 报告

    支持功能：
    - 使用 Jinja2 模板渲染报告
    - 多格式导出（Markdown / HTML / JSON）
    - 报告版本管理（更新已有报告时自动递增版本号）
    """

    def __init__(self, db: AsyncSession) -> None:
        """初始化报告服务，注入数据库会话"""
        self.db = db

    async def create_report(
        self,
        task_id: str,
        content: str,
        format: str = "markdown",
        findings_count: int = 0,
        severity_distribution: dict | None = None,
    ) -> Report:
        """
        创建任务级汇总报告（由 Reporter 节点调用）

        Args:
            task_id: 任务 ID
            content: 渲染后的报告内容（Markdown）
            format: 报告格式
            findings_count: 漏洞发现数
            severity_distribution: 严重级别分布

        Returns:
            Report 模型实例
        """
        report = Report(
            id=str(uuid.uuid4()),
            task_id=task_id,
            finding_id=None,
            format=format,
            content=content,
            version=1,
            report_metadata={
                "findings_count": findings_count,
                "severity_distribution": severity_distribution or {},
            },
        )
        self.db.add(report)
        await self.db.flush()
        logger.info("task_report_created", task_id=task_id, findings_count=findings_count)
        return report

    async def generate_report(
        self,
        finding_id: str,
        template: str = "report_generic",
        created_by: Optional[str] = None,
    ) -> Report:
        """
        为指定漏洞发现生成报告。

        如果该发现已有报告，则更新内容并递增版本号；
        否则创建新报告。

        Args:
            finding_id: 漏洞发现 ID
            template: Jinja2 模板名称（不含扩展名）
            created_by: 创建者用户 ID

        Returns:
            Report 模型实例

        Raises:
            ValueError: 漏洞发现不存在
        """
        # 获取漏洞发现
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            raise ValueError(f"漏洞发现不存在: {finding_id}")

        # 使用模板渲染报告内容
        content = self._render_template(template, finding)

        # 检查是否已有报告（更新 vs 新建）
        existing = await self.db.execute(
            select(Report).where(Report.finding_id == finding_id)
        )
        report = existing.scalar_one_or_none()

        if report:
            # 更新已有报告：刷新内容并递增版本号
            report.content = content
            report.version += 1
        else:
            # 创建新报告
            report = Report(
                id=str(uuid.uuid4()),
                finding_id=finding_id,
                format="markdown",
                content=content,
                version=1,
                created_by=created_by,
            )
            self.db.add(report)

        await self.db.flush()
        return report

    async def get_report(self, finding_id: str) -> Optional[Report]:
        """
        获取指定漏洞发现的报告

        Args:
            finding_id: 漏洞发现 ID

        Returns:
            Report 实例，不存在则返回 None
        """
        result = await self.db.execute(
            select(Report).where(Report.finding_id == finding_id)
        )
        return result.scalar_one_or_none()

    async def export_report(self, finding_id: str, format: str = "md") -> str:
        """
        导出报告为指定格式。

        如果报告尚未生成，会自动触发生成流程。

        Args:
            finding_id: 漏洞发现 ID
            format: 导出格式，支持 "md"（Markdown）、"html"、"json"

        Returns:
            导出内容的字符串

        Raises:
            ValueError: 不支持的导出格式
        """
        report = await self.get_report(finding_id)
        if not report:
            # 报告不存在时自动生成
            report = await self.generate_report(finding_id)

        if format == "md":
            return report.content

        elif format == "html":
            return self._markdown_to_html(report.content)

        elif format == "json":
            # JSON 格式包含发现详情和报告元信息
            result = await self.db.execute(
                select(Finding).where(Finding.id == finding_id)
            )
            finding = result.scalar_one_or_none()
            return json.dumps(
                {
                    "finding": {
                        "id": str(finding.id),
                        "type": finding.type,
                        "severity": finding.severity,
                        "title": finding.title,
                        "description": finding.description,
                    },
                    "report": {
                        "content": report.content,
                        "version": report.version,
                        "format": report.format,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )

        else:
            raise ValueError(f"不支持的导出格式: {format}")

    def _render_template(self, template_name: str, finding: Finding) -> str:
        """
        使用 Jinja2 渲染报告模板

        模板文件从 TEMPLATE_DIR 目录加载。
        如果模板加载或渲染失败，回退到内置的简单格式。

        Args:
            template_name: 模板文件名（不含 .md 扩展名）
            finding: 漏洞发现模型实例
        """
        try:
            from jinja2 import Environment, FileSystemLoader

            env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
            tmpl = env.get_template(f"{template_name}.md")
            return tmpl.render(
                title=finding.title,
                type=finding.type,
                severity=finding.severity,
                description=finding.description,
                trigger_path=finding.trigger_path or [],
                payload=finding.payload or "",
                reproduction_steps=finding.reproduction_steps or [],
                evidence=finding.evidence or {},
                impact=finding.impact_assessment or "",
                fix_suggestion=finding.fix_suggestion or "",
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            )
        except Exception as e:
            logger.warning("template_render_failed", error=str(e), template=template_name)
            return self._fallback_render(finding)

    def _fallback_render(self, finding: Finding) -> str:
        """
        模板不可用时的备用渲染

        使用 Python f-string 直接生成简化版 Markdown 报告。
        """
        steps = finding.reproduction_steps or ["待补充"]
        steps_text = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps))
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        return f"""# {finding.title}

## 漏洞概述
{finding.description}

## 漏洞等级
{finding.severity}

## 漏洞类型
{finding.type}

## 复现步骤
{steps_text}

## Payload
```
{finding.payload or "N/A"}
```

## 修复建议
{finding.fix_suggestion or "待补充"}

---
*由 Argus 自动生成 - {timestamp}*
"""

    def _markdown_to_html(self, markdown_content: str) -> str:
        """
        Markdown 转 HTML

        优先使用 markdown 库进行转换，不可用时回退到 <pre> 包裹。
        """
        try:
            import markdown

            return markdown.markdown(
                markdown_content, extensions=["tables", "fenced_code"]
            )
        except ImportError:
            # markdown 库未安装时的降级方案
            logger.warning("markdown_library_not_available")
            return f"<pre>{markdown_content}</pre>"
