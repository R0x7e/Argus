"""
LLM 客户端模块

封装与多种 LLM 供应商 API 的交互，集成模型路由和 Token 预算管理。
支持从数据库动态加载供应商配置，回退到环境变量。
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from app.agents.model_router import ModelRouter
from app.agents.token_budget import TokenBudget

logger = logging.getLogger(__name__)

# API 密钥缺失时的 mock 响应，用于开发和测试环境
_MOCK_RESPONSES: dict[str, str] = {
    "orchestrator": json.dumps({
        "target_profile": {
            "tech_stack": ["unknown"],
            "framework": "unknown",
            "server": "unknown",
        },
        "strategy": "comprehensive_scan",
        "next_action": "hypothesize",
        "reasoning": "[MOCK] 无 API 密钥，返回模拟数据。请在设置页面配置 AI 供应商。",
    }),
    "hypothesizer": json.dumps([
        {
            "type": "xss",
            "description": "[MOCK] 模拟假设 - 反射型 XSS",
            "trigger_path": ["/search?q=<script>"],
            "preconditions": ["搜索功能存在", "无输入过滤"],
            "expected_impact": "用户会话劫持",
            "confidence": 0.5,
            "test_steps": ["发送含脚本标签的搜索请求", "检查响应中是否原样反射"],
            "payloads": ["<script>alert(1)</script>"],
        }
    ]),
    "verifier": json.dumps({
        "hypothesis_id": "mock-hyp-001",
        "verified": False,
        "risk_level": "L0",
        "evidence": {"status_code": 200, "response_diff": "N/A", "timing": "N/A"},
        "reproduction_steps": ["[MOCK] 无法在无 API 密钥环境下执行真实验证"],
        "severity": "low",
        "false_positive_reason": "[MOCK] 模拟数据，非真实验证结果",
    }),
}


@dataclass
class ProviderConfig:
    """运行时供应商配置（从 DB 或环境变量加载后的内存表示）"""
    provider_type: str  # anthropic | openai | deepseek | zhipu | qwen | custom
    api_key: str
    base_url: str | None = None
    default_model: str | None = None


async def load_active_provider() -> ProviderConfig | None:
    """从数据库加载优先级最高的活跃 LLM 供应商配置"""
    try:
        from sqlalchemy import select

        from app.core.database import async_session_factory
        from app.core.encryption import decrypt_api_key
        from app.models.llm_provider import LLMProvider

        async with async_session_factory() as db:
            stmt = (
                select(LLMProvider)
                .where(LLMProvider.is_active == True)
                .order_by(LLMProvider.priority)
                .limit(1)
            )
            result = await db.execute(stmt)
            provider = result.scalar_one_or_none()
            if not provider:
                return None

            return ProviderConfig(
                provider_type=provider.provider_type,
                api_key=decrypt_api_key(provider.api_key_encrypted),
                base_url=provider.base_url,
                default_model=provider.default_model,
            )
    except Exception as e:
        logger.warning("从数据库加载 LLM 供应商失败，将使用环境变量: %s", e)
        return None


class LLMClient:
    """
    LLM 客户端

    支持多种供应商（Anthropic、OpenAI 兼容接口）：
    - 优先从数据库加载活跃供应商配置
    - 无数据库配置时回退到 ANTHROPIC_API_KEY 环境变量
    - API 密钥缺失时返回 mock 数据（开发模式）
    """

    def __init__(
        self,
        api_key: str | None = None,
        model_router: ModelRouter | None = None,
        token_budget: TokenBudget | None = None,
        provider_config: ProviderConfig | None = None,
    ) -> None:
        self._provider_config = provider_config
        self._explicit_api_key = api_key
        self.model_router = model_router or ModelRouter()
        self.token_budget = token_budget
        self._initialized = False
        self._mock_mode = False

    async def _ensure_initialized(self) -> None:
        """延迟初始化：首次调用时加载供应商配置"""
        if self._initialized:
            return
        self._initialized = True

        if self._provider_config:
            self._mock_mode = False
            return

        # 尝试从 DB 加载
        db_provider = await load_active_provider()
        if db_provider:
            self._provider_config = db_provider
            if db_provider.default_model:
                self.model_router.update_default_model(db_provider.default_model)
            logger.info(
                "使用数据库配置的 LLM 供应商: %s (%s)",
                db_provider.provider_type,
                db_provider.default_model or "default",
            )
            self._mock_mode = False
            return

        # 回退到环境变量
        env_key = self._explicit_api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if env_key:
            self._provider_config = ProviderConfig(
                provider_type="anthropic",
                api_key=env_key,
            )
            self._mock_mode = False
        else:
            self._mock_mode = True
            logger.warning(
                "⚠️ 未配置任何 LLM 供应商且 ANTHROPIC_API_KEY 未设置，"
                "LLM 客户端将运行在 MOCK 模式。"
            )

    async def call(
        self,
        agent: str,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]] | None = None,
    ) -> str:
        """
        调用 LLM 获取响应

        Args:
            agent: 调用方 Agent 名称（用于模型选择和预算跟踪）
            messages: 消息列表，格式 [{"role": "...", "content": "..."}]
            tools: 可选的工具定义列表（用于 function calling）

        Returns:
            LLM 响应的文本内容
        """
        await self._ensure_initialized()

        # 检查预算
        if self.token_budget and self.token_budget.is_exceeded():
            logger.error("任务 [%s] Token 预算已超限，拒绝调用", self.token_budget.task_id)
            from app.core.exceptions import BudgetExceededError
            raise BudgetExceededError(
                budget_limit=self.token_budget.total_budget,
                current_cost=self.token_budget.spent,
            )

        # Mock 模式
        if self._mock_mode:
            return self._get_mock_response(agent)

        # 选择模型
        budget_ratio = self.token_budget.remaining_ratio() if self.token_budget else 1.0
        model_id = self.model_router.select_model(agent, budget_ratio)

        response_text = await self._invoke_llm(model_id, messages, tools)
        return response_text

    async def _invoke_llm(
        self,
        model_id: str,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]] | None = None,
        max_retries: int = 3,
    ) -> str:
        """实际调用 LLM，包含重试逻辑"""
        import asyncio

        from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

        config = self._provider_config
        assert config is not None

        llm = self._create_llm_instance(config, model_id)

        # 转换消息格式为 LangChain 格式
        lc_messages = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            if role == "system":
                lc_messages.append(SystemMessage(content=content))
            elif role == "user":
                lc_messages.append(HumanMessage(content=content))
            elif role == "assistant":
                lc_messages.append(AIMessage(content=content))

        # 带重试的调用
        last_error: Exception | None = None
        for attempt in range(1, max_retries + 1):
            try:
                if tools:
                    llm_with_tools = llm.bind_tools(tools)
                    response = await llm_with_tools.ainvoke(lc_messages)
                else:
                    response = await llm.ainvoke(lc_messages)

                # 记录 Token 消耗
                if self.token_budget and hasattr(response, "usage_metadata"):
                    usage = response.usage_metadata
                    self.token_budget.consume(
                        agent="llm",
                        tokens_in=usage.get("input_tokens", 0),
                        tokens_out=usage.get("output_tokens", 0),
                    )

                # 提取文本内容
                if hasattr(response, "content"):
                    return response.content if isinstance(response.content, str) else str(response.content)
                return str(response)

            except Exception as e:
                last_error = e
                error_msg = str(e).lower()

                if "rate" in error_msg or "429" in error_msg:
                    wait_time = 2 ** attempt
                    logger.warning(
                        "速率限制，第 %d/%d 次重试，等待 %d 秒...",
                        attempt, max_retries, wait_time,
                    )
                    await asyncio.sleep(wait_time)
                    continue

                logger.error("LLM 调用失败 (第 %d/%d 次): %s", attempt, max_retries, str(e))
                if attempt < max_retries:
                    await asyncio.sleep(1)
                    continue

        logger.error("LLM 调用在 %d 次重试后仍然失败: %s", max_retries, last_error)
        raise RuntimeError(f"LLM 调用失败: {last_error}") from last_error

    def _create_llm_instance(self, config: ProviderConfig, model_id: str):
        """根据供应商类型创建对应的 LangChain LLM 实例"""
        if config.provider_type == "anthropic":
            from langchain_anthropic import ChatAnthropic

            return ChatAnthropic(
                model=model_id,
                api_key=config.api_key,
                max_tokens=4096,
                temperature=0.1,
            )
        else:
            # OpenAI 兼容接口（OpenAI / DeepSeek / Qwen / Zhipu / Custom）
            from langchain_openai import ChatOpenAI

            kwargs: dict[str, Any] = {
                "model": model_id,
                "api_key": config.api_key,
                "max_tokens": 4096,
                "temperature": 0.1,
            }
            if config.base_url:
                kwargs["base_url"] = config.base_url

            return ChatOpenAI(**kwargs)

    def _get_mock_response(self, agent: str) -> str:
        response = _MOCK_RESPONSES.get(agent, json.dumps({
            "error": "unknown_agent",
            "message": f"[MOCK] 未知 Agent: {agent}",
        }))
        logger.info("[MOCK] Agent [%s] 返回模拟数据", agent)
        return response
