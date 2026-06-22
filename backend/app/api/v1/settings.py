"""
系统设置路由 — LLM 供应商管理

提供 AI 供应商的 CRUD 接口和连接测试功能。
所有端点均要求管理员角色。
"""

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_role
from app.core.encryption import decrypt_api_key, encrypt_api_key
from app.dependencies import get_db
from app.models.llm_provider import LLMProvider
from app.models.user import User
from app.schemas.common import ApiResponse
from app.schemas.llm_provider import (
    LLMProviderCreate,
    LLMProviderResponse,
    LLMProviderTestRequest,
    LLMProviderUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _mask_key(encrypted_key: str) -> str:
    """将加密的 API Key 解密后脱敏展示"""
    try:
        plain = decrypt_api_key(encrypted_key)
        if len(plain) <= 8:
            return "****"
        return f"{plain[:3]}...{plain[-4:]}"
    except Exception:
        return "****"


def _to_response(provider: LLMProvider) -> dict:
    return {
        "id": str(provider.id),
        "provider_type": provider.provider_type,
        "display_name": provider.display_name,
        "api_key_masked": _mask_key(provider.api_key_encrypted),
        "base_url": provider.base_url,
        "default_model": provider.default_model,
        "models_available": provider.models_available,
        "is_active": provider.is_active,
        "priority": provider.priority,
        "created_at": provider.created_at.isoformat() if provider.created_at else "",
        "updated_at": provider.updated_at.isoformat() if provider.updated_at else None,
    }


@router.get("/llm-providers", response_model=ApiResponse, summary="获取所有 LLM 供应商配置")
async def list_providers(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_role(["admin"])),
) -> ApiResponse:
    stmt = select(LLMProvider).order_by(LLMProvider.priority, LLMProvider.created_at)
    result = await db.execute(stmt)
    providers = result.scalars().all()
    return ApiResponse(data=[_to_response(p) for p in providers])


@router.post("/llm-providers", response_model=ApiResponse, summary="新增 LLM 供应商")
async def create_provider(
    body: LLMProviderCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(["admin"])),
) -> ApiResponse:
    provider = LLMProvider(
        provider_type=body.provider_type,
        display_name=body.display_name,
        api_key_encrypted=encrypt_api_key(body.api_key),
        base_url=body.base_url,
        default_model=body.default_model,
        models_available=body.models_available,
        is_active=body.is_active,
        priority=body.priority,
        created_by=user.id,
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return ApiResponse(message="供应商已添加", data=_to_response(provider))


@router.put("/llm-providers/{provider_id}", response_model=ApiResponse, summary="更新 LLM 供应商")
async def update_provider(
    provider_id: str,
    body: LLMProviderUpdate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_role(["admin"])),
) -> ApiResponse:
    result = await db.execute(select(LLMProvider).where(LLMProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="供应商不存在")

    update_data = body.model_dump(exclude_unset=True)
    if "api_key" in update_data:
        api_key = update_data.pop("api_key")
        if api_key:
            provider.api_key_encrypted = encrypt_api_key(api_key)

    for field, value in update_data.items():
        setattr(provider, field, value)

    await db.commit()
    await db.refresh(provider)
    return ApiResponse(message="供应商已更新", data=_to_response(provider))


@router.delete("/llm-providers/{provider_id}", response_model=ApiResponse, summary="删除 LLM 供应商")
async def delete_provider(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_role(["admin"])),
) -> ApiResponse:
    result = await db.execute(select(LLMProvider).where(LLMProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="供应商不存在")

    await db.delete(provider)
    await db.commit()
    return ApiResponse(message="供应商已删除")


@router.post("/llm-providers/test", response_model=ApiResponse, summary="测试 LLM 供应商连接")
async def test_provider(
    body: LLMProviderTestRequest,
    _user: User = Depends(require_role(["admin"])),
) -> ApiResponse:
    """测试供应商连接：发送一条极简消息验证 API Key 和端点可用性"""
    start = time.time()
    try:
        if body.provider_type == "anthropic":
            from langchain_anthropic import ChatAnthropic

            llm = ChatAnthropic(
                model=body.model,
                api_key=body.api_key,
                max_tokens=10,
                timeout=15,
            )
        else:
            from langchain_openai import ChatOpenAI

            kwargs: dict = {
                "model": body.model,
                "api_key": body.api_key,
                "max_tokens": 10,
                "timeout": 15,
            }
            if body.base_url:
                kwargs["base_url"] = body.base_url

            llm = ChatOpenAI(**kwargs)

        await llm.ainvoke("Hi")
        latency_ms = int((time.time() - start) * 1000)
        return ApiResponse(data={"success": True, "latency_ms": latency_ms})

    except Exception as e:
        latency_ms = int((time.time() - start) * 1000)
        error_msg = str(e)[:200]
        logger.warning("LLM provider test failed: %s", error_msg)
        return ApiResponse(
            data={"success": False, "latency_ms": latency_ms, "error": error_msg}
        )
