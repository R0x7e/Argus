"""
LLM 供应商配置 Schema
"""

from typing import Literal

from pydantic import BaseModel, Field

ProviderType = Literal["anthropic", "openai", "deepseek", "zhipu", "qwen", "custom"]


class LLMProviderCreate(BaseModel):
    provider_type: ProviderType
    display_name: str = Field(min_length=1, max_length=100)
    api_key: str = Field(min_length=1)
    base_url: str | None = None
    default_model: str = Field(min_length=1, max_length=100)
    models_available: list[str] | None = None
    is_active: bool = True
    priority: int = Field(default=10, ge=1, le=100)


class LLMProviderUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=100)
    api_key: str | None = None
    base_url: str | None = None
    default_model: str | None = Field(default=None, max_length=100)
    models_available: list[str] | None = None
    is_active: bool | None = None
    priority: int | None = Field(default=None, ge=1, le=100)


class LLMProviderResponse(BaseModel):
    id: str
    provider_type: str
    display_name: str
    api_key_masked: str
    base_url: str | None
    default_model: str
    models_available: list[str] | None
    is_active: bool
    priority: int
    created_at: str
    updated_at: str | None

    model_config = {"from_attributes": True}


class LLMProviderTestRequest(BaseModel):
    provider_type: ProviderType
    api_key: str = Field(min_length=1)
    base_url: str | None = None
    model: str = Field(min_length=1)
