"""
Argus 全局配置模块

使用 pydantic-settings 从环境变量加载配置，支持 .env 文件。
"""

import logging
import secrets
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

# 已知的不安全默认值，非 DEBUG 模式下禁止使用
_INSECURE_JWT_DEFAULTS = frozenset({
    "your-super-secret-key-change-in-production",
    "argus-dev-secret-key-2024",
    "",
})


class Settings(BaseSettings):
    """应用配置类，从环境变量和 .env 文件加载配置项"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # 数据库连接（异步 PostgreSQL）
    DATABASE_URL: str = "postgresql+asyncpg://argus:argus_dev_password@localhost:5432/argus"

    # Redis 连接
    REDIS_URL: str = "redis://localhost:6379/0"

    # NATS 消息总线连接
    NATS_URL: str = "nats://localhost:4222"

    # Anthropic API 密钥
    ANTHROPIC_API_KEY: str = ""

    # JWT 认证配置
    JWT_SECRET: str = "your-super-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440  # 默认 24 小时

    # 独立的加密密钥（用于 Fernet 加密 API Key），默认从 JWT_SECRET 派生但推荐使用独立密钥
    ENCRYPTION_KEY: str = ""

    # CORS 允许的来源列表（逗号分隔）
    CORS_ORIGINS: str = "*"

    # 调试模式
    DEBUG: bool = False

    # 日志级别
    LOG_LEVEL: str = "INFO"

    # 应用信息
    APP_NAME: str = "Argus"
    APP_VERSION: str = "0.1.0"

    # mitmproxy 代理地址
    MITMPROXY_URL: str = "http://mitmproxy:8080"

    # crawlergo 深度爬虫 API 地址
    CRAWLERGO_URL: str = "http://crawlergo:7777"

    # PoC 沙箱执行器地址
    POC_SANDBOX_URL: str = "http://poc-sandbox:9090"

    # Sidecar 服务共享密钥（用于内部服务认证）
    SIDECAR_SECRET: str = ""

    # 代理流量 Redis 发布频道
    PROXY_FLOWS_CHANNEL: str = "proxy:flows"

    # 任务执行全局超时（秒）
    TASK_TIMEOUT_SECONDS: int = 3600

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        """启动时校验安全配置，非 DEBUG 模式下拒绝使用不安全的默认值"""
        if not self.DEBUG:
            if self.JWT_SECRET in _INSECURE_JWT_DEFAULTS:
                raise ValueError(
                    "JWT_SECRET 使用了不安全的默认值，请在环境变量中设置安全的密钥。"
                    "可通过 python -c \"import secrets; print(secrets.token_hex(32))\" 生成。"
                )
        return self

    def get_cors_origins(self) -> list[str]:
        """解析 CORS 来源配置"""
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache()
def get_settings() -> Settings:
    """获取全局配置单例（带缓存）"""
    return Settings()
