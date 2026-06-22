"""
Argus 全局配置模块

使用 pydantic-settings 从环境变量加载配置，支持 .env 文件。
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # 代理流量 Redis 发布频道
    PROXY_FLOWS_CHANNEL: str = "proxy:flows"


@lru_cache()
def get_settings() -> Settings:
    """获取全局配置单例（带缓存）"""
    return Settings()
