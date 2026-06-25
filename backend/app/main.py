"""
Argus 应用入口

FastAPI 应用实例，包含生命周期管理、中间件配置和路由挂载。
集成事件总线和 Agent 运行器的初始化。
"""

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.core.database import async_session_factory, engine
from app.core.event_bus import event_bus
from app.core.redis import close_redis, init_redis
from app.core.nats_client import close_nats, init_nats, get_nats_client
from app.core.middleware import RequestLoggingMiddleware, RateLimitMiddleware, register_exception_handlers
from app.models.base import Base
from app.services import agent_runner as agent_runner_module
from app.services.agent_runner import AgentRunner

# 获取配置
settings = get_settings()

# 配置日志
logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger(__name__)


async def _ensure_default_admin() -> None:
    """创建默认管理员账号，密码从环境变量 ADMIN_PASSWORD 读取，已存在则跳过"""
    import os
    from sqlalchemy import select
    from app.core.security import hash_password
    from app.models.user import User

    admin_password = os.environ.get("ADMIN_PASSWORD", "argus123")

    async with async_session_factory() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        if result.scalar_one_or_none():
            return

        admin = User(
            username="admin",
            email="admin@argus.local",
            password_hash=hash_password(admin_password),
            role="admin",
        )
        db.add(admin)
        await db.commit()
        # 日志中不输出明文密码
        logger.info("默认管理员账号已创建: admin (密码已通过环境变量 ADMIN_PASSWORD 设置)")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    应用生命周期管理

    启动时初始化数据库表、Redis 和 NATS 连接；
    关闭时优雅释放所有资源。
    """
    # === 启动阶段 ===
    logger.info("正在启动 Argus 服务...")

    # 初始化数据库表（开发模式下自动创建，生产环境应使用 alembic upgrade head）
    if settings.DEBUG:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.warning("DEBUG 模式: 使用 create_all 初始化表。生产环境请使用 'alembic upgrade head'。")

    # 创建默认管理员账号（仅在不存在时创建，任何模式下均执行）
    try:
        await _ensure_default_admin()
    except Exception as e:
        logger.warning(f"默认管理员创建失败: {e}")

    # 初始化 Redis
    try:
        await init_redis()
        logger.info("Redis 连接已建立")
    except Exception as e:
        logger.warning(f"Redis 连接失败（服务可降级运行）: {e}")

    # 初始化 NATS
    nats_available = False
    try:
        await init_nats()
        nats_available = True
        logger.info("NATS 连接已建立，JetStream 流已配置")
    except Exception as e:
        logger.warning(f"NATS 连接失败（服务可降级运行）: {e}")

    # 初始化事件总线（注入 NATS 客户端）
    if nats_available:
        try:
            event_bus.set_nats(get_nats_client())
            logger.info("事件总线已绑定 NATS 客户端")
        except Exception as e:
            logger.warning(f"事件总线绑定 NATS 失败: {e}")

    # 初始化 Playwright 浏览器
    try:
        from app.core.playwright_manager import init_playwright
        proxy_url = settings.MITMPROXY_URL.replace("http://", "")
        await init_playwright(proxy_url=f"http://{proxy_url}")
        logger.info("Playwright 浏览器已初始化")
    except Exception as e:
        logger.warning(f"Playwright 初始化失败（浏览器工具不可用）: {e}")

    # 初始化代理流量消费者
    try:
        from app.core.proxy_client import start_consumer
        await start_consumer()
        logger.info("ProxyFlowConsumer 已启动")
    except Exception as e:
        logger.warning(f"ProxyFlowConsumer 启动失败（流量工具不可用）: {e}")

    # 初始化 Agent 运行器
    runner = AgentRunner(session_factory=async_session_factory)
    agent_runner_module.agent_runner = runner
    app.state.agent_runner = runner
    logger.info("Agent 运行器已初始化")

    yield

    # === 关闭阶段 ===
    logger.info("正在关闭 Argus 服务...")

    # 关闭 Playwright
    try:
        from app.core.playwright_manager import close_playwright
        await close_playwright()
        logger.info("Playwright 已关闭")
    except Exception as e:
        logger.warning(f"Playwright 关闭异常: {e}")

    # 停止代理流量消费者
    try:
        from app.core.proxy_client import stop_consumer
        await stop_consumer()
        logger.info("ProxyFlowConsumer 已停止")
    except Exception as e:
        logger.warning(f"ProxyFlowConsumer 停止异常: {e}")

    # 关闭 NATS
    try:
        await close_nats()
        logger.info("NATS 连接已关闭")
    except Exception as e:
        logger.warning(f"NATS 关闭异常: {e}")

    # 关闭 Redis
    try:
        await close_redis()
        logger.info("Redis 连接已关闭")
    except Exception as e:
        logger.warning(f"Redis 关闭异常: {e}")

    # 释放数据库引擎
    await engine.dispose()
    logger.info("数据库连接已释放")

    logger.info("Argus 服务已停止")


# 创建 FastAPI 应用实例
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Argus - AI SRC 漏洞挖掘多 Agent 系统",
    lifespan=lifespan,
)

# 配置 CORS 中间件（根据环境变量 CORS_ORIGINS 控制）
_cors_origins = settings.get_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True if _cors_origins != ["*"] else False,  # wildcard 时不允许 credentials
    allow_methods=["*"],
    allow_headers=["*"],
)

# 添加请求日志中间件
app.add_middleware(RequestLoggingMiddleware)

# 添加认证端点速率限制（每 IP 每 60s 最多 10 次登录/注册请求）
app.add_middleware(RateLimitMiddleware, max_requests=10, window_seconds=60)

# 注册全局异常处理器（将 ArgusBaseError 转换为 JSON 响应）
register_exception_handlers(app)

# 挂载 API 路由（安全导入，模块不存在时不影响启动）
try:
    from app.api.router import api_router  # noqa: E402
    app.include_router(api_router)
    logger.info("API v1 路由已挂载")
except ImportError:
    logger.info("API 路由模块尚未创建，跳过挂载")


@app.get("/", tags=["健康检查"])
async def health_check() -> dict:
    """
    健康检查端点

    返回服务名称、版本和运行状态。
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "ok",
    }
