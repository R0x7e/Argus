"""
Argus 测试配置

提供测试用的 fixtures：内存数据库、测试客户端、模拟服务等。
"""

import asyncio
from collections.abc import AsyncGenerator, Generator
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.models.base import Base


# SQLite 异步内存数据库，用于单元测试
TEST_DATABASE_URL = "sqlite+aiosqlite:///file::memory:?cache=shared"


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """为整个测试会话创建单一事件循环"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_engine():
    """创建测试用异步数据库引擎"""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """为每个测试创建独立的数据库会话（自动回滚）"""
    async_session = sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    """创建测试用 HTTP 客户端"""
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_llm():
    """模拟 LLM 客户端，避免真实 API 调用"""
    llm = AsyncMock()
    llm.invoke.return_value = AsyncMock(
        content='{"action": "continue", "analysis": "test analysis"}'
    )
    return llm
