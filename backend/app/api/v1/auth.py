"""
认证路由

提供用户注册、登录和获取当前用户信息的 API 端点。
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.auth import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.dependencies import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.schemas.common import ApiResponse

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter()


@router.post("/register", response_model=ApiResponse[UserResponse], summary="用户注册")
async def register(
    data: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> ApiResponse[UserResponse]:
    """
    注册新用户

    - 用户名不可重复
    - 密码存储为 bcrypt 哈希
    - 默认角色为 operator
    """
    # 检查用户名是否已存在
    result = await db.execute(select(User).where(User.username == data.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="用户名已存在",
        )

    # 检查邮箱是否已注册
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="邮箱已注册",
        )

    # 创建用户
    user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role="operator",
    )
    db.add(user)
    await db.flush()

    logger.info("新用户注册: %s", data.username)

    return ApiResponse(
        code=201,
        message="注册成功",
        data=UserResponse(
            id=str(user.id),
            username=user.username,
            email=user.email,
            role=user.role,
        ),
    )


@router.post("/login", response_model=ApiResponse[TokenResponse], summary="用户登录")
async def login(
    data: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> ApiResponse[TokenResponse]:
    """
    用户登录，返回 JWT Access Token

    - 验证用户名和密码
    - 成功后更新最后登录时间
    - 返回 Bearer Token
    """
    # 查找用户
    result = await db.execute(select(User).where(User.username == data.username))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
        )

    # 更新最后登录时间
    user.last_login_at = datetime.utcnow()

    # 生成 JWT Token
    token = create_access_token(data={"sub": str(user.id), "role": user.role})

    logger.info("用户登录: %s", data.username)

    return ApiResponse(
        message="登录成功",
        data=TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        ),
    )


@router.get("/me", response_model=ApiResponse[UserResponse], summary="当前用户信息")
async def get_me(
    user: User = Depends(get_current_user),
) -> ApiResponse[UserResponse]:
    """获取当前认证用户的信息"""
    return ApiResponse(
        data=UserResponse(
            id=str(user.id),
            username=user.username,
            email=user.email,
            role=user.role,
        ),
    )
