"""
认证依赖注入

提供 get_current_user 依赖，从请求头中提取并验证 JWT Token。
"""

from fastapi import Cookie, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.dependencies import get_db
from app.models.user import User

# Bearer Token 提取器
security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    access_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    从 Authorization 头或 httpOnly Cookie 提取 JWT 并返回当前用户

    优先级：Bearer Header > httpOnly Cookie

    Raises:
        HTTPException 401: Token 缺失、无效或用户不存在
    """
    # 优先使用 Bearer Header，其次使用 Cookie
    token: str | None = None
    if credentials:
        token = credentials.credentials
    elif access_token:
        token = access_token

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未提供认证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token 无效或已过期",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token 格式错误",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户不存在",
        )

    return user


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """
    可选的用户认证依赖

    Token 缺失时返回 None（不抛异常），用于公开+可选认证的端点。
    """
    if credentials is None:
        return None

    payload = decode_access_token(credentials.credentials)
    if payload is None:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


def require_role(allowed_roles: list[str]):
    """
    角色检查依赖工厂

    Usage:
        @router.get("/admin", dependencies=[Depends(require_role(["admin"]))])
    """
    async def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"权限不足，需要角色: {', '.join(allowed_roles)}",
            )
        return user
    return role_checker


async def verify_task_ownership(
    task_id: str,
    user: User,
    db: AsyncSession,
) -> None:
    """
    IDOR 防护：验证当前用户是否有权操作指定任务

    Admin 用户可以操作任何任务，其他用户只能操作自己创建的任务。
    """
    import uuid as _uuid
    from app.models.task import Task

    if user.role == "admin":
        return  # Admin 可以操作任何资源

    result = await db.execute(
        select(Task.created_by).where(Task.id == _uuid.UUID(task_id))
    )
    created_by = result.scalar_one_or_none()
    if created_by is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if created_by != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足，只能操作自己创建的任务",
        )
