"""
认证工具模块

提供 JWT Token 生成/验证和密码哈希/校验工具函数。
"""

import hashlib
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from app.config import get_settings

settings = get_settings()


def hash_password(password: str) -> str:
    """将明文密码哈希为 bcrypt 格式（通过 SHA-256 预处理规避 72 字节限制）"""
    import bcrypt
    # bcrypt 有 72 字节限制，先用 SHA-256 预哈希
    pw_bytes = hashlib.sha256(password.encode()).hexdigest().encode()
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pw_bytes, salt).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证明文密码是否匹配已存储的哈希值"""
    import bcrypt
    pw_bytes = hashlib.sha256(plain_password.encode()).hexdigest().encode()
    return bcrypt.checkpw(pw_bytes, hashed_password.encode())


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    """
    生成 JWT Access Token

    Args:
        data: 要编码进 token 的数据（至少包含 sub 字段）
        expires_delta: 过期时间增量，默认使用配置中的 JWT_EXPIRE_MINUTES

    Returns:
        编码后的 JWT 字符串
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """
    解码并验证 JWT Token

    Returns:
        解码后的 payload 字典，token 无效或过期时返回 None
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None
