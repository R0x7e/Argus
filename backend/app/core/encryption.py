"""
API Key 加密工具

使用 Fernet 对称加密存储敏感信息（如 LLM 供应商 API Key）。
密钥从 JWT_SECRET 派生，确保与应用安全配置绑定。
"""

import base64
import hashlib

from cryptography.fernet import Fernet

from app.config import get_settings


def _get_fernet() -> Fernet:
    settings = get_settings()
    key = base64.urlsafe_b64encode(
        hashlib.sha256(settings.JWT_SECRET.encode()).digest()
    )
    return Fernet(key)


def encrypt_api_key(plain_key: str) -> str:
    return _get_fernet().encrypt(plain_key.encode()).decode()


def decrypt_api_key(encrypted_key: str) -> str:
    return _get_fernet().decrypt(encrypted_key.encode()).decode()
