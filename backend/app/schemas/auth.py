"""
认证 Schema 模块

定义登录、注册和用户信息相关的请求/响应数据模型。
"""

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """登录请求"""
    username: str = Field(min_length=2, max_length=100, description="用户名")
    password: str = Field(min_length=6, max_length=200, description="密码")


class RegisterRequest(BaseModel):
    """注册请求"""
    username: str = Field(min_length=2, max_length=100, description="用户名")
    email: EmailStr = Field(description="邮箱地址")
    password: str = Field(min_length=6, max_length=200, description="密码")


class TokenResponse(BaseModel):
    """Token 响应"""
    access_token: str = Field(description="JWT Access Token")
    token_type: str = Field(default="bearer", description="Token 类型")
    expires_in: int = Field(description="过期时间（秒）")


class UserResponse(BaseModel):
    """用户信息响应"""
    id: str = Field(description="用户 ID")
    username: str = Field(description="用户名")
    email: str = Field(description="邮箱")
    role: str = Field(description="角色")

    model_config = {"from_attributes": True}
