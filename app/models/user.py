"""User models and schemas for authentication"""
from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime
from pydantic import EmailStr


# Database Models
class User(SQLModel, table=True):
    """User model with authentication fields - Admin only"""
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True, max_length=255)
    hashed_password: str
    is_active: bool = Field(default=True)
    role: str = Field(default="admin")  # Always admin
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)


class RefreshToken(SQLModel, table=True):
    """Refresh token model for token rotation"""
    __tablename__ = "refresh_tokens"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    token_hash: str = Field(unique=True, index=True)
    expires_at: datetime
    is_revoked: bool = Field(default=False)
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)


# API Schemas (Request/Response models)
class UserRegister(SQLModel):
    """Admin user registration request"""
    email: EmailStr
    password: str


class UserLogin(SQLModel):
    """User login request"""
    email: EmailStr
    password: str


class Token(SQLModel):
    """Access token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None


class RefreshTokenRequest(SQLModel):
    """Refresh token request"""
    refresh_token: str
