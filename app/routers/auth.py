"""Authentication router for Service1 (Auth Service)"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select
from datetime import datetime, timedelta, timezone

from app.core.security import (
    verify_password, 
    hash_password,
    create_access_token,
    generate_refresh_token,
    hash_refresh_token
)
from app.database.engine import get_session
from app.models.user import User, RefreshToken, Token, RefreshTokenRequest, UserRegister, UserLogin
from app.core.keys import key_manager
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister, session=Depends(get_session)):
    """Register a new user"""
    # Check if user exists
    query = select(User).where(User.email == user_data.email)
    result = await session.exec(query)
    if result.first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create admin user
    user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        role="admin"  # Always admin
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    
    return {"message": "User registered successfully", "user_id": user.id}


@router.post("/login", response_model=Token)
async def login(login_data: UserLogin, session=Depends(get_session)):
    """
    Authenticate user and issue JWT tokens
    
    Issues:
    - Access token (short-lived, RS256 signed)
    - Refresh token (long-lived, stored in database)
    """
    # Find user
    query = select(User).where(User.email == login_data.email)
    result = await session.exec(query)
    user = result.first()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    # Create access token with full claims
    access_token, expires_in = create_access_token(
        user_id=str(user.id),
        email=user.email,
        role=user.role
    )
    
    # Generate refresh token
    refresh_token_str = generate_refresh_token()
    refresh_token_hash = hash_refresh_token(refresh_token_str)
    
    # Store refresh token in database
    refresh_token = RefreshToken(
        user_id=user.id,
        token_hash=refresh_token_hash,
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    session.add(refresh_token)
    await session.commit()
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        refresh_token=refresh_token_str
    )


@router.post("/refresh", response_model=Token)
async def refresh_access_token(
    refresh_request: RefreshTokenRequest,
    session=Depends(get_session)
):
    """
    Exchange a valid refresh token for a new access token
    """
    token_hash = hash_refresh_token(refresh_request.refresh_token)
    
    # Find refresh token
    query = select(RefreshToken).where(
        RefreshToken.token_hash == token_hash,
        RefreshToken.is_revoked == False
    )
    result = await session.exec(query)
    refresh_token = result.first()
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Check expiration
    if refresh_token.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired"
        )
    
    # Get user
    query = select(User).where(User.id == refresh_token.user_id)
    result = await session.exec(query)
    user = result.first()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new access token
    access_token, expires_in = create_access_token(
        user_id=str(user.id),
        email=user.email,
        role=user.role
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in
    )


@router.post("/revoke")
async def revoke_refresh_token(
    refresh_request: RefreshTokenRequest,
    session=Depends(get_session)
):
    """Revoke a refresh token"""
    token_hash = hash_refresh_token(refresh_request.refresh_token)
    
    query = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    result = await session.exec(query)
    refresh_token = result.first()
    
    if refresh_token:
        refresh_token.is_revoked = True
        session.add(refresh_token)
        await session.commit()
    
    return {"message": "Token revoked successfully"}

