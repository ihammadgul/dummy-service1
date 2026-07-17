"""Authentication dependencies for Service1 (Auth Service)"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import settings
from app.core.security import verify_access_token
from app.models.user import User
from app.database.engine import get_session
from sqlmodel import select

# Bearer token scheme (simpler than OAuth2PasswordBearer)
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session=Depends(get_session)
) -> User:
    """
    Dependency to get current authenticated user
    
    Verifies the JWT token and returns the user object
    """
    exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Verify token using RS256 public key
        token = credentials.credentials
        payload = verify_access_token(token)
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise exception
            
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fetch user from database
    result = await session.exec(select(User).where(User.id == int(user_id)))
    user = result.first()

    if not user:
        raise exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    return user


def require_role(required_role: str):
    """
    Dependency factory to enforce role-based access control
    
    Usage:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
    """
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role}"
            )
        return current_user
    
    return role_checker
