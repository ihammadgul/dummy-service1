"""JWT Security for Auth Service (RS256 Asymmetric)"""
from datetime import datetime, timedelta, timezone
import jwt
import secrets
import hashlib
import uuid
from passlib.context import CryptContext
from app.core.config import settings
from app.core.keys import key_manager


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


def create_access_token(user_id: str, email: str, role: str) -> tuple[str, int]:
    """
    Create a signed JWT access token with RS256 algorithm
    
    Returns:
        tuple: (token, expires_in_seconds)
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())  # Unique token identifier
    
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": jti,
    }
    
    # Sign with private key
    token = jwt.encode(
        payload,
        key_manager.get_private_key_pem(),
        algorithm=settings.ALGORITHM,
        headers={"kid": key_manager.kid}
    )
    
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    return token, expires_in


def verify_access_token(token: str) -> dict:
    """
    Verify and decode a JWT token using the public key
    
    Raises:
        jwt.InvalidTokenError: If token is invalid
    """
    payload = jwt.decode(
        token,
        key_manager.get_public_key_pem(),
        algorithms=[settings.ALGORITHM],
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_iss": True,
            "verify_aud": True,
        }
    )
    return payload


def generate_refresh_token() -> str:
    """Generate a cryptographically secure refresh token"""
    return secrets.token_urlsafe(settings.REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """Hash a refresh token for storage (SHA-256)"""
    return hashlib.sha256(token.encode()).hexdigest()