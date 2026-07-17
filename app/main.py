from fastapi import FastAPI, Depends
from app.core.config import settings

from contextlib import asynccontextmanager
from app.database.engine import init_db, close_db

from fastapi.middleware.cors import CORSMiddleware

from app.routers.auth import router as auth_router
from app.core.auth import get_current_user
from app.models.user import User


@asynccontextmanager
async def lifespan(app: FastAPI):
     # Startup logic
     await init_db()
     print("-" * 60)
     print(f"{settings.PROJECT_NAME} is Running...")
     print("Database Connection Initialized")
     print(f"JWT Issuer: {settings.JWT_ISSUER}")
     print(f"JWT Audience: {settings.JWT_AUDIENCE}")
     print(f"Algorithm: {settings.ALGORITHM}")
     print("JWKS Endpoint: /auth/.well-known/jwks.json")
     print("-" * 60)
     yield
     # Shutdown logic
     await close_db()
     print("Database Connection Disposed")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Centralized Authentication Service with RS256 JWT",
    version="1.0.0",
    lifespan=lifespan
)

# Include CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update with specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth_router)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": settings.PROJECT_NAME,
        "status": "running",
        "type": "auth_service",
        "jwks_endpoint": "/auth/.well-known/jwks.json"
    }


@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    """Example protected endpoint"""
    return {
        "message": "This is a protected route",
        "user_id": current_user.id,
        "email": current_user.email,
        "role": current_user.role
    }

from app.core.keys import key_manager

@app.get("/auth/.well-known/jwks.json")
async def get_jwks():
    """ JWKS (JSON Web Key Set) endpoint, Exposes public keys for token verification by resource services.
    This is a standard endpoint used by OAuth2/OIDC implementations. """
    return key_manager.get_jwks()