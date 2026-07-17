from pydantic_settings import BaseSettings


class Settings(BaseSettings):
     PROJECT_NAME: str = "Auth Service"
     DATABASE_URL: str
     
     
     PRIVATE_KEY_PATH: str
     PUBLIC_KEY_PATH: str 

     ALGORITHM: str = "RS256"
     ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
     REFRESH_TOKEN_EXPIRE_DAYS: int = 7
     REFRESH_TOKEN_BYTES: int = 32 

     JWT_ISSUER: str = "auth.name"
     JWT_AUDIENCE: str = "name.services"
     
    
     class Config:
          env_file = ".env"

settings = Settings()