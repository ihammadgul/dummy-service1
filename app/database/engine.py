from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.core.config import settings

# Import models to ensure they're registered with SQLModel metadata
from app.models.user import User, RefreshToken


engine = create_async_engine(settings.DATABASE_URL, echo=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session():
     async with SessionLocal() as session:
          yield session


async def init_db():
     async with engine.begin() as conn:
          await conn.run_sync(SQLModel.metadata.create_all)
          
async def close_db():
     await engine.dispose()
               