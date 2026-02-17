from sqlalchemy import String, Integer, Float, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

DATABASE_URL = "sqlite+aiosqlite:///./triad_scan.db"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class AssetORM(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cpe_string: Mapped[str] = mapped_column(String, nullable=False, index=True)

    confidentiality: Mapped[int] = mapped_column(Integer, nullable=False)
    integrity: Mapped[int] = mapped_column(Integer, nullable=False)
    availability: Mapped[int] = mapped_column(Integer, nullable=False)


class VulnerabilityORM(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)

    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    is_known_exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
