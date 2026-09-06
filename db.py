from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.config import settings
def _engine_kwargs(url: str) -> dict:
    if url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True}
def make_engine():
    url = settings.database_url
    try:
        engine = create_engine(url, **_engine_kwargs(url))
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return engine, url
    except Exception:
        fallback = "sqlite:///./tracepost.db"
        engine = create_engine(fallback, **_engine_kwargs(fallback))
        return engine, fallback
engine, active_database_url = make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
class Base(DeclarativeBase):
    pass
def init_db():
    from app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
