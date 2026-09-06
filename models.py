import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base
def utcnow() -> datetime:
    return datetime.now(timezone.utc)
class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    filename: Mapped[str] = mapped_column(String(255), default="message.eml")
    subject: Mapped[str] = mapped_column(String(512), default="")
    from_addr: Mapped[str] = mapped_column(String(512), default="")
    classification: Mapped[str] = mapped_column(String(64), default="UNSCORED")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    indicators: Mapped[list["Indicator"]] = relationship(back_populates="case", cascade="all, delete-orphan")
class Indicator(Base):
    __tablename__ = "indicators"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # ip, domain, url, email
    value: Mapped[str] = mapped_column(String(1024), index=True)
    case: Mapped[Case] = relationship(back_populates="indicators")
