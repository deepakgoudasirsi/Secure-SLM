import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogSource(str, enum.Enum):
    WINDOWS = "windows"
    SYSLOG = "syslog"
    FIREWALL = "firewall"
    AUTH = "auth"
    IDS = "ids"
    UNKNOWN = "unknown"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    raw_text: Mapped[str] = mapped_column(Text)
    source: Mapped[LogSource] = mapped_column(Enum(LogSource), default=LogSource.UNKNOWN)
    normalized_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    alerts: Mapped[list["ThreatAlert"]] = relationship(back_populates="log")


class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    log_id: Mapped[int] = mapped_column(ForeignKey("security_logs.id"), index=True)
    threat_type: Mapped[str] = mapped_column(String(128))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str | None] = mapped_column(Text, nullable=True)
    slm_mode: Mapped[str] = mapped_column(String(32), default="template")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    log: Mapped["SecurityLog"] = relationship(back_populates="alerts")
