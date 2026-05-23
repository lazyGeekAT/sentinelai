# SentinelAI — Database Models
# Owner: Atul
# Define DB tables here using SQLAlchemy (works with SQLite or PostgreSQL)

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Text, Float, Index
)
from sqlalchemy.orm import declarative_base
from datetime import datetime
import uuid

Base = declarative_base()


def new_id():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=new_id)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    trust_score = Column(Integer, default=100)
    status = Column(String, default="active")  # active | quarantined | blocked
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)
    last_ip = Column(String, nullable=True)
    is_admin = Column(Boolean, default=False)

    # Behavioral snapshot at registration (stored as individual columns)
    typing_variance_ms = Column(Float, nullable=True)
    time_to_complete_sec = Column(Float, nullable=True)
    mouse_move_count = Column(Integer, nullable=True)
    keypress_count = Column(Integer, nullable=True)

    # ML output at registration
    ml_anomaly_score = Column(Float, nullable=True)
    triggered_flags = Column(Text, nullable=True)  # JSON array string


class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=new_id)
    user_id = Column(String, nullable=False)
    action = Column(String, nullable=False)
    # action types: register | login | login_failed | otp_sent | otp_verified
    #               quarantined | unquarantined | blocked | geo_drift
    ip_address = Column(String, nullable=True)
    country = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    trust_score_at_time = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(Text, nullable=True)  # JSON blob for extra context

    __table_args__ = (
        Index("idx_events_action_ip", "action", "ip_address"),
        Index("idx_events_action_ua", "action", "user_agent"),
        Index("idx_events_action_ts", "action", "timestamp"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=new_id)
    type = Column(String, nullable=False)
    # types: bot_wave | geo_drift | speed_bot | email_pattern
    #        duplicate_device | velocity_spike
    severity = Column(String, nullable=False)  # low | medium | high | critical
    description = Column(Text, nullable=True)
    affected_user_ids = Column(Text, nullable=True)  # JSON array string
    resolved = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


class OtpSession(Base):
    __tablename__ = "otp_sessions"

    id = Column(String, primary_key=True, default=new_id)
    user_id = Column(String, nullable=False)
    otp_code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    
    # SMTP delivery tracking (hardening)
    delivery_status = Column(String, default="pending")  # pending | delivered | failed | console_fallback
    delivery_attempts = Column(Integer, default=0)
    last_delivery_error = Column(String, nullable=True)
