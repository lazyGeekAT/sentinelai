from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.orm import Session
from database import get_db
from models import User, Event, Alert, OtpSession
from scorer import score_registration, score_login, BehavioralPayload
from geo import get_country
from mailer import send_otp_email
import hashlib
import secrets
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pathlib import Path
from logging_config import get_logger
from error_codes import ErrorCode
from monitoring import record_auth_event, record_security_rule, record_alert

# JWT imports
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import Optional
import base64
import hmac
from slowapi import Limiter
from starlette.requests import ClientDisconnect

ROOT = Path(__file__).resolve().parents[1]
# Load the canonical project `.env` at the repository root
load_dotenv(ROOT / '.env')

logger = get_logger(__name__)
router = APIRouter()

# Rate limiter for brute force protection
def _rate_limit_key(request: Request) -> str:
    """Resolve client IP respecting X-Forwarded-For so rate limiting works behind proxies."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        forwarded_ip = xff.split(",")[0].strip()
        if forwarded_ip:
            return forwarded_ip
    return request.client.host if request.client else "127.0.0.1"

limiter = Limiter(key_func=_rate_limit_key)

# JWT config
SECRET_KEY = os.getenv("JWT_SECRET", "your-secret-key-change-in-prod")
if SECRET_KEY == "your-secret-key-change-in-prod":
    if os.getenv("ENV", "development") != "development":
        raise RuntimeError("JWT_SECRET must be set in non-development environments")
    import warnings
    warnings.warn("⚠️  WARNING: JWT_SECRET is using the default value! This is insecure. Set JWT_SECRET environment variable to a random 32+ byte string.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

import bcrypt

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    trust_score: int


class CaptchaVerifyRequest(BaseModel):
    captcha_token: str
    captcha_answer: str


class CaptchaChallengeResponse(BaseModel):
    captcha_required: bool
    captcha_token: str
    captcha_prompt: str
    user_id: str
    recommendation: str


def validate_password(password: str) -> None:
    """Validate password strength. Raises HTTPException on failure."""
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not any(c.isalpha() for c in password):
        raise HTTPException(status_code=400, detail="Password must contain at least one letter")
    if not any(c.isdigit() for c in password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit")


def hash_password(password: str) -> str:
    """Hash password using bcrypt (secure, slow hash function resistant to brute force)."""
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds ≈ 200ms on modern hardware
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password: str, hash_value: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hash_value.encode('utf-8'))
    except Exception:
        return False


def _get_registration_counts(db: Session, *, ip_address: str, user_agent: str, since: datetime) -> tuple[int, int]:
    registrations_from_ip = (
        db.query(Event)
        .filter(
            Event.action == "register",
            Event.ip_address == ip_address,
            Event.timestamp >= since,
        )
        .count()
    )
    same_ua_count = (
        db.query(Event)
        .filter(
            Event.action == "register",
            Event.user_agent == user_agent,
            Event.timestamp >= since,
        )
        .count()
    )
    return registrations_from_ip, same_ua_count


def _create_alerts(db: Session, user_id: str, email: str, triggered_rules: list[str]) -> None:
    severity_map = {
        "geo_drift": "high",
        "velocity_ip": "high",
        "speed_bot": "high",
        "duplicate_device": "medium",
        "email_pattern": "medium",
        "velocity_spike": "high",
        "platform_velocity_spike": "high",
    }
    for rule in triggered_rules:
        # Rename platform_velocity_spike to bot_wave for dashboard consistency
        alert_type = "bot_wave" if rule == "platform_velocity_spike" else rule
        db.add(
            Alert(
                type=alert_type,
                severity=severity_map.get(rule, "medium"),
                description=f"Rule triggered: {rule} for {email}",
                affected_user_ids=user_id,
            )
        )
        try:
            # increment Prometheus metrics for rule and alert
            record_security_rule(rule)
            record_alert(alert_type)
        except Exception:
            # Metric recording must never break the main flow
            logger.debug("Failed to record monitoring metric for alert/rule")


def _create_ml_alert(db: Session, user_id: str, email: str, ml_anomaly_score: Optional[float]) -> None:
    if ml_anomaly_score is None or ml_anomaly_score > -0.5:
        return

    severity = "high" if ml_anomaly_score <= -0.8 else "medium"
    db.add(
        Alert(
            type="ml_anomaly",
            severity=severity,
            description=f"ML anomaly detected for {email} (score: {ml_anomaly_score:.2f})",
            affected_user_ids=user_id,
        )
    )


def _extract_ip(request: Request, payload: dict) -> str:
    """
    Resolve the client IP with proxy/header support for local demo scripts.
    Priority: X-Forwarded-For header -> request payload -> socket client host.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        forwarded_ip = xff.split(",")[0].strip()
        if forwarded_ip:
            return forwarded_ip

    payload_ip = payload.get("ip_address")
    if payload_ip:
        return str(payload_ip)

    return request.client.host if request.client else "127.0.0.1"


def _extract_user_agent(request: Request, payload: dict) -> str:
    """Prefer real HTTP User-Agent header, then payload fallback for scripted tests."""
    return request.headers.get("user-agent") or payload.get("user_agent") or "unknown"


async def _safe_read_json(request: Request) -> dict:
    """Read JSON body but handle client disconnects and invalid JSON gracefully."""
    try:
        return await request.json()
    except ClientDisconnect:
        logger.debug("Client disconnected while sending request body for %s", request.url.path)
        raise HTTPException(status_code=400, detail="Client disconnected while sending body")
    except Exception:
        logger.debug("Failed to parse JSON body for %s", request.url.path)
        raise HTTPException(status_code=400, detail="Invalid JSON body")


def create_access_token(user: User, expires_delta: timedelta = None) -> str:
    """Create a JWT access token for the user."""
    if expires_delta is None:
        expires_delta = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    
    expire = datetime.utcnow() + expires_delta
    to_encode = {
        "sub": user.id,
        "email": user.email,
        "is_admin": user.is_admin,
        "exp": expire,
    }
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def _create_captcha_challenge(user_id: str, prompt_length: int = 6) -> tuple[str, str]:
    """Create a signed captcha challenge that can be verified without DB state."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    prompt = "".join(secrets.choice(alphabet) for _ in range(prompt_length))
    issued_at = datetime.utcnow().timestamp()
    payload = f"{user_id}:{prompt}:{issued_at:.0f}"
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token = base64.urlsafe_b64encode(f"{payload}:{signature}".encode("utf-8")).decode("utf-8")
    return token, prompt


def _verify_captcha_challenge(captcha_token: str, captcha_answer: str, max_age_seconds: int = 300) -> str:
    """Verify the signed captcha challenge and return the user_id if valid."""
    try:
        decoded = base64.urlsafe_b64decode(captcha_token.encode("utf-8")).decode("utf-8")
        user_id, prompt, issued_at_raw, signature = decoded.rsplit(":", 3)
        payload = f"{user_id}:{prompt}:{issued_at_raw}"
        expected_signature = hmac.new(
            SECRET_KEY.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid captcha signature")
        if captcha_answer.strip().upper() != prompt.upper():
            raise ValueError("Incorrect captcha answer")
        if (datetime.utcnow().timestamp() - float(issued_at_raw)) > max_age_seconds:
            raise ValueError("Captcha challenge expired")
        return user_id
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    """
    Dependency to verify JWT token and get current user.
    Extracts token from Authorization header: "Bearer <token>"
    Used by all protected endpoints.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    try:
        # Extract token from "Bearer <token>" format
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authorization header format")
        
        token = parts[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency that blocks non-admin users from admin routes."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied: admin privileges required")
    return current_user


@limiter.limit("5/minute")  # Max 5 registration attempts per IP per minute
@router.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    data = await _safe_read_json(request)
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        try:
            record_auth_event('registration', 'failed')
        except Exception:
            logger.debug('Failed to record registration missing-fields metric')
        raise HTTPException(status_code=400, detail="Missing email or password")

    validate_password(password)
    
    # Check if user exists - don't reveal this to prevent user enumeration
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        # Log this attempt but return generic error
        try:
            record_auth_event('registration', 'failed')
        except Exception:
            logger.debug('Failed to record registration failed metric')
        raise HTTPException(status_code=400, detail="Registration failed. Please try again or contact support.")
    
    # Parse behavioral payload — accepts both camelCase (JS SDK) and short form
    beh_data = data.get("behavioralData") or data.get("behavioral") or {}
    behavioral = BehavioralPayload(
        typing_variance_ms=beh_data.get("typing_variance_ms", 150),
        time_to_complete_sec=beh_data.get("time_to_complete_sec", 10),
        mouse_move_count=beh_data.get("mouse_move_count", 20),
        keypress_count=beh_data.get("keypress_count", 20),
        session_tempo_sec=beh_data.get("session_tempo_sec"),
        mouse_entropy_score=beh_data.get("mouse_entropy_score"),
        fill_order_score=beh_data.get("fill_order_score"),
    )

    ip_address = _extract_ip(request, data)
    user_agent = _extract_user_agent(request, data)
    
    hour_ago = datetime.utcnow() - timedelta(hours=1)
    minute_ago = datetime.utcnow() - timedelta(minutes=1)
    reg_count, same_ua_count = _get_registration_counts(
        db,
        ip_address=ip_address,
        user_agent=user_agent,
        since=hour_ago,
    )
    
    # Query platform-wide registrations per minute for spike detection
    registrations_per_minute = (
        db.query(Event)
        .filter(Event.action == "register", Event.timestamp >= minute_ago)
        .count()
    )
    
    score_result = score_registration(
        email=email,
        behavioral=behavioral,
        ip_address=ip_address,
        user_agent=user_agent,
        registrations_from_ip_last_hour=reg_count,
        accounts_with_same_ua_today=same_ua_count,
        registrations_per_minute=registrations_per_minute,
    )
    
    new_user = User(
        email=email,
        password_hash=hash_password(password),
        trust_score=score_result.trust_score,
        status="quarantined" if score_result.trust_score < 40 else "active",
        last_ip=ip_address,
        typing_variance_ms=behavioral.typing_variance_ms,
        time_to_complete_sec=behavioral.time_to_complete_sec,
        mouse_move_count=behavioral.mouse_move_count,
        keypress_count=behavioral.keypress_count,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Log event
    event = Event(
        user_id=new_user.id,
        action="register",
        ip_address=ip_address,
        country=get_country(ip_address),
        user_agent=user_agent,
        trust_score_at_time=score_result.trust_score,
        metadata_json=json.dumps({
            "triggered_rules": score_result.triggered_rules,
            "rule_penalty": score_result.rule_penalty,
            "behavioral_penalty": score_result.behavioral_penalty,
            "ml_penalty": score_result.ml_penalty,
            "ml_anomaly_score": score_result.ml_anomaly_score,
            "recommendation": score_result.recommendation,
        }),
    )
    db.add(event)
    
    # Create alerts if triggered
    _create_alerts(db, new_user.id, email, score_result.triggered_rules)
    _create_ml_alert(db, new_user.id, email, score_result.ml_anomaly_score)
        
    db.commit()
    try:
        # Record registration metric (status: active/quarantined)
        record_auth_event('registration', new_user.status)
    except Exception:
        logger.debug('Failed to record registration metric')

    return {
        "message": "Registration successful",
        "trust_score": score_result.trust_score,
        "status": new_user.status,
        "triggered_rules": score_result.triggered_rules,
        "rule_penalty": score_result.rule_penalty,
        "behavioral_penalty": score_result.behavioral_penalty,
        "ml_penalty": score_result.ml_penalty,
        "recommendation": score_result.recommendation,
    }


@limiter.limit("10/minute")  # Max 10 login attempts per IP per minute
@router.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    data = await _safe_read_json(request)
    email = data.get("email")
    password = data.get("password")
    
    if not email or not password:
        try:
            record_auth_event('login', 'failed')
        except Exception:
            logger.debug('Failed to record login missing-fields metric')
        raise HTTPException(status_code=400, detail="Missing email or password")
    
    user = db.query(User).filter(User.email == email).first()
    
    # Verify password using bcrypt - always check even if user doesn't exist (timing attack mitigation)
    password_valid = verify_password(password, user.password_hash) if user else False
    
    ip_address = _extract_ip(request, data)
    user_agent = _extract_user_agent(request, data)
    
    if not user or not password_valid:
        # Generic error - don't reveal whether user exists or password is wrong
        try:
            record_auth_event('login', 'failed')
        except Exception:
            logger.debug('Failed to record login failed metric')
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    current_country = get_country(ip_address)
    previous_login_event = (
        db.query(Event)
        .filter(Event.user_id == user.id, Event.action == "login")
        .order_by(Event.timestamp.desc())
        .first()
    )
    last_country = previous_login_event.country if previous_login_event else None
    minutes_since_last_login = None
    if previous_login_event and previous_login_event.timestamp:
        minutes_since_last_login = (
            (datetime.utcnow() - previous_login_event.timestamp).total_seconds() / 60.0
        )

    score_result = score_login(
        user_id=user.id,
        existing_trust_score=user.trust_score,
        ip_address=ip_address,
        current_country=current_country,
        last_country=last_country,
        minutes_since_last_login=minutes_since_last_login,
    )
    
    user.trust_score = score_result.trust_score
    user.status = "blocked" if score_result.trust_score < 20 else "quarantined" if score_result.trust_score < 40 else "active"
    user.last_login_at = datetime.utcnow()
    db.commit()
    
    # Log event
    event = Event(
        user_id=user.id,
        action="login",
        ip_address=ip_address,
        country=current_country,
        user_agent=user_agent,
        trust_score_at_time=score_result.trust_score,
        metadata_json=json.dumps({
            "triggered_rules": score_result.triggered_rules,
            "rule_penalty": score_result.rule_penalty,
            "behavioral_penalty": score_result.behavioral_penalty,
            "ml_penalty": score_result.ml_penalty,
            "ml_anomaly_score": score_result.ml_anomaly_score,
            "recommendation": score_result.recommendation,
        }),
    )
    db.add(event)
    _create_alerts(db, user.id, email, score_result.triggered_rules)
    _create_ml_alert(db, user.id, email, score_result.ml_anomaly_score)
    db.commit()
    
    # Generate JWT token
    access_token = create_access_token(user)
    
    # Determine action based on recommendation (progressive auth policy)
    # allow (>70): smooth login, otp (40-70): OTP challenge, captcha (20-39): captcha challenge, quarantine (<20): block + alert
    otp_required = score_result.recommendation == "otp"
    captcha_required = score_result.recommendation == "captcha"
    is_blocked = score_result.recommendation == "quarantine"

    if score_result.recommendation in ["captcha", "quarantine"]:
        db.add(
            Alert(
                type="captcha_challenge" if captcha_required else "trust_quarantine",
                severity="medium" if captcha_required else "high",
                description=f"Low-trust login for {email}: {score_result.recommendation}",
                affected_user_ids=user.id,
            )
        )
        try:
            record_alert("captcha_challenge" if captcha_required else "trust_quarantine")
        except Exception:
            logger.debug('Failed to record login alert metric')
    
    if is_blocked:
        # Trust score too low — reject login and alert
        try:
            record_auth_event('login', 'quarantined')
        except Exception:
            logger.debug('Failed to record login quarantined metric')
        return {
            "token": None,
            "trust_score": score_result.trust_score,
            "otp_required": False,
            "is_blocked": True,
            "user_id": user.id,
            "recommendation": score_result.recommendation,
            "message": "Account flagged. Please contact support."
        }
    elif otp_required:
        # Create OTP session for medium-trust users
        otp_code = secrets.randbelow(1000000)
        otp_code_str = str(otp_code).zfill(6)
        otp_session = OtpSession(
            user_id=user.id,
            otp_code=otp_code_str,
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.add(otp_session)
        db.commit()
        db.refresh(otp_session)
        
        try:
            record_auth_event('login', 'otp_required')
        except Exception:
            logger.debug('Failed to record login otp_required metric')
        return {
            "token": None,
            "trust_score": score_result.trust_score,
            "otp_required": True,
            "otp_session_id": otp_session.id,
            "user_id": user.id,
            "recommendation": score_result.recommendation
        }
    elif captcha_required:
        try:
            record_auth_event('login', 'captcha_required')
        except Exception:
            logger.debug('Failed to record login captcha_required metric')
        captcha_token, captcha_prompt = _create_captcha_challenge(user.id)
        return {
            "token": None,
            "trust_score": score_result.trust_score,
            "captcha_required": True,
            "captcha_token": captcha_token,
            "captcha_prompt": captcha_prompt,
            "user_id": user.id,
            "recommendation": score_result.recommendation,
        }
    else:
        try:
            record_auth_event('login', 'success')
        except Exception:
            logger.debug('Failed to record login success metric')
        # High-trust user — allow smooth login
        return {
            "token": access_token,
            "token_type": "bearer",
            "trust_score": score_result.trust_score,
            "otp_required": False,
            "user_id": user.id,
            "recommendation": score_result.recommendation
        }


@router.post("/captcha/verify")
async def verify_captcha(request: Request, db: Session = Depends(get_db)):
    """Verify a captcha challenge and issue a JWT token."""
    data = await _safe_read_json(request)
    captcha_token = data.get("captcha_token")
    captcha_answer = data.get("captcha_answer")

    if not captcha_token or not captcha_answer:
        raise HTTPException(status_code=400, detail="Missing captcha_token or captcha_answer")

    user_id = _verify_captcha_challenge(captcha_token, captcha_answer)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access_token = create_access_token(user)

    event = Event(
        user_id=user.id,
        action="captcha_verified",
        ip_address=request.client.host if request.client else "127.0.0.1",
        user_agent=request.headers.get("user-agent", "unknown"),
        trust_score_at_time=user.trust_score,
        metadata_json=json.dumps({"captcha_verified": True}),
    )
    db.add(event)
    db.commit()

    return {
        "token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "message": "Captcha verified successfully",
    }


@router.post("/otp/send")
async def send_otp(request: Request, db: Session = Depends(get_db)):
    """Send OTP code to user's email."""
    data = await _safe_read_json(request)
    otp_session_id = data.get("otp_session_id")
    email = data.get("email")
    
    if not otp_session_id or not email:
        raise HTTPException(status_code=400, detail="Missing otp_session_id or email")
    
    otp_session = db.query(OtpSession).filter(OtpSession.id == otp_session_id).first()
    
    if not otp_session:
        raise HTTPException(status_code=400, detail="Invalid OTP session")

    user = db.query(User).filter(User.id == otp_session.user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    if user.email != email:
        raise HTTPException(status_code=400, detail="Email does not match OTP session")
    
    # Send OTP with retry logic (hardening)
    delivery_result = send_otp_email(email, otp_session.otp_code)
    
    # Update OTP session with delivery status
    otp_session.delivery_status = delivery_result["status"]
    otp_session.delivery_attempts = delivery_result["attempts"]
    if delivery_result["error"]:
        otp_session.last_delivery_error = delivery_result["error"]

    event = Event(
        user_id=user.id,
        action="otp_sent",
        ip_address=request.client.host if request.client else "127.0.0.1",
        user_agent=request.headers.get("user-agent", "unknown"),
        metadata_json=json.dumps({
            "otp_session_id": otp_session.id,
            "delivery_status": delivery_result["status"],
            "delivery_attempts": delivery_result["attempts"],
            "delivery_error": delivery_result["error"],
        }),
    )
    db.add(event)
    db.commit()
    
    expires_in_seconds = max(0, int((otp_session.expires_at - datetime.utcnow()).total_seconds()))
    
    # In strict mode, fail if SMTP couldn't deliver
    if os.getenv("SMTP_STRICT_MODE", "0") == "1" and delivery_result["status"] == "failed":
        raise HTTPException(status_code=503, detail=f"OTP delivery failed: {delivery_result['error']}")
    
    return {
        "message": "OTP sent successfully",
        "expires_in_seconds": expires_in_seconds,
        "delivery_status": delivery_result["status"],
        "delivery_attempts": delivery_result["attempts"],
    }


@router.post("/otp/verify")
async def verify_otp(request: Request, db: Session = Depends(get_db)):
    """Verify OTP code and issue JWT token."""
    data = await _safe_read_json(request)
    otp_session_id = data.get("otp_session_id")
    otp_code = data.get("otp_code")
    
    if not otp_session_id or not otp_code:
        raise HTTPException(status_code=400, detail="Missing otp_session_id or otp_code")
    
    otp_session = db.query(OtpSession).filter(OtpSession.id == otp_session_id).first()
    
    if not otp_session:
        raise HTTPException(status_code=400, detail="Invalid OTP session")
    
    if otp_session.used:
        raise HTTPException(status_code=400, detail="OTP already used")
    
    if datetime.utcnow() > otp_session.expires_at:
        raise HTTPException(status_code=400, detail="OTP expired")
    
    if otp_session.otp_code != otp_code:
        raise HTTPException(status_code=400, detail="Invalid OTP code")
    
    # Mark OTP as used
    otp_session.used = True
    db.commit()
    
    # Get user and generate JWT
    user = db.query(User).filter(User.id == otp_session.user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    
    access_token = create_access_token(user)

    event = Event(
        user_id=user.id,
        action="otp_verified",
        ip_address=request.client.host if request.client else "127.0.0.1",
        user_agent=request.headers.get("user-agent", "unknown"),
        trust_score_at_time=user.trust_score,
        metadata_json=json.dumps({"otp_session_id": otp_session.id}),
    )
    db.add(event)
    db.commit()
    
    return {
        "token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "message": "Login successful"
    }
