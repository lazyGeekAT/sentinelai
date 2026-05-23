from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel
import json

from database import get_db
from models import User, Event
from auth import get_current_user, require_admin

router = APIRouter()

class StatusUpdateRequest(BaseModel):
    status: str

@router.get("")
def get_users(
    status: Optional[str] = None,
    min_trust: Optional[int] = None,
    max_trust: Optional[int] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user),
    _admin: User = Depends(require_admin),
):
    query = db.query(User)
    
    if status:
        query = query.filter(User.status == status)
    if min_trust is not None:
        query = query.filter(User.trust_score >= min_trust)
    if max_trust is not None:
        query = query.filter(User.trust_score <= max_trust)
        
    total = query.count()
    users = query.offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "users": [
            {
                "user_id": u.id,
                "email": u.email,
                "trust_score": u.trust_score,
                "status": u.status,
                "registered_at": u.registered_at.isoformat() + "Z",
                "last_login_at": u.last_login_at.isoformat() + "Z" if u.last_login_at else None,
                "last_ip": u.last_ip,
                "flag_count": 0 # Placeholder for now
            }
            for u in users
        ]
    }

@router.get("/{user_id}")
def get_user(user_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), _admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    return {
        "user_id": user.id,
        "email": user.email,
        "trust_score": user.trust_score,
        "status": user.status,
        "registered_at": user.registered_at.isoformat() + "Z",
        "behavioral_snapshot": {
            "typing_variance_ms": user.typing_variance_ms,
            "time_to_complete_sec": user.time_to_complete_sec,
            "mouse_move_count": user.mouse_move_count,
            "keypress_count": user.keypress_count
        },
        "ml_anomaly_score": user.ml_anomaly_score,
        "flags": user.triggered_flags.split(",") if user.triggered_flags else []
    }

@router.get("/{user_id}/timeline")
def get_user_timeline(user_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), _admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    events = db.query(Event).filter(Event.user_id == user_id).order_by(Event.timestamp.desc()).all()
    
    return {
        "user_id": user_id,
        "user_email": user.email,
        "timeline": [
            {
                "event_id": e.id,
                "action": e.action,
                "action_type": e.action,
                "timestamp": e.timestamp.isoformat() + "Z",
                "ip_address": e.ip_address,
                "country": e.country,
                "user_agent": e.user_agent,
                "trust_score_at_time": e.trust_score_at_time,
                "description": _describe_event(e.action, e.metadata_json),
                "metadata": _parse_metadata(e.metadata_json),
            }
            for e in events
        ]
    }


def _parse_metadata(metadata_json: Optional[str]) -> dict:
    if not metadata_json:
        return {}
    try:
        parsed = json.loads(metadata_json)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _describe_event(action: str, metadata_json: Optional[str]) -> str:
    metadata = _parse_metadata(metadata_json)
    if action == "register":
        rules = metadata.get("triggered_rules") or []
        return "Registration completed" + (f"; triggered {', '.join(rules)}" if rules else "")
    if action == "login":
        recommendation = metadata.get("recommendation")
        return f"Login completed" + (f"; recommendation: {recommendation}" if recommendation else "")
    if action == "otp_sent":
        mode = metadata.get("delivery_mode")
        return f"OTP dispatched" + (f" via {mode}" if mode else "")
    if action == "otp_verified":
        return "OTP verified successfully"
    return action.replace("_", " ").title()

@router.patch("/{user_id}/status")
def update_user_status(user_id: str, req: StatusUpdateRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), _admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if req.status not in ["active", "quarantined", "blocked"]:
        raise HTTPException(status_code=400, detail="Invalid status")
        
    user.status = req.status
    db.commit()
    
    return {
        "user_id": user.id,
        "status": user.status,
        "message": "User status updated"
    }

