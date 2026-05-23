# SentinelAI — Trust Score Calculator
# Owner: Akash
# Branch: feature/security-engine
# Combines rules engine + behavioral signals + ML anomaly score into final trust score.
# Trust score formula (from docs/architecture.md):
#   trust_score = 100 - rule_penalty - behavioral_penalty - ml_penalty

from dataclasses import dataclass
from typing import List, Optional
from rules import run_registration_rules, run_login_rules, RulesEngineOutput


@dataclass
class BehavioralPayload:
    typing_variance_ms: float
    time_to_complete_sec: float
    mouse_move_count: int
    keypress_count: int
    session_tempo_sec: Optional[float] = None
    mouse_entropy_score: Optional[float] = None
    fill_order_score: Optional[float] = None


@dataclass
class ScoreResult:
    trust_score: int                  # Final 0-100 score
    rule_penalty: int
    behavioral_penalty: int
    ml_penalty: int
    triggered_rules: List[str]
    ml_anomaly_score: Optional[float]
    recommendation: str               # "allow" | "otp" | "captcha" | "quarantine"


def compute_behavioral_penalty(behavioral: BehavioralPayload) -> int:
    """
    Deduct points based on raw behavioral signals from the JS SDK.
    Max penalty: 25 points
    """
    penalty = 0

    # Too fast → likely bot
    if behavioral.time_to_complete_sec < 3:
        penalty += 15
    elif behavioral.time_to_complete_sec < 6:
        penalty += 5

    # No typing variance → uniform bot keypresses
    if behavioral.typing_variance_ms < 20:
        penalty += 10  # architecture.md: -10 pts
    elif behavioral.typing_variance_ms < 50:
        penalty += 3

    # No mouse movement → headless browser
    if behavioral.mouse_move_count == 0:
        penalty += 5  # architecture.md: -5 pts

    # Tempo too compressed or too uniform can indicate automation
    if behavioral.session_tempo_sec is not None and behavioral.session_tempo_sec < 2:
        penalty += 5
    elif behavioral.session_tempo_sec is not None and behavioral.session_tempo_sec < 5:
        penalty += 2

    # Low mouse entropy = linear robotic movement
    if behavioral.mouse_entropy_score is not None and behavioral.mouse_entropy_score < 0.2:
        penalty += 5
    elif behavioral.mouse_entropy_score is not None and behavioral.mouse_entropy_score < 0.45:
        penalty += 2

    # Odd field-fill ordering or repeated focus patterns
    if behavioral.fill_order_score is not None and behavioral.fill_order_score < 0.4:
        penalty += 5
    elif behavioral.fill_order_score is not None and behavioral.fill_order_score < 0.7:
        penalty += 2

    return min(penalty, 25)  # cap at 25


def compute_ml_penalty(anomaly_score: Optional[float]) -> int:
    """
    Convert Isolation Forest anomaly score to penalty.
    anomaly_score range: [-1, 0]
    -1 = strong anomaly, 0 = normal
    Max penalty: 15 points
    """
    if anomaly_score is None:
        return 0
    # abs(anomaly_score) is in [0,1], multiply by 15
    return min(int(abs(anomaly_score) * 15), 15)


def get_recommendation(trust_score: int) -> str:
    """
    Map trust score to an action recommendation.
    Thresholds should match .env values.
    """
    if trust_score >= 70:
        return "allow"
    elif trust_score >= 40:
        return "otp"
    elif trust_score >= 20:
        return "captcha"
    else:
        return "quarantine"


def score_registration(
    email: str,
    behavioral: BehavioralPayload,
    ip_address: str,
    user_agent: str,
    registrations_from_ip_last_hour: int,
    accounts_with_same_ua_today: int,
    ml_anomaly_score: Optional[float] = None,
    registrations_per_minute: int = 0,
) -> ScoreResult:
    """
    Full scoring pipeline for new user registration.
    Called by Atul's /api/register endpoint.

    registrations_per_minute — optional; if provided, enables the
    platform_velocity_spike rule (alert only, no individual penalty).
    """
    # Layer 1: Rules engine
    rules_output: RulesEngineOutput = run_registration_rules(
        email=email,
        time_to_complete_sec=behavioral.time_to_complete_sec,
        ip_address=ip_address,
        user_agent=user_agent,
        registrations_from_ip_last_hour=registrations_from_ip_last_hour,
        accounts_with_same_ua_today=accounts_with_same_ua_today,
        registrations_per_minute=registrations_per_minute,
    )

    # Layer 2: Behavioral signals
    behavioral_penalty = compute_behavioral_penalty(behavioral)

    # Layer 3: ML anomaly score
    ml_penalty = compute_ml_penalty(ml_anomaly_score)

    # Final score
    total_penalty = rules_output.total_penalty + behavioral_penalty + ml_penalty
    trust_score = max(0, min(100, 100 - total_penalty))

    return ScoreResult(
        trust_score=trust_score,
        rule_penalty=rules_output.total_penalty,
        behavioral_penalty=behavioral_penalty,
        ml_penalty=ml_penalty,
        triggered_rules=rules_output.triggered_rules,
        ml_anomaly_score=ml_anomaly_score,
        recommendation=get_recommendation(trust_score),
    )


def score_login(
    user_id: str,
    existing_trust_score: int,
    ip_address: str,
    current_country: str,
    last_country: Optional[str],
    minutes_since_last_login: Optional[float],
    ml_anomaly_score: Optional[float] = None,
) -> ScoreResult:
    """
    Full scoring pipeline for login events.
    Called by Atul's /api/login endpoint.
    Starts from the user's existing trust score rather than 100.
    """
    rules_output: RulesEngineOutput = run_login_rules(
        user_id=user_id,
        ip_address=ip_address,
        current_country=current_country,
        last_country=last_country,
        minutes_since_last_login=minutes_since_last_login,
    )

    ml_penalty = compute_ml_penalty(ml_anomaly_score)

    total_penalty = rules_output.total_penalty + ml_penalty
    trust_score = max(0, min(100, existing_trust_score - total_penalty))

    return ScoreResult(
        trust_score=trust_score,
        rule_penalty=rules_output.total_penalty,
        behavioral_penalty=0,
        ml_penalty=ml_penalty,
        triggered_rules=rules_output.triggered_rules,
        ml_anomaly_score=ml_anomaly_score,
        recommendation=get_recommendation(trust_score),
    )
