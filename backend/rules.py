# SentinelAI — Security Rules Engine
# Owner: Akash
# Branch: feature/security-engine
#
# Each rule returns a RuleResult with a penalty and optional alert payload.
# All rules are independent — they do not call each other.
# Run all rules for a request via run_registration_rules() or run_login_rules().

from dataclasses import dataclass, field
from typing import List, Optional
import os
import re

# ---------------------------------------------------------------------------
# Disposable / temporary email domain blocklist
# Source: aggregated from public disposable-email-domains lists
# Can be extended via DISPOSABLE_DOMAINS_EXTRA env var (comma-separated)
# ---------------------------------------------------------------------------
_DISPOSABLE_CORE = {
    # Classic throwaway services
    "temp.com", "tempmail.com", "tempinbox.com", "tempr.email",
    "mailinator.com", "mailinator2.com",
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.biz", "guerrillamail.de", "guerrillamail.info",
    "throwam.com", "throwaway.email",
    "fakeinbox.com", "fakeinbox.net",
    "trashmail.com", "trashmail.net", "trashmail.me", "trashmail.at",
    "trashmail.io",
    "yopmail.com", "yopmail.fr",
    "getairmail.com",
    "dispostable.com",
    "sharklasers.com", "guerrillamailblock.com",
    "spam4.me", "spamgourmet.com", "spamgourmet.net",
    "maildrop.cc",
    "discard.email",
    "mailnull.com",
    "spamthisplease.com",
    "spamhereplease.com",
    "crap.la",
    "objectmail.com",
    "ownmail.net",
    "jetable.fr.nf", "jetable.net",
    "nospam.ze.tc",
    "hulapla.de",
    "wegwerfadresse.de",
    "sofort-mail.de",
}

_extra = os.getenv("DISPOSABLE_DOMAINS_EXTRA", "")
DISPOSABLE_DOMAINS = _DISPOSABLE_CORE | ({d.strip().lower() for d in _extra.split(",") if d.strip()} if _extra else set())

# ---------------------------------------------------------------------------
# Minimum time (seconds) a human is expected to take to fill a form
# ---------------------------------------------------------------------------
MIN_REGISTRATION_SECONDS = float(os.getenv("MIN_REGISTRATION_SECONDS", "3.0"))

# ---------------------------------------------------------------------------
# Platform-level registration velocity limit (signups per minute)
# ---------------------------------------------------------------------------
PLATFORM_VELOCITY_LIMIT = 10


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    rule_name: str
    triggered: bool
    penalty: int
    alert_type: Optional[str] = None
    alert_severity: Optional[str] = None
    alert_description: Optional[str] = None


@dataclass
class RulesEngineOutput:
    total_penalty: int = 0
    triggered_rules: List[str] = field(default_factory=list)
    alerts_to_create: List[RuleResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Individual rule implementations
# ---------------------------------------------------------------------------

def check_velocity_ip(ip_address: str, registrations_from_ip_last_hour: int) -> RuleResult:
    """
    Rule: More than 3 registrations from the same IP in the last hour → bot wave.

    Penalty: 25 points
    Alert:   bot_wave / critical
    """
    limit = 3
    triggered = registrations_from_ip_last_hour > limit
    return RuleResult(
        rule_name="velocity_ip",
        triggered=triggered,
        penalty=25 if triggered else 0,
        alert_type="bot_wave" if triggered else None,
        alert_severity="critical" if triggered else None,
        alert_description=(
            f"IP {ip_address} made {registrations_from_ip_last_hour} registrations "
            f"in the last hour (limit: {limit})"
            if triggered else None
        ),
    )


def check_email_pattern(email: str) -> RuleResult:
    """
    Rule: Sequential / auto-generated email names or disposable domains → flag.

    Patterns flagged:
      - Disposable domain (temp.com, mailinator.com, etc.)
      - Sequential username: user1, test99, bot3, fake7, temp5, admin2
      - Purely numeric local part: 123456@domain.com
      - Generic numeric suffix on any base: name123@domain.com (≥3 digits)

    Penalty: 20 points
    """
    try:
        local, domain = email.lower().rsplit("@", 1)
    except ValueError:
        # Malformed email — flag it
        return RuleResult(rule_name="email_pattern", triggered=True, penalty=20)

    is_disposable = domain in DISPOSABLE_DOMAINS

    # Sequential bot patterns
    sequential_patterns = [
        r'^(user|test|temp|fake|bot|admin|demo|sample|guest|anon)\d+$',  # user1, admin99
        r'^\d+$',                                                          # 123456
        r'^[a-z]{2,10}\d{3,}$',                                           # name1234
    ]
    is_sequential = any(re.match(p, local) for p in sequential_patterns)

    triggered = is_disposable or is_sequential
    return RuleResult(
        rule_name="email_pattern",
        triggered=triggered,
        penalty=20 if triggered else 0,
    )


def check_speed_bot(
    time_to_complete_sec: float,
    min_seconds: float = MIN_REGISTRATION_SECONDS,
) -> RuleResult:
    """
    Rule: Registration completed faster than a human can realistically type.

    Penalty: 20 points
    Alert:   speed_bot / high
    """
    triggered = time_to_complete_sec < min_seconds
    return RuleResult(
        rule_name="speed_bot",
        triggered=triggered,
        penalty=20 if triggered else 0,
        alert_type="speed_bot" if triggered else None,
        alert_severity="high" if triggered else None,
        alert_description=(
            f"Registration completed in {time_to_complete_sec:.2f}s "
            f"(minimum expected: {min_seconds}s)"
            if triggered else None
        ),
    )


def check_duplicate_device(user_agent: str, accounts_with_same_ua_today: int) -> RuleResult:
    """
    Rule: Same user-agent string seen on 3+ different accounts in 24 hours.
    Indicates a shared bot device / headless browser pool.

    Penalty: 15 points
    """
    triggered = accounts_with_same_ua_today >= 3
    return RuleResult(
        rule_name="duplicate_device",
        triggered=triggered,
        penalty=15 if triggered else 0,
        alert_type="duplicate_device" if triggered else None,
        alert_severity="medium" if triggered else None,
        alert_description=(
            f"User-agent '{user_agent[:60]}' used by {accounts_with_same_ua_today} "
            f"accounts today"
            if triggered else None
        ),
    )


def check_geo_drift(
    user_id: str,
    current_country: str,
    last_country: Optional[str],
    minutes_since_last_login: Optional[float],
    window_minutes: float = 120.0,
) -> RuleResult:
    """
    Rule: Same account logs in from a different country within the drift window (default 2h).
    Signals session hijacking, credential stuffing, or account sharing.

    Penalty: 30 points (applied to login trust score, not registration)
    Alert:   geo_drift / high
    """
    if last_country is None or minutes_since_last_login is None:
        return RuleResult(rule_name="geo_drift", triggered=False, penalty=0)

    country_changed = current_country.strip().lower() != last_country.strip().lower()
    within_window = minutes_since_last_login < window_minutes

    triggered = country_changed and within_window
    return RuleResult(
        rule_name="geo_drift",
        triggered=triggered,
        penalty=30 if triggered else 0,
        alert_type="geo_drift" if triggered else None,
        alert_severity="high" if triggered else None,
        alert_description=(
            f"User {user_id} logged in from {last_country}, then {current_country} "
            f"within {minutes_since_last_login:.0f} minutes"
            if triggered else None
        ),
    )


def check_platform_velocity_spike(
    registrations_per_minute: int,
    limit: int = PLATFORM_VELOCITY_LIMIT,
) -> RuleResult:
    """
    Rule: Platform-wide registration rate exceeds the spike threshold.
    This is a global alert — it does NOT penalise individual users.
    Used to populate Panel 4 (Registration Velocity Chart) on the admin dashboard.

    Penalty: 0 (platform alert only)
    Alert:   velocity_spike / high
    """
    triggered = registrations_per_minute > limit
    return RuleResult(
        rule_name="platform_velocity_spike",
        triggered=triggered,
        penalty=0,  # no individual user penalty — platform-level event only
        alert_type="velocity_spike" if triggered else None,
        alert_severity="high" if triggered else None,
        alert_description=(
            f"Platform registration rate: {registrations_per_minute}/min "
            f"(limit: {limit}/min)"
            if triggered else None
        ),
    )


# ---------------------------------------------------------------------------
# Aggregated runners — called by scorer.py
# ---------------------------------------------------------------------------

def run_registration_rules(
    email: str,
    time_to_complete_sec: float,
    ip_address: str,
    user_agent: str,
    registrations_from_ip_last_hour: int,
    accounts_with_same_ua_today: int,
    registrations_per_minute: int = 0,
) -> RulesEngineOutput:
    """
    Run all registration-time rules and aggregate the result.
    Called by scorer.py → score_registration().

    registrations_per_minute — optional; pass if computed by the DB query.
    """
    results = [
        check_velocity_ip(ip_address, registrations_from_ip_last_hour),
        check_email_pattern(email),
        check_speed_bot(time_to_complete_sec),
        check_duplicate_device(user_agent, accounts_with_same_ua_today),
    ]

    # Platform-level spike check (alert only, no individual penalty)
    if registrations_per_minute > 0:
        results.append(check_platform_velocity_spike(registrations_per_minute))

    output = RulesEngineOutput()
    for r in results:
        if r.triggered:
            output.total_penalty += r.penalty
            output.triggered_rules.append(r.rule_name)
            if r.alert_type:
                output.alerts_to_create.append(r)

    return output


def run_login_rules(
    user_id: str,
    ip_address: str,
    current_country: str,
    last_country: Optional[str],
    minutes_since_last_login: Optional[float],
) -> RulesEngineOutput:
    """
    Run all login-time rules and aggregate the result.
    Called by scorer.py → score_login().
    """
    results = [
        check_geo_drift(user_id, current_country, last_country, minutes_since_last_login),
    ]

    output = RulesEngineOutput()
    for r in results:
        if r.triggered:
            output.total_penalty += r.penalty
            output.triggered_rules.append(r.rule_name)
            if r.alert_type:
                output.alerts_to_create.append(r)

    return output
