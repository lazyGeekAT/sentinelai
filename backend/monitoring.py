"""
Monitoring and metrics for SentinelAI.
Provides Prometheus metrics, performance tracking, and event alerting.
"""

from prometheus_client import Counter, Histogram
import logging

logger = logging.getLogger(__name__)

# === COUNTERS ===
# Track occurrences of events

# Authentication metrics
auth_registration_total = Counter(
    'sentinelai_auth_registration_total',
    'Total registration attempts',
    ['status']  # success, rate_limited, blocked
)

auth_login_total = Counter(
    'sentinelai_auth_login_total',
    'Total login attempts',
    ['status']  # success, failed, otp_required, quarantined
)

auth_otp_sent_total = Counter(
    'sentinelai_auth_otp_sent_total',
    'Total OTP codes sent',
    ['status']  # delivered, failed, console_fallback
)

auth_token_validation_failures = Counter(
    'sentinelai_auth_token_validation_failures_total',
    'Total JWT token validation failures',
    ['reason']  # expired, invalid, malformed
)

# Security metrics
security_rules_triggered = Counter(
    'sentinelai_security_rules_triggered_total',
    'Total security rules fired',
    ['rule_name']  # velocity_ip, email_pattern, geo_drift, etc.
)

security_alerts_created = Counter(
    'sentinelai_security_alerts_created_total',
    'Total security alerts created',
    ['alert_type']  # bot_wave, geo_drift, suspicious_behavior
)

api_requests_total = Counter(
    'sentinelai_api_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status_code']
)

api_errors_total = Counter(
    'sentinelai_api_errors_total',
    'Total API errors',
    ['endpoint', 'error_code']
)

# === HISTOGRAMS ===
# Track request latency and durations

api_request_duration = Histogram(
    'sentinelai_api_request_duration_seconds',
    'API request latency in seconds',
    ['method', 'endpoint'],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)

auth_registration_duration = Histogram(
    'sentinelai_auth_registration_duration_seconds',
    'Registration request duration in seconds',
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5)
)

password_hash_duration = Histogram(
    'sentinelai_password_hash_duration_seconds',
    'Password hashing duration in seconds',
    buckets=(0.05, 0.1, 0.2, 0.5, 1.0)
)

db_query_duration = Histogram(
    'sentinelai_db_query_duration_seconds',
    'Database query latency in seconds',
    ['query_type'],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5)
)

# === ALERT THRESHOLDS ===

class AlertThreshold:
    """Alert configuration and state."""
    
    # Failed auth attempts per minute to trigger alert
    FAILED_LOGIN_ATTEMPTS_THRESHOLD = 10
    
    # Bot wave detection: registrations per minute
    BOT_WAVE_REGISTRATIONS_THRESHOLD = 5
    
    # Geo drift detections per minute to escalate
    GEO_DRIFT_ALERTS_THRESHOLD = 3
    
    # API error rate (percentage) to trigger alert
    API_ERROR_RATE_THRESHOLD = 5  # %
    
    # Database query latency to trigger alert (seconds)
    DB_QUERY_LATENCY_THRESHOLD = 1.0




def record_request_timing(method: str, endpoint: str, duration: float, status_code: int):
    """Record API request metrics."""
    api_request_duration.labels(method=method, endpoint=endpoint).observe(duration)
    api_requests_total.labels(method=method, endpoint=endpoint, status_code=status_code).inc()


def record_error(endpoint: str, error_code: str):
    """Record API error."""
    api_errors_total.labels(endpoint=endpoint, error_code=error_code).inc()


def record_auth_event(event_type: str, status: str):
    """Record authentication event."""
    if event_type == 'registration':
        auth_registration_total.labels(status=status).inc()
    elif event_type == 'login':
        auth_login_total.labels(status=status).inc()


def record_security_rule(rule_name: str):
    """Record a security rule being triggered."""
    security_rules_triggered.labels(rule_name=rule_name).inc()


def record_alert(alert_type: str):
    """Record a security alert being created."""
    security_alerts_created.labels(alert_type=alert_type).inc()
