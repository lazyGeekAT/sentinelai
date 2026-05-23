# Graph Report - .  (2026-05-23)

## Corpus Check
- Corpus is ~35,101 words - fits in a single context window. You may not need a graph.

## Summary
- 606 nodes · 1406 edges · 35 communities detected
- Extraction: 73% EXTRACTED · 27% INFERRED · 0% AMBIGUOUS · INFERRED: 384 edges (avg confidence: 0.6)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Auth & API Layer|Auth & API Layer]]
- [[_COMMUNITY_Core Framework & Middleware|Core Framework & Middleware]]
- [[_COMMUNITY_Scoring Pipeline & Tests|Scoring Pipeline & Tests]]
- [[_COMMUNITY_API Contract & Documentation|API Contract & Documentation]]
- [[_COMMUNITY_Rules Engine|Rules Engine]]
- [[_COMMUNITY_Security Audit Scripts|Security Audit Scripts]]
- [[_COMMUNITY_Registration & Simulation|Registration & Simulation]]
- [[_COMMUNITY_Behavioral Fingerprinting SDK|Behavioral Fingerprinting SDK]]
- [[_COMMUNITY_Test Suite Helpers|Test Suite Helpers]]
- [[_COMMUNITY_ML Model Pipeline|ML Model Pipeline]]
- [[_COMMUNITY_Database Layer|Database Layer]]
- [[_COMMUNITY_Metrics & Monitoring|Metrics & Monitoring]]
- [[_COMMUNITY_Hackathon Demo Script|Hackathon Demo Script]]
- [[_COMMUNITY_Attack Simulation|Attack Simulation]]
- [[_COMMUNITY_Frontend Auth & API Client|Frontend Auth & API Client]]
- [[_COMMUNITY_Team Planning & Collab|Team Planning & Collab]]
- [[_COMMUNITY_Dashboard Seed Script|Dashboard Seed Script]]
- [[_COMMUNITY_Alignment Fix Tests|Alignment Fix Tests]]
- [[_COMMUNITY_Focused Fix Tests|Focused Fix Tests]]
- [[_COMMUNITY_Logging Configuration|Logging Configuration]]
- [[_COMMUNITY_Varied Simulation|Varied Simulation]]
- [[_COMMUNITY_User Management API|User Management API]]
- [[_COMMUNITY_Geolocation Service|Geolocation Service]]
- [[_COMMUNITY_Training Data Generator|Training Data Generator]]
- [[_COMMUNITY_Analytics Endpoints|Analytics Endpoints]]
- [[_COMMUNITY_Obsolete Documentation|Obsolete Documentation]]
- [[_COMMUNITY_Alerts API|Alerts API]]
- [[_COMMUNITY_User Timeline Frontend|User Timeline Frontend]]
- [[_COMMUNITY_Dashboard Frontend|Dashboard Frontend]]
- [[_COMMUNITY_Test Package Init|Test Package Init]]
- [[_COMMUNITY_Event Actions Constants|Event Actions Constants]]
- [[_COMMUNITY_Project Conventions|Project Conventions]]
- [[_COMMUNITY_Speed Bot Rule|Speed Bot Rule]]
- [[_COMMUNITY_Duplicate Device Rule|Duplicate Device Rule]]
- [[_COMMUNITY_Platform Velocity Spike|Platform Velocity Spike]]

## God Nodes (most connected - your core abstractions)
1. `Event` - 55 edges
2. `User` - 54 edges
3. `Alert` - 51 edges
4. `OtpSession` - 45 edges
5. `BehavioralPayload` - 41 edges
6. `TestSuite` - 27 edges
7. `APIError` - 20 edges
8. `ErrorCode` - 19 edges
9. `login()` - 18 edges
10. `SecurityAudit` - 18 edges

## Surprising Connections (you probably didn't know these)
- `SentinelAI Platform` --semantically_similar_to--> `Layered Defense Architecture`  [INFERRED] [semantically similar]
  README.md → docs/architecture.md
- `Bot Wave Detection` --semantically_similar_to--> `Velocity (IP-based) Rule`  [INFERRED] [semantically similar]
  README.md → docs/architecture.md
- `Geospatial Drift Alert` --semantically_similar_to--> `Geospatial Drift Rule`  [INFERRED] [semantically similar]
  README.md → docs/architecture.md
- `Quarantine Mode` --semantically_similar_to--> `Rationale: Quarantine over Hard Ban`  [INFERRED] [semantically similar]
  README.md → docs/architecture.md
- `Git Workflow` --semantically_similar_to--> `Branch Strategy`  [INFERRED] [semantically similar]
  CONTRIBUTING.md → docs/PLAN.md

## Hyperedges (group relationships)
- **Trust Score Computation Pipeline** — readme_BehavioralFingerprinting, arch_VelocityRule, readme_MLAnomalyDetection, agents_TrustScoreFormula, readme_OTPAdaptiveAuth, readme_QuarantineMode [EXTRACTED 1.00]
- **Four Security Detection Layers** — readme_BehavioralFingerprinting, arch_VelocityRule, arch_EmailPatternRule, arch_SpeedBotRule, arch_DuplicateDeviceRule, readme_MLAnomalyDetection, readme_QuarantineMode [EXTRACTED 1.00]
- **Team Role Structure** — readme_Arindam, readme_Atul, readme_Akash, readme_Debarshi, readme_Parthiv, plan_TeamCollaboration, plan_BranchStrategy [EXTRACTED 1.00]

## Communities

### Community 0 - "Auth & API Layer"
Cohesion: 0.09
Nodes (75): ResolveAlertRequest, CaptchaChallengeResponse, CaptchaVerifyRequest, create_access_token(), _create_alerts(), _create_captcha_challenge(), _create_ml_alert(), _extract_ip() (+67 more)

### Community 1 - "Core Framework & Middleware"
Cohesion: 0.07
Nodes (44): BaseHTTPMiddleware, Enum, APIError, AuthenticationError, InternalError, NotFoundError, RateLimitError, Centralized error code definitions for SentinelAI. Provides structured error res (+36 more)

### Community 2 - "Scoring Pipeline & Tests"
Cohesion: 0.08
Nodes (37): Test SMTP delivery hardening and retry logic., Verify mailer module imports correctly., Verify OtpSession model has delivery tracking fields., Verify send_otp_email returns structured result dict., Verify SMTP env vars are documented in .env.example., _read_text(), _service_is_up(), TestLiveSmoke (+29 more)

### Community 3 - "API Contract & Documentation"
Cohesion: 0.06
Nodes (46): Alert Types List, Trust Score Formula, API Contract, Alerts Endpoints, Analytics Endpoints, POST /api/login, OTP Endpoints, POST /api/register (+38 more)

### Community 4 - "Rules Engine"
Cohesion: 0.14
Nodes (30): check_duplicate_device(), check_email_pattern(), check_geo_drift(), check_platform_velocity_spike(), check_speed_bot(), check_velocity_ip(), Rule: Sequential / auto-generated email names or disposable domains → flag., Rule: Registration completed faster than a human can realistically type.      Pe (+22 more)

### Community 5 - "Security Audit Scripts"
Cohesion: 0.14
Nodes (15): main(), Audit password hashing implementation., Audit SQL injection protection., Audit session and token management., Audit for error message leakage., Audit input validation., Audit for known vulnerabilities in dependencies., Audit logging for security events. (+7 more)

### Community 6 - "Registration & Simulation"
Cohesion: 0.13
Nodes (22): Batch registrations script: bots, borderline, benign — prints trust_score and re, register(), check_backend_health(), generate_behavioral_payload(), generate_random_email(), login_user(), Login a user and measure response time., Verify backend is running. (+14 more)

### Community 7 - "Behavioral Fingerprinting SDK"
Cohesion: 0.14
Nodes (17): _computeFillOrderScore(), _computeMouseEntropy(), _computeSessionTempo(), _computeVariance(), getPayload(), _onFocusIn(), _onKeydown(), _onMouseMove() (+9 more)

### Community 8 - "Test Suite Helpers"
Cohesion: 0.28
Nodes (2): main(), TestSuite

### Community 9 - "ML Model Pipeline"
Cohesion: 0.22
Nodes (13): build_feature_vector(), get_model(), load_model(), predict(), Build a numpy feature vector in the correct order for the model.     Call this b, Train the Isolation Forest on normal user data and save the model.     Run this, Load the saved model. Returns None if model file doesn't exist yet., Predict anomaly score for a single feature vector.     Returns a score in [-1, 0 (+5 more)

### Community 10 - "Database Layer"
Cohesion: 0.22
Nodes (12): build_engine(), get_db(), init_db(), is_sqlite_url(), main(), run_task(), clear_target(), copy_model_rows() (+4 more)

### Community 11 - "Metrics & Monitoring"
Cohesion: 0.17
Nodes (8): MetricsCollector, Centralized metrics collection and alerting., Register a callback to be called when an alert is triggered., Log an event for alerting and auditing., Execute alert callbacks., Check if failed login attempts exceed threshold., Check if registrations per minute indicate bot wave., Check for unusual geo drift patterns.

### Community 12 - "Hackathon Demo Script"
Cohesion: 0.26
Nodes (5): HackathonDemo, main(), Simulate credential stuffing, Rapid location  jumps, Execute a wave of attacks in parallel

### Community 13 - "Attack Simulation"
Cohesion: 0.5
Nodes (10): attack(), header(), info(), main(), SentinelAI -- Live Demo Attack Simulator Owner: Parthiv  Runs 3 attack scenarios, scenario_bot_wave(), scenario_geo_drift(), scenario_speed_bot() (+2 more)

### Community 14 - "Frontend Auth & API Client"
Cohesion: 0.27
Nodes (8): clearUserSession(), getAuthToken(), getUserId(), setAuthToken(), setUserSession(), App(), ProtectedRoute(), UserTimelineRoute()

### Community 15 - "Team Planning & Collab"
Cohesion: 0.3
Nodes (12): File Ownership Map, Git Workflow, Branch Strategy, Build Timeline, Coordination Tips for Tech Lead, Team Collaboration Plan, Akash (Security & ML), Arindam (Tech Lead) (+4 more)

### Community 16 - "Dashboard Seed Script"
Cohesion: 0.49
Nodes (9): delete_demo_rows(), demo_metadata(), hash_password(), main(), parse_args(), register_event_metadata(), seed_alerts(), seed_users() (+1 more)

### Community 17 - "Alignment Fix Tests"
Cohesion: 0.53
Nodes (9): cleanup_db(), main(), random_email(), test_bot_wave_spike_detection(), test_kpi_consistency(), test_polling_config(), test_progressive_auth_allow(), test_progressive_auth_otp() (+1 more)

### Community 18 - "Focused Fix Tests"
Cohesion: 0.58
Nodes (8): cleanup_db(), main(), random_email(), test_1_progressive_auth_recommendation_logic(), test_2_bot_wave_spike_wiring(), test_3_bot_wave_alert_mapping(), test_4_polling_interval_config(), test_5_endpoint_signature_changes()

### Community 19 - "Logging Configuration"
Cohesion: 0.29
Nodes (7): get_logger(), Structured logging configuration for SentinelAI. Provides JSON-formatted logs fo, Custom JSON formatter that adds context to log records., Configure structured JSON logging for SentinelAI.          Args:         log_lev, Get a structured logger instance., SentinelAIFormatter, setup_logging()

### Community 20 - "Varied Simulation"
Cohesion: 0.53
Nodes (8): bot_wave(), credential_stuffing(), generate_errors(), geodrift_test(), login(), main(), mixed_registrations(), register()

### Community 21 - "User Management API"
Cohesion: 0.47
Nodes (7): _describe_event(), get_user(), get_user_timeline(), get_users(), _parse_metadata(), StatusUpdateRequest, update_user_status()

### Community 22 - "Geolocation Service"
Cohesion: 0.46
Nodes (6): GeoLocation, get_country(), get_location(), is_private_ip(), Get geographic location for an IP address.     Returns a mock location for priva, Convenience method — returns just the country name string.     Returns "Unknown"

### Community 23 - "Training Data Generator"
Cohesion: 0.43
Nodes (6): generate_benign(), generate_malicious(), main(), SentinelAI — ML Training Data Generator Owner: Parthiv (in coordination with Aka, Simulate real human users registering on a platform.     High variance in behavi, Simulate bots and malicious registrations.     Tight, uniform, inhuman distribut

### Community 24 - "Analytics Endpoints"
Cohesion: 0.6
Nodes (3): get_summary(), trust_dist(), velocity()

### Community 25 - "Obsolete Documentation"
Cohesion: 0.4
Nodes (5): Obsolete Documentation, Connection Pool Stress Test, SQLite-to-Postgres Migration, Smoke Tests (Register/Login), Test Summary & Results

### Community 26 - "Alerts API"
Cohesion: 0.67
Nodes (2): get_alerts(), resolve_alert()

### Community 27 - "User Timeline Frontend"
Cohesion: 0.67
Nodes (2): formatActionLabel(), UserTimeline()

### Community 28 - "Dashboard Frontend"
Cohesion: 0.67
Nodes (2): Dashboard(), KPICard()

### Community 29 - "Test Package Init"
Cohesion: 0.67
Nodes (1): SentinelAI project test suite package.

### Community 44 - "Event Actions Constants"
Cohesion: 1.0
Nodes (1): Event Actions List

### Community 45 - "Project Conventions"
Cohesion: 1.0
Nodes (1): Project Conventions

### Community 46 - "Speed Bot Rule"
Cohesion: 1.0
Nodes (1): Speed Bot Rule

### Community 47 - "Duplicate Device Rule"
Cohesion: 1.0
Nodes (1): Duplicate Device Rule

### Community 48 - "Platform Velocity Spike"
Cohesion: 1.0
Nodes (1): Platform Velocity Spike Rule

## Ambiguous Edges - Review These
- `Test Summary & Results` → `Obsolete Documentation`  [AMBIGUOUS]
  docs/obsolete/ · relation: references

## Knowledge Gaps
- **98 isolated node(s):** `Build a numpy feature vector in the correct order for the model.     Call this b`, `Train the Isolation Forest on normal user data and save the model.     Run this`, `Load the saved model. Returns None if model file doesn't exist yet.`, `Predict anomaly score for a single feature vector.     Returns a score in [-1, 0`, `Hash password using bcrypt (secure, slow hash function resistant to brute force)` (+93 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Test Suite Helpers`** (24 nodes): `main()`, `TestSuite`, `.error()`, `.generate_behavioral_payload()`, `.get_admin_token()`, `.get_alerts()`, `.header()`, `.info()`, `.__init__()`, `.login_user()`, `.print_report()`, `.register_user()`, `.reset_database()`, `.success()`, `.test_bot_wave()`, `.test_coordinated_logins()`, `.test_credential_stuffing()`, `.test_geodrift()`, `.test_mixed_attack()`, `.test_quarantine_lifecycle()`, `.wait_for_alerts()`, `.warn()`, `comprehensive_security_test.py`, `comprehensive_security_test.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Alerts API`** (4 nodes): `get_alerts()`, `resolve_alert()`, `alerts.py`, `alerts.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `User Timeline Frontend`** (4 nodes): `UserTimeline.jsx`, `UserTimeline.jsx`, `formatActionLabel()`, `UserTimeline()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Dashboard Frontend`** (4 nodes): `Dashboard()`, `KPICard()`, `Dashboard.jsx`, `Dashboard.jsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Test Package Init`** (3 nodes): `__init__.py`, `SentinelAI project test suite package.`, `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Event Actions Constants`** (1 nodes): `Event Actions List`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Project Conventions`** (1 nodes): `Project Conventions`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Speed Bot Rule`** (1 nodes): `Speed Bot Rule`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Duplicate Device Rule`** (1 nodes): `Duplicate Device Rule`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Platform Velocity Spike`** (1 nodes): `Platform Velocity Spike Rule`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Test Summary & Results` and `Obsolete Documentation`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **Why does `login()` connect `Auth & API Layer` to `Scoring Pipeline & Tests`, `Geolocation Service`, `Registration & Simulation`?**
  _High betweenness centrality (0.111) - this node is a cross-community bridge._
- **Why does `send_otp_email()` connect `Behavioral Fingerprinting SDK` to `Auth & API Layer`, `Scoring Pipeline & Tests`, `Registration & Simulation`, `Test Suite Helpers`, `Attack Simulation`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Why does `BehavioralPayload` connect `Scoring Pipeline & Tests` to `Auth & API Layer`, `ML Model Pipeline`?**
  _High betweenness centrality (0.073) - this node is a cross-community bridge._
- **Are the 52 inferred relationships involving `Event` (e.g. with `TokenResponse` and `CaptchaVerifyRequest`) actually correct?**
  _`Event` has 52 INFERRED edges - model-reasoned connections that need verification._
- **Are the 51 inferred relationships involving `User` (e.g. with `TokenResponse` and `CaptchaVerifyRequest`) actually correct?**
  _`User` has 51 INFERRED edges - model-reasoned connections that need verification._
- **Are the 48 inferred relationships involving `Alert` (e.g. with `TokenResponse` and `CaptchaVerifyRequest`) actually correct?**
  _`Alert` has 48 INFERRED edges - model-reasoned connections that need verification._