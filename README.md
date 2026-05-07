# 🛡️ SentinelAI

> **Behavioral Intelligence Platform for Campus Event Ecosystems**  
> Built for ECLearnix & All College Event — Hackathon Submission, Domain 5: Cyber Security & Forensic Science

---

## 🧠 What Is SentinelAI?

SentinelAI is an AI-powered security platform that detects fake users, bot activity, and suspicious behavior on campus event platforms — not through simple rules alone, but through **behavioral fingerprinting and a continuous trust score system**.

Every user gets a **Trust Score (0–100)** that updates in real time based on:
- How they fill forms (typing cadence, time-on-form)
- Where they log in from (geospatial drift detection)
- How fast they act (velocity analysis)
- What patterns their account matches (email pattern, device fingerprint)
- What the ML anomaly model thinks of their behavior

---

## 🔒 Security Features

| # | Feature | Description |
|---|---|---|
| 1 | **Behavioral Fingerprinting** | Tracks typing variance, mouse entropy, form-fill speed |
| 2 | **Trust Score Engine** | Continuous 0–100 score, drives adaptive auth decisions |
| 3 | **Bot Wave Detection** | Flags mass registrations in short time windows |
| 4 | **Geospatial Drift Alert** | Alerts when same account logs in from 2 countries in <2 hrs |
| 5 | **Email Pattern Analysis** | Detects sequential/disposable email patterns |
| 6 | **OTP Adaptive Auth** | OTP triggered only when trust score drops below threshold |
| 7 | **Quarantine Mode** | Suspicious users are rate-limited + monitored, not hard-banned |
| 8 | **ML Anomaly Detection** | Isolation Forest trained on behavioral feature vectors |

---

## 👥 Team

| Member | Role |
|---|---|
| **Arindam** | Tech Lead & Architect |
| **Atul** | Backend Engineer (FastAPI, Auth, DB) |
| **Akash** | Security Logic & ML Engineer |
| **Debarshi** | Frontend & Dashboard Engineer |
| **Parthiv** | DevOps, Scripts & Documentation |

---

## 🏗️ Architecture

```mermaid
graph TD
    A["👤 USER LAYER<br/>Registration → Login → Event Actions<br/><i>(Behavioral JS SDK captures signals)</i>"]
    
    B["🧠 SENTINELAI CORE<br/>FastAPI Backend"]
    
    C["📊 Behavioral Collector"]
    D["⚡ Rules Engine<br/>Fast Rules"]
    E["🤖 ML Scorer<br/>Trust Score 0-100"]
    F["💾 PostgreSQL Event Store (local Postgres for dev)"]
    P["📡 Prometheus\n(scrapes /metrics)"]
    Q["📈 Grafana\n(dashboards & alerts)"]
    L["🧾 Logging/Tracing\n(Sentry / ELK / Datadog)"]
    
    G["📈 ADMIN DASHBOARD<br/>React + Vite<br/>Live Threat Feed · Trust Map · User Forensics"]
    
    A -->|Sends Events| B
    B --> C
    C -->|Processes| D
    D -->|Calculates| E
    C -->|Logs| F
    D -->|Logs| F
    E -->|Logs| F
    E -->|Trust Insights| G
    F -->|Historical Data| G
    B -->|exposes `/metrics`| P
    B -->|emits logs & traces (http, structured)| L
    P -->|visualized & alerted| Q
    L -->|visualized| Q
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- A Gmail account (for OTP)

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/sentinelai.git
cd sentinelai
```

### 2. Set up environment variables
```bash
cp .env.example .env
# Example: point the backend to a local Postgres instance (optional)
# DATABASE_URL=postgresql+psycopg2://sentinelai:sentinelai@127.0.0.1:5432/sentinelai
# Fill in your values — see .env.example for details
```

### 3. Start a local Postgres (recommended for dev)
Run the monitoring compose which also contains a Postgres service used by local development:
```bash
docker compose -f docker-compose.monitoring.yml up -d postgres
# or, start the full monitoring stack (Prometheus + Grafana + Postgres)
docker compose -f docker-compose.monitoring.yml up -d
```

Then start the backend (ensure `DATABASE_URL` points to Postgres if you started it):
```bash
cd backend
pip install -r requirements.txt
# Example: export DATABASE_URL='postgresql+psycopg2://sentinelai:sentinelai@127.0.0.1:5432/sentinelai'
uvicorn main:app --reload --port 9000
```

### 4. Start the frontend
```bash
cd frontend
npm install
npm run dev
# Opens at http://localhost:3000
```

### 5. Seed the database with demo users
```bash
cd scripts
python seed_normal_users.py
```

### 6. Run the attack simulation (for demo)
```bash
python simulate_attack.py
# Watch the admin dashboard react in real time
```

---

## 🔗 Key URLs (local dev)

| Service | URL |
|---|---|
| Backend API | http://localhost:9000 |
| API Docs (Swagger) | http://localhost:9000/docs |
| Admin Dashboard | http://localhost:3000/admin |
| User Login | http://localhost:3000/login |

---

## 📁 Project Structure

```
sentinelai/
├── backend/
│   ├── main.py           # FastAPI app entrypoint
│   ├── auth.py           # JWT + OTP logic
│   ├── models.py         # DB table definitions (SQLAlchemy) — works with SQLite or PostgreSQL
│   ├── database.py       # DB connection + helpers
│   ├── rules.py          # Security rules engine
│   ├── scorer.py         # Trust score calculator
│   ├── ml_model.py       # Isolation Forest model
│   └── geo.py            # IP geolocation wrapper
├── frontend/
│   └── src/
│       ├── dashboard/    # Admin dashboard panels
│       ├── auth/         # Login + Register pages
│       └── sdk/
│           └── behavioral.js  # Behavioral signal collector
├── scripts/
│   ├── seed_normal_users.py      # Populate DB with benign users
│   ├── simulate_attack.py        # Live demo attack scenarios
│   └── generate_training_data.py # Generate ML training CSV
├── docs/
│   └── architecture.md   # Detailed system design
├── .env.example
├── requirements.txt
├── API.md                # Full API contract
└── README.md
```

---

## 📋 Git Workflow

1. **Fork** this repository
2. **Clone** your fork locally
3. Create your feature branch: `git checkout -b feature/your-assigned-branch`
4. Commit your work: `git commit -m "feat: description of what you built"`
5. Push to your fork: `git push origin feature/your-assigned-branch`
6. Open a **Pull Request** to `main` — tag Arindam as reviewer
7. Wait for review + approval before merging

**Branch assignments:**
- `feature/backend-core` → Atul
- `feature/security-engine` → Akash
- `feature/admin-dashboard` → Debarshi
- `feature/scripts-and-docs` → Parthiv

---

## 🧪 Running Tests

```bash
cd backend
python test_scorer.py        # Tests trust score pipeline
python test_rules.py         # Tests rules engine with sample inputs
```

---

## 🧪 Demo Data and Local Monitoring

Seed the dashboard with users across active, quarantined, and blocked states:

```bash
python scripts/seed_demo_dashboard.py --reset
```

Run Prometheus and Grafana locally:

```bash
docker compose -f docker-compose.monitoring.yml up -d
```

Local URLs:

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001
- Grafana login: `admin` / `admin`
- Backend metrics target: `http://host.docker.internal:9000/metrics`

Test summary: see [docs/TEST_SUMMARY.md](docs/TEST_SUMMARY.md)

## Monitoring & Logging Integrations

SentinelAI emits Prometheus-format metrics on `/metrics` and structured logs/traces from the FastAPI backend. For production and advanced observability you can integrate one or more of the following:

- **Prometheus + Grafana (local / short-term):** recommended for metrics. Prometheus scrapes `http://<host>:9000/metrics`. Use the included Grafana JSON at `docs/grafana/sentinelai_overview_dashboard.json` to import panels.

- **Sentry (errors & performance tracing):** set `SENTRY_DSN` in your environment and initialize SDK in `backend/main.py`:

```py
import sentry_sdk
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware

sentry_sdk.init(dsn=os.getenv('SENTRY_DSN'), traces_sample_rate=0.1)
app.add_middleware(SentryAsgiMiddleware)
```

- **Datadog (metrics, traces, logs):** set `DATADOG_AGENT_HOST` and `DD_ENV`, and use the `datadog` Python client or `ddtrace` for APM. For containerized setups, configure the agent to receive traces and metrics.

- **ELK (Elasticsearch / Logstash / Kibana):** send structured JSON logs to Logstash or use filebeat to ship logs to Elasticsearch. Ensure logs are JSON-formatted for better parsability (use Python `structlog` or `logging` JSON formatter).

Environment examples (add to `.env`):

```
SENTRY_DSN=
DATADOG_AGENT_HOST=127.0.0.1
ELK_URL=http://elk-host:9200
```

## Integrations

Short integration notes for common tooling:

- **Sentry:** capture exceptions & performance traces. Configure `SENTRY_DSN` and set appropriate sampling for production.
- **Datadog:** install `ddtrace` and configure `DD_SERVICE` / `DD_ENV`. Use the DogStatsD client to push custom metrics from `scorer.py` and `rules.py`.
- **ELK:** use structured logs and ship via Filebeat or Logstash. Kibana dashboards can complement Grafana dashboards for log-centric investigations.


---

## 📄 License

## 🔁 Pipeline & CI/CD

This repository includes a minimal, practical CI/CD and local pipeline designed to make development, testing, and demos repeatable.

- **CI (GitHub Actions recommended):** run linting, unit tests, and security checks on every PR. Build matrix should include Python 3.10+ and node for frontend checks.
- **Build steps:** install Python deps (`pip install -r requirements.txt`), run backend unit tests, run frontend lint/build checks (`npm ci && npm run build`), and run integration smoke tests (`scripts/hackathon_demo.py` or targeted smoke scripts).
- **Container images:** Dockerfile present for backend (use `docker build -t sentinelai/backend:dev .`) and `docker compose -f docker-compose.monitoring.yml` for local monitoring + Postgres during dev.
- **Migrations & data:** Use `scripts/migrate_sqlite_to_postgres.py` for one-time migrations; prefer Alembic for schema evolution in CI/CD pipelines going forward.
- **Release:** CI should tag a release and push a Docker image to your registry. Deploy jobs can run a deploy script (e.g., Helm or simple `docker compose` on the target host).
- **Observability in pipeline:** CI artifacts include test reports and metrics snapshots; optionally publish Prometheus/Grafana exports for demo runs.

Keep this section short and link to any repo-specific CI workflows you add (e.g., `.github/workflows/ci.yml`).

MIT — Built for educational/hackathon purposes.
