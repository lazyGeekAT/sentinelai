# SentinelAI — Agent Instructions

## Quick start

```bash
# Backend (port 9000) — uses ./venv (not .venv)
cd backend && ../venv/bin/pip install -r ../requirements.txt && ../venv/bin/uvicorn main:app --reload --port 9000

# Frontend (port 3000)
cd frontend && npm install && npm run dev

# Tests (run from repo root)
./venv/bin/python tests/project_suite.py

# Demo: seed users, then simulate attack
./venv/bin/python scripts/seed_normal_users.py && ./venv/bin/python scripts/simulate_attack.py

# Monitoring stack (Prometheus:9090, Grafana:3001, Postgres:5432)
docker compose -f docker-compose.monitoring.yml up -d
```

## Architecture

- **Backend:** FastAPI at `backend/main.py`. Loads `.env` from repo root (not `backend/`). Middleware order (last→first): CORS, TrustedHost, RequestTiming, SecurityHeaders.
- **Frontend:** React + Vite + Tailwind. Dev server on port 3000. API base from `VITE_API_BASE_URL` env (default `http://localhost:9000/api`).
- **DB:** SQLite by default (`./sentinel.db`). Postgres via docker-compose (`DATABASE_URL=postgresql+psycopg2://sentinelai:sentinelai@127.0.0.1:5432/sentinelai`). Tables auto-created on startup.
- **Trust score:** `100 - rule_penalty (0-60) - behavioral_penalty (0-25) - ml_penalty (0-15)`. Bands: >70 direct, 40-70 OTP, 20-39 OTP+CAPTCHA, <20 quarantined.

## Key quirks

- Behavioral payload accepted as either `behavioralData` or `behavioral` key
- IP resolution: `X-Forwarded-For` header → `payload.ip_address` → `request.client.host`
- User-Agent: real HTTP header → `payload.user_agent` → `"unknown"`
- `ALLOWED_HOSTS` env var is comma-separated; `FRONTEND_URL` is single URL
- Rate limits: 5 reg/min/IP, 10 login/min/IP (`slowapi`)
- Rate limiter key defaults to `get_remote_address` — may need adjustment behind proxies
- JWT: HS256, 24h expiry, stored in `localStorage` under `sentinelai_token`
- Geo: ip-api.com (free, no key). `127.0.0.1` mocked to `GEO_LOCAL_MOCK_COUNTRY` (default India)
- SMTP: Gmail app password only; `SMTP_STRICT_MODE=1` fails hard on delivery errors
- ML model: `backend/ml_model.pkl` (joblib). Retrain: `python scripts/generate_training_data.py && python backend/ml_model.py --train`
- Scikit-learn pinned to `1.5.0` — upgrading may break the pickled model

## Test suite

- Single file: `tests/project_suite.py` (unittest). Run from repo root.
- Live smoke tests skip gracefully if backend/frontend are down
- No pytest, no tox, no CI config

## Conventions

- SQLAlchemy models use UUID strings as PKs (`models.new_id()`)
- bcrypt: 12 rounds
- Alert types: `bot_wave`, `geo_drift`, `speed_bot`, `email_pattern`, `duplicate_device`, `velocity_spike`
- Event actions: `register`, `login`, `login_failed`, `otp_sent`, `otp_verified`, `captcha_verified`, `quarantined`, `unquarantined`, `blocked`, `geo_drift`
- Frontend: no TypeScript, plain JSX. CSS via Tailwind utility classes.

## What's NOT here

- No pre-commit hooks, linter config (README mentions eslint in package.json but no `.eslintrc`)
- No CI/CD workflows (README describes desired setup, nothing is implemented)
- No Dockerfile for backend (README mentions one, none exists)
- No Alembic migrations (table creation is auto via `Base.metadata.create_all`)
