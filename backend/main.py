from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import os
from dotenv import load_dotenv
from pathlib import Path
import time
import logging
import auth
import users
import alerts
import analytics
import scoring
from ml_model import load_model as load_ml_model
from database import init_db
from logging_config import setup_logging, get_logger
from error_codes import APIError, ValidationError, InternalError
from monitoring import record_request_timing, record_error
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

ROOT = Path(__file__).resolve().parents[1]
# Load the canonical project `.env` at the repository root
load_dotenv(ROOT / '.env')

# Setup structured logging
setup_logging()
logger = get_logger(__name__)

# Initialize DB
init_db()

app = FastAPI(
    title="SentinelAI",
    description="Behavioral Intelligence Platform for Campus Event Ecosystems",
    version="1.0.0"
)

from database import engine
import models

models.Base.metadata.create_all(bind=engine)

# --- Request Timing Middleware (for metrics) ---
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class RequestTimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        try:
            response = await call_next(request)
        except Exception as e:
            duration = time.time() - start_time
            record_timing(
                method=request.method,
                endpoint=request.url.path,
                duration=duration,
                status_code=500
            )
            record_error(endpoint=request.url.path, error_code="UNHANDLED_EXCEPTION")
            raise
        
        duration = time.time() - start_time
        record_request_timing(
            method=request.method,
            endpoint=request.url.path,
            duration=duration,
            status_code=response.status_code
        )
        # Record API errors for non-exception responses (4xx/5xx)
        try:
            if getattr(response, 'status_code', 0) >= 400:
                # use status code as error_code label
                record_error(endpoint=request.url.path, error_code=str(response.status_code))
        except Exception:
            # Metric recording must not interrupt response
            logger.debug('Failed to record api error metric for %s', request.url.path)
        return response


def record_timing(method: str, endpoint: str, duration: float, status_code: int):
    """Helper to record request timing metrics."""
    record_request_timing(method, endpoint, duration, status_code)


# --- Security Headers Middleware ---
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        # Prevent clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Enforce HTTPS (set max-age to 1 year)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Set SameSite cookies for CSRF protection
        response.headers["Set-Cookie"] = "SameSite=Strict"
        return response

# Add middlewares in reverse order (first added = last executed)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestTimingMiddleware)

# --- Trusted Host Middleware (prevents Host header injection) ---
extra_allowed_hosts = [
    host.strip()
    for host in os.getenv("ALLOWED_HOSTS", "").split(",")
    if host.strip()
]
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.localhost", *extra_allowed_hosts],
)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:5173"), "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Route Imports ---
app.include_router(auth.router, prefix="/api", tags=["Auth & Core"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(analytics.router, prefix="/api/analytics", tags=["Analytics"])
app.include_router(scoring.router, prefix="/api/score", tags=["Scoring"])


# --- Global Error Handlers ---
@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError):
    """Handle structured API errors."""
    record_error(endpoint=request.url.path, error_code=exc.code.value)
    logger.warning(
        f"API Error: {exc.code.value}",
        extra={"error_code": exc.code.value, "message": exc.message}
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_response()
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors."""
    record_error(endpoint=request.url.path, error_code="VALIDATION_ERROR")
    logger.warning(f"Validation error on {request.url.path}", extra={"errors": exc.errors()})
    
    error = ValidationError(
        message="Request validation failed",
        details={"errors": [
            {"field": str(e.get("loc", [])[-1]), "type": e.get("type")}
            for e in exc.errors()
        ]}
    )
    return JSONResponse(
        status_code=400,
        content=error.to_response()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    record_error(endpoint=request.url.path, error_code="INTERNAL_ERROR")
    logger.exception(
        f"Unhandled exception on {request.url.path}",
        extra={"error_type": type(exc).__name__}
    )
    
    error = InternalError(
        message="An unexpected error occurred"
    )
    return JSONResponse(
        status_code=500,
        content=error.to_response()
    )


# --- Monitoring Endpoints ---
@app.get("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


# --- Health & Info Endpoints ---
@app.get("/")
def root():
    return {
        "service": "SentinelAI",
        "status": "running",
        "docs": "/docs",
        "metrics": "/metrics"
    }


@app.get("/health")
def health():
    """Liveness probe."""
    return {"status": "ok"}


@app.on_event("startup")
async def startup_event():
    """Log application startup and preload ML model."""
    ml = load_ml_model()
    if ml is not None:
        logger.info("ML model loaded on startup")
    else:
        logger.warning("ML model not found — predictions will return neutral scores")
    logger.info(
        "SentinelAI backend started",
        extra={"version": "1.0.0", "environment": os.getenv("ENV", "development")}
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Log application shutdown."""
    logger.info("SentinelAI backend shutting down")
