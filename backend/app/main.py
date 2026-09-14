from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# Main FastAPI application.
app = FastAPI(
    title="Situation Monitor API",
    description="Backend API for the real-time situational awareness platform.",
    version="0.1.0",
)


# During development the React frontend runs on port 5173
# while FastAPI runs on port 8000.
#
# Browsers normally block requests between different origins,
# so CORS explicitly allows our frontend to call the backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    """
    Simple root endpoint.

    This confirms that the API itself is reachable.
    """
    return {
        "service": "Situation Monitor API",
        "version": "0.1.0",
    }


@app.get("/api/health")
def health_check():
    """
    Health endpoint.

    Later this endpoint will also check PostgreSQL,
    Redis, collector status, and other dependencies.
    """
    return {
        "status": "healthy",
        "api": True,
        "database": "not_checked_yet",
        "redis": "not_checked_yet",
    }