"""Backward-compat entry point for uvicorn api:app."""

from api.app import app, limiter  # noqa: F401
