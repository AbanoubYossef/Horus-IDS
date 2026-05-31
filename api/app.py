"""App factory -- sets up the FastAPI instance."""

import asyncio
import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from domain.exceptions import DomainError
from api.error_handlers import domain_error_handler
from api.dependencies import (
    get_settings, get_ws_manager, get_prediction_repo,
    get_info_service,
)
from infrastructure.persistence.database import init_db

from api.routes.predict import router as predict_router
from api.routes.predictions import router as predictions_router
from api.routes.info import router as info_router
from api.routes.auth import router as auth_router
from api.routes.alerts import router as alerts_router
from api.routes.analytics import router as analytics_router
from api.routes.ai import router as ai_router
from api.routes.websocket import router as ws_router

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("horus-api")

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings = get_settings()
    ws = get_ws_manager()
    ws.set_event_loop(asyncio.get_event_loop())
    init_db(settings.db_path)
    info = get_info_service()
    info.index_csvs()
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="HORUS SOC -- Hierarchical 11-Class IDS",
        description="Network Intrusion Detection: 98.70% F1 on 1.6M unseen flows",
        version="5.0.0",
        lifespan=_lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_exception_handler(DomainError, domain_error_handler)

    @app.middleware("http")
    async def api_key_middleware(request: Request, call_next):
        skip_paths = ("/health", "/auth/")
        if settings.api_key and not any(request.url.path.startswith(p) for p in skip_paths):
            provided = request.headers.get("X-API-Key", "")
            if provided != settings.api_key:
                return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})
        return await call_next(request)

    app.include_router(predict_router)
    app.include_router(predictions_router)
    app.include_router(info_router)
    app.include_router(auth_router)
    app.include_router(alerts_router)
    app.include_router(analytics_router)
    app.include_router(ai_router)
    app.include_router(ws_router)

    return app


app = create_app()
