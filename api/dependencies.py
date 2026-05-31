"""DI wiring -- all the factory funcs live here."""

from functools import lru_cache
from pathlib import Path

from fastapi import Depends, Request

from infrastructure.config import Settings
from infrastructure.persistence.prediction_repository import SqlitePredictionRepository
from infrastructure.persistence.user_repository import SqliteUserRepository
from infrastructure.persistence.alert_repository import SqliteAlertRepository
from infrastructure.ml.model_gateway import HierarchicalModelGateway
from infrastructure.external.groq_client import GroqClient
from infrastructure.websocket.manager import ConnectionManager

from application.services.prediction_service import PredictionService
from application.services.history_service import HistoryService
from application.services.auth_service import AuthService
from application.services.alert_service import AlertService
from application.services.analytics_service import AnalyticsService
from application.services.ai_service import AiService
from application.services.info_service import InfoService

from data_utils import LABEL_MERGE, LABEL_MERGE_11CLASS, DATA_DIR


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_model_gateway() -> HierarchicalModelGateway:
    settings = get_settings()
    return HierarchicalModelGateway(settings.model_dir)


@lru_cache
def get_ws_manager() -> ConnectionManager:
    return ConnectionManager()


@lru_cache
def get_prediction_repo() -> SqlitePredictionRepository:
    settings = get_settings()
    return SqlitePredictionRepository(settings.db_path)


@lru_cache
def get_user_repo() -> SqliteUserRepository:
    settings = get_settings()
    return SqliteUserRepository(settings.db_path)


@lru_cache
def get_alert_repo() -> SqliteAlertRepository:
    settings = get_settings()
    return SqliteAlertRepository(settings.db_path)


@lru_cache
def get_groq_client() -> GroqClient:
    settings = get_settings()
    return GroqClient(
        api_key=settings.groq_api_key,
        api_url=settings.groq_api_url,
        model=settings.groq_model,
    )


def get_prediction_service(
    model: HierarchicalModelGateway = Depends(get_model_gateway),
    repo: SqlitePredictionRepository = Depends(get_prediction_repo),
    alert_repo: SqliteAlertRepository = Depends(get_alert_repo),
    prediction_repo: SqlitePredictionRepository = Depends(get_prediction_repo),
) -> PredictionService:
    alert_service = AlertService(alert_repo, prediction_repo)
    return PredictionService(model, repo, LABEL_MERGE, LABEL_MERGE_11CLASS, alert_service)


def get_history_service(
    repo: SqlitePredictionRepository = Depends(get_prediction_repo),
) -> HistoryService:
    return HistoryService(repo)


def get_auth_service(
    repo: SqliteUserRepository = Depends(get_user_repo),
) -> AuthService:
    return AuthService(repo)


def get_alert_service(
    alert_repo: SqliteAlertRepository = Depends(get_alert_repo),
    prediction_repo: SqlitePredictionRepository = Depends(get_prediction_repo),
) -> AlertService:
    return AlertService(alert_repo, prediction_repo)


def get_analytics_service(
    repo: SqlitePredictionRepository = Depends(get_prediction_repo),
) -> AnalyticsService:
    return AnalyticsService(repo)


def get_ai_service(
    groq: GroqClient = Depends(get_groq_client),
    repo: SqlitePredictionRepository = Depends(get_prediction_repo),
) -> AiService:
    return AiService(groq, repo)


@lru_cache
def get_info_service() -> InfoService:
    model = get_model_gateway()
    settings = get_settings()
    return InfoService(model, DATA_DIR, LABEL_MERGE, LABEL_MERGE_11CLASS)


def _extract_token(request: Request) -> str | None:
    token = request.cookies.get("session_token")
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    return token


def get_current_user(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
) -> dict | None:
    token = _extract_token(request)
    return auth.get_current_user(token)


def require_user(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
) -> dict:
    token = _extract_token(request)
    return auth.require_user(token)


def require_model(
    model: HierarchicalModelGateway = Depends(get_model_gateway),
):
    from domain.exceptions import ModelNotLoadedError
    if not model.is_loaded():
        raise ModelNotLoadedError("Model not loaded")
