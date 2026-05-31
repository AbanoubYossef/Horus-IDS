"""Health check and misc info endpoints."""

from fastapi import APIRouter, Depends

from api.dependencies import get_info_service, get_history_service, require_model
from application.services.info_service import InfoService
from application.services.history_service import HistoryService

router = APIRouter()


@router.get("/health")
def health(service: InfoService = Depends(get_info_service)):
    return service.get_health()


@router.get("/classes")
def get_classes(
    service: InfoService = Depends(get_info_service),
    _=Depends(require_model),
):
    return service.get_classes()


@router.get("/features")
def get_features(
    service: InfoService = Depends(get_info_service),
    _=Depends(require_model),
):
    return service.get_features()


@router.get("/data/sample")
def data_sample(
    service: InfoService = Depends(get_info_service),
    _=Depends(require_model),
):
    return service.get_data_sample()


@router.get("/db/stats")
def db_stats(service: HistoryService = Depends(get_history_service)):
    return service.get_db_stats()
