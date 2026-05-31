"""Prediction history + stats."""

from typing import Optional

from fastapi import APIRouter, Depends, Query

from api.dependencies import get_history_service
from application.services.history_service import HistoryService

router = APIRouter()


@router.get("/predictions")
def get_predictions(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    attack_only: bool = False,
    service: HistoryService = Depends(get_history_service),
):
    return service.list_predictions(limit, offset, severity, attack_only)


@router.get("/predictions/stats")
def prediction_stats(
    window: Optional[str] = Query(None, pattern="^(1h|24h|7d|30d)$"),
    service: HistoryService = Depends(get_history_service),
):
    return service.get_stats(window)


@router.delete("/predictions/clear")
def clear_predictions(
    service: HistoryService = Depends(get_history_service),
):
    return service.clear()


@router.delete("/predictions/retain")
def retain_predictions(
    days: int = Query(30, ge=1, le=365),
    service: HistoryService = Depends(get_history_service),
):
    return service.retain(days)
