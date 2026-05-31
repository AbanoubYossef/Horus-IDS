"""Analytics endpoints: timeline, attack trends, severity distribution."""

from fastapi import APIRouter, Depends, Query

from api.dependencies import get_analytics_service, require_user
from application.services.analytics_service import AnalyticsService

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/timeline")
def timeline(
    period: str = Query("hour", pattern="^(hour|day)$"),
    days: int = Query(7, ge=1, le=90),
    user: dict = Depends(require_user),
    service: AnalyticsService = Depends(get_analytics_service),
):
    return service.get_timeline(period, days)


@router.get("/attack-trends")
def attack_trends(
    days: int = Query(7, ge=1, le=90),
    user: dict = Depends(require_user),
    service: AnalyticsService = Depends(get_analytics_service),
):
    return service.get_attack_trends(days)


@router.get("/severity-distribution")
def severity_distribution(
    days: int = Query(7, ge=1, le=90),
    user: dict = Depends(require_user),
    service: AnalyticsService = Depends(get_analytics_service),
):
    return service.get_severity_distribution(days)
