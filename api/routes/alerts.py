"""Alert CRUD endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, Query

from api.schemas import AlertCreateRequest, AlertUpdateRequest
from api.dependencies import get_alert_service, require_user
from application.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    user: dict = Depends(require_user),
    service: AlertService = Depends(get_alert_service),
):
    return service.list_alerts(limit, offset, status, severity)


@router.post("")
def create_alert(
    req: AlertCreateRequest,
    user: dict = Depends(require_user),
    service: AlertService = Depends(get_alert_service),
):
    return service.create_alert(
        req.title, req.description, req.severity,
        req.prediction_id, user["id"], user["username"],
    )


@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    user: dict = Depends(require_user),
    service: AlertService = Depends(get_alert_service),
):
    return service.get_alert(alert_id)


@router.put("/{alert_id}")
def update_alert(
    alert_id: str,
    req: AlertUpdateRequest,
    user: dict = Depends(require_user),
    service: AlertService = Depends(get_alert_service),
):
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    return service.update_alert(alert_id, updates)


@router.post("/generate")
def generate_alerts(
    user: dict = Depends(require_user),
    service: AlertService = Depends(get_alert_service),
):
    return service.generate_alerts(user["id"])


@router.delete("/{alert_id}")
def delete_alert(
    alert_id: str,
    user: dict = Depends(require_user),
    service: AlertService = Depends(get_alert_service),
):
    return service.delete_alert(alert_id)
