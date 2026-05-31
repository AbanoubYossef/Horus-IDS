"""Predict + CSV upload endpoints."""

from typing import List

from fastapi import APIRouter, Depends, Request, UploadFile, File

from api.schemas import SingleFlowRequest
from api.dependencies import get_prediction_service, get_ws_manager, require_model
from application.services.prediction_service import PredictionService
from infrastructure.websocket.manager import ConnectionManager

router = APIRouter()


@router.post("/predict")
def predict(
    request: Request,
    req: SingleFlowRequest,
    service: PredictionService = Depends(get_prediction_service),
    ws: ConnectionManager = Depends(get_ws_manager),
    _=Depends(require_model),
):
    meta = {
        "src_ip": req.src_ip, "dst_ip": req.dst_ip,
        "src_port": req.src_port, "dst_port": req.dst_port,
        "protocol": req.protocol, "vlan_id": req.vlan_id,
        "src_vlan": req.src_vlan, "dst_vlan": req.dst_vlan,
    }
    result = service.predict_single(req.features_dict, meta)
    ws.broadcast_from_thread(result)
    return result


@router.post("/predict/batch")
def predict_batch(
    request: Request,
    reqs: List[SingleFlowRequest],
    service: PredictionService = Depends(get_prediction_service),
    ws: ConnectionManager = Depends(get_ws_manager),
    _=Depends(require_model),
):
    requests_data = [
        {
            "features_dict": r.features_dict,
            "src_ip": r.src_ip, "dst_ip": r.dst_ip,
            "src_port": r.src_port, "dst_port": r.dst_port,
            "protocol": r.protocol, "vlan_id": r.vlan_id,
            "src_vlan": r.src_vlan, "dst_vlan": r.dst_vlan,
        }
        for r in reqs
    ]
    result = service.predict_batch(requests_data)
    for r in result["results"]:
        ws.broadcast_from_thread(r)
    return result


@router.post("/upload/csv")
async def upload_csv(
    request: Request,
    file: UploadFile = File(...),
    service: PredictionService = Depends(get_prediction_service),
    _=Depends(require_model),
):
    content = await file.read()
    return service.upload_csv(file.filename, content)
