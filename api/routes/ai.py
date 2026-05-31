"""AI chatbot endpoint."""

from fastapi import APIRouter, Depends

from api.schemas import ChatRequest
from api.dependencies import get_ai_service, require_user
from application.services.ai_service import AiService

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/chat")
async def ai_chat(
    req: ChatRequest,
    user: dict = Depends(require_user),
    service: AiService = Depends(get_ai_service),
):
    response_text = await service.chat(req.message, req.history)
    return {"response": response_text}
