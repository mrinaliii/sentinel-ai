"""
Chat (Analyst Copilot) API Router  —  /api/v1/chat
====================================================
Provides both REST (request/response) and WebSocket (streaming) interfaces
for the LangChain-powered analyst copilot.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Path, WebSocket, WebSocketDisconnect, status

from app.core.logging import get_logger
from app.core.security import AnalystRequired, TokenPayload, decode_token
from app.models.common import ChatRequest, ChatResponse, SuccessResponse
from app.services.chat_service import ChatService

logger = get_logger(__name__)
router = APIRouter(prefix="/chat", tags=["Analyst Copilot"])


def get_chat_service() -> ChatService:
    return ChatService()


@router.post(
    "/message",
    response_model=SuccessResponse[ChatResponse],
    summary="Send message to analyst copilot",
    description=(
        "Sends a message to the LangChain SOC agent and returns a complete response. "
        "For streaming token-by-token output, use the WebSocket endpoint instead."
    ),
)
async def send_message(
    payload: ChatRequest,
    token: TokenPayload = AnalystRequired,
    svc: ChatService = Depends(get_chat_service),
) -> SuccessResponse[ChatResponse]:
    session_id = payload.session_id or str(uuid.uuid4())
    response = await svc.process_message(
        session_id=session_id,
        message=payload.message,
        user_id=token.user_id,
        alert_context_id=payload.alert_context_id,
        incident_context_id=payload.incident_context_id,
    )
    return SuccessResponse(data=response)


@router.get(
    "/history/{session_id}",
    response_model=SuccessResponse[list],
    summary="Get conversation history for a session",
)
async def get_history(
    session_id: str = Path(...),
    token: TokenPayload = AnalystRequired,
    svc: ChatService = Depends(get_chat_service),
) -> SuccessResponse[list]:
    history = await svc.get_history(session_id=session_id, user_id=token.user_id)
    return SuccessResponse(data=history)


@router.delete(
    "/session/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Clear session memory",
)
async def clear_session(
    session_id: str = Path(...),
    token: TokenPayload = AnalystRequired,
    svc: ChatService = Depends(get_chat_service),
) -> None:
    await svc.clear_session(session_id=session_id, user_id=token.user_id)
    logger.info("session_cleared", session_id=session_id, user_id=token.user_id)


@router.websocket("/ws/{session_id}")
async def chat_websocket(
    websocket: WebSocket,
    session_id: str,
    svc: ChatService = Depends(get_chat_service),
) -> None:
    """
    WebSocket endpoint for streaming analyst copilot responses.

    Protocol:
      1. Client connects with Authorization header (Bearer token).
      2. Client sends JSON: {"message": "...", "alert_context_id": "..."}
      3. Server streams token chunks: {"type": "token", "content": "..."}
      4. Server sends completion: {"type": "done", "citations": [...], "tokens_used": N}
      5. Client sends next message or disconnects.
    """
    # Authenticate via query param token (WS can't set headers from browser)
    token_str = websocket.query_params.get("token")
    if not token_str:
        await websocket.close(code=4001, reason="Missing authentication token")
        return

    try:
        token = decode_token(token_str)
    except Exception:
        await websocket.close(code=4003, reason="Invalid authentication token")
        return

    await websocket.accept()
    logger.info("ws_connected", session_id=session_id, user_id=token.user_id)

    try:
        while True:
            data = await websocket.receive_json()
            message = data.get("message", "").strip()
            if not message:
                continue

            async for chunk in svc.stream_message(
                session_id=session_id,
                message=message,
                user_id=token.user_id,
                alert_context_id=data.get("alert_context_id"),
            ):
                await websocket.send_json(chunk)

    except WebSocketDisconnect:
        logger.info("ws_disconnected", session_id=session_id, user_id=token.user_id)
    except Exception as exc:
        logger.exception("ws_error", session_id=session_id, error=str(exc))
        await websocket.close(code=1011, reason="Internal server error")
