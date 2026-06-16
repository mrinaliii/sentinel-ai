"""
Chat Service
=============
Orchestrates the LangChain SOC Agent for the analyst copilot.
Handles both request/response and streaming (async generator) modes.
"""

from __future__ import annotations

import uuid
from typing import Any, AsyncGenerator, Dict, List, Optional

from app.core.config import settings
from app.core.logging import get_logger
from app.models.common import ChatResponse

logger = get_logger(__name__)


class ChatService:
    """
    Wraps the LangChain SOC Agent with session-aware memory management.

    In production:
    - self._agent: Initialized LangChain AgentExecutor
    - self._memory_store: Dict[session_id, ConversationBufferMemory]
    - self._vector_memory: VectorStoreRetrieverMemory for long-term recall
    """

    async def process_message(
        self,
        session_id: str,
        message: str,
        user_id: str,
        alert_context_id: Optional[str] = None,
        incident_context_id: Optional[str] = None,
    ) -> ChatResponse:
        """
        Process a single analyst message and return a complete response.

        Steps:
          1. Load or create session memory for session_id
          2. Build agent input: message + alert/incident context
          3. Invoke LangChain agent (AgentExecutor.ainvoke)
          4. Extract response text and citations from agent output
          5. Save exchange to session memory
          6. Return ChatResponse

        TODO: Replace stub with actual LangChain agent invocation.
        """
        logger.info(
            "chat_message_received",
            session_id=session_id,
            user_id=user_id,
            message_length=len(message),
            alert_context=alert_context_id,
        )

        # Stub response — replace with LangChain agent call
        response_text = (
            f"[Stub] I received your message: '{message}'. "
            f"The LangChain SOC agent (Llama 3 via Ollama) will respond here. "
            f"Model: {settings.OLLAMA_MODEL}"
        )

        return ChatResponse(
            session_id=session_id,
            message=response_text,
            role="assistant",
            citations=[],
            suggested_queries=[
                "Show me all failed logins for this host",
                "What other alerts are linked to this entity?",
                "Map this activity to MITRE ATT&CK",
            ],
            tokens_used=None,
        )

    async def stream_message(
        self,
        session_id: str,
        message: str,
        user_id: str,
        alert_context_id: Optional[str] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Async generator that yields token chunks for WebSocket streaming.

        Yields dicts with shape:
          {"type": "token", "content": "<token>"}      — during streaming
          {"type": "done", "citations": [...], "tokens_used": N}  — at end

        TODO: Replace with LangChain streaming callback handler:
            from langchain.callbacks.streaming_aiter import AsyncIteratorCallbackHandler
        """
        stub_tokens = (
            f"[Streaming stub] Processing: {message} "
            f"(LangChain + Llama 3 response will stream here)"
        ).split(" ")

        for token in stub_tokens:
            yield {"type": "token", "content": token + " "}

        yield {
            "type": "done",
            "citations": [],
            "suggested_queries": [],
            "tokens_used": len(stub_tokens),
        }

    async def get_history(
        self, session_id: str, user_id: str
    ) -> List[Dict[str, str]]:
        """
        Retrieve conversation history for a session.

        TODO: Load from ConversationBufferMemory or Redis-persisted memory.
        """
        return []

    async def clear_session(self, session_id: str, user_id: str) -> None:
        """
        Clear session memory for session_id.

        TODO: Remove from memory store dict and purge Redis session key.
        """
        logger.info("session_memory_cleared", session_id=session_id, user_id=user_id)
