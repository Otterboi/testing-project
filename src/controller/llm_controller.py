import traceback
import asyncio
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from fastapi import HTTPException
from app.auth.dependencies import require_valid_token
from app.models.ollama_completion_requests import OllamaCompletionRequests
from app.RAG.rag_pipeline import RagPipeline
from app.ollama_init import chat_with_ollama
from app.services.prompt_injection_detector.exceptions import PromptInjectionBlocked
from app.logger import logger
from app.services.conversation_context import get_session_messages_for_llm, format_messages_for_llm
from app.controller.chat_controller import sanitize_session_id, sanitize_user_id

security_logger = logger.get_logger("security")

router = APIRouter(prefix="/ollama", tags=["Ollama"])

pipeline: RagPipeline | None = None


class PromptRequest(BaseModel):
    prompt: str
    session_id: str | None = None
    user_id: str | None = None
    agents_md: str | None = None


# [SECURITY LEAK PREVENTION]-----------------------------------------------
# =========================================================================
# SYSTEM PROMPTS (Never exposed to users)
# =========================================================================
CHAT_SYSTEM_PROMPT = """You are ScribePilot, an AI coding assistant.
You help developers write better code, explain concepts, and solve problems.
Always be helpful, accurate, and concise."""

COMPLETION_SYSTEM_PROMPT = """You are ScribePilot, a code completion AI.
Generate ONLY the requested code with NO explanations, preambles, or markdown.
Output raw code that can be directly inserted into the file."""


HISTORY_RETRIEVAL_TIMEOUT = 5.0  # seconds - don't wait forever for history


# helper function for getting conversation history
async def get_conversation_history(session_id: str, user_id: str) -> list | None:
    """Retrieve conversation history with error handling and timeout."""
    try:
        validated_session_id = sanitize_session_id(session_id)
        validated_user_id = sanitize_user_id(user_id)

        print(
            f"Retrieving conversation history for session: {validated_session_id}, "
            f"user: {validated_user_id}"
        )

        try:
            raw_messages = await asyncio.wait_for(
                get_session_messages_for_llm(
                    session_id=validated_session_id, user_id=validated_user_id, limit=75
                ),
                timeout=HISTORY_RETRIEVAL_TIMEOUT,
            )

            if raw_messages:
                conversation_history = format_messages_for_llm(raw_messages)
                print(f"Retrieved {len(conversation_history)} messages for LLM context")
                return conversation_history
            else:
                print("No previous messages found for this session/user")
                return None

        except asyncio.TimeoutError:
            print(
                f"History retrieval timed out after {HISTORY_RETRIEVAL_TIMEOUT}s - "
                "continuing without context"
            )
            security_logger.warning(
                event_type="chat.history_timeout",
                message=f"History retrieval timeout for session {validated_session_id}",
            )
            return None

    except ValueError as validation_error:
        print(f"Invalid session_id or user_id format: {str(validation_error)}")
        security_logger.warning(
            event_type="chat.invalid_history_params",
            message=f"Invalid history parameters: {str(validation_error)}",
        )
        return None

    except Exception as history_error:
        print(f"Failed to retrieve conversation history: {str(history_error)}")
        security_logger.error(
            event_type="chat.history_error",
            message=f"History retrieval failed: {str(history_error)}",
        )
        return None


# =========================================================================
# STARTUP EVENT
# =========================================================================


@router.on_event("startup")
async def startup_event():
    global pipeline
    pipeline = RagPipeline()
    await pipeline.initialize()
    print("✅ RagPipeline initialized successfully")


# =========================================================================
# CHAT ENDPOINT -- ENHANCED SECURITY
# =========================================================================
@router.post("/chat")
async def chat_with_model(
    request_body: PromptRequest,
    request: Request,
    _claims: dict = Depends(require_valid_token),
):
    """Chat endpoint with security filtering and RAG integration"""
    print("=" * 80)
    print("🔍 OLLAMA /chat endpoint hit")

    try:
        # Use filtered prompt if available (from security middleware)
        if hasattr(request.state, "filtered_body"):
            filtered_request = PromptRequest(**request.state.filtered_body)
            user_prompt = filtered_request.prompt
            session_id = filtered_request.session_id
            user_id = filtered_request.user_id
            agents_md = filtered_request.agents_md
            print("🔒 Using FILTERED prompt")
        else:
            user_prompt = request_body.prompt
            session_id = request_body.session_id
            user_id = request_body.user_id
            agents_md = request_body.agents_md
            print("⚠️ Using ORIGINAL prompt (no filtering)")

        conversation_history = None
        if session_id and user_id:
            conversation_history = await get_conversation_history(session_id, user_id)

        # Use RAG pipeline if available
        global pipeline
        if pipeline is not None:
            print("⚙️ Using RAG pipeline for response...")
            # Pass agents_md content to RAG pipeline
            result = await pipeline.send_rag_chat_to_llm(
                user_query=user_prompt,
                conversation_history=conversation_history,  # ← NEW!
                agents_md=agents_md,
            )
            return {"response": result["answer"], "sources": result.get("sources", [])}
        else:
            print("⚙️ Using Ollama fallback...")

            # SECURE: Separate system and user messages | leaks prevention
            response = chat_with_ollama(user_message=user_prompt, system_message=CHAT_SYSTEM_PROMPT)
            return {"response": response}

    except PromptInjectionBlocked as error:
        print(f"❌ ERROR in /chat: {type(error).__name__}: {str(error)}")
        security_logger.error(
            event_type="chat.prompt_injection_blocked",
            message="A prompt injection was detected and blocked from being sent to ScribePilot",
        )
        raise HTTPException(status_code=403, detail={"error": str(error)})
    except Exception as e:
        print(f"❌ ERROR in /chat: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=500, detail={"error": str(e)})


# =========================================================================
# INLINE COMPLETION ENDPOINT -- ENHANCED SECURITY
# =========================================================================
@router.post("/completion")
async def inline_completion_chat(
    request_body: OllamaCompletionRequests,
    request: Request,
    _claims: dict = Depends(require_valid_token),
):
    """Code completion endpoint with security filtering and RAG integration"""
    print("=" * 80)
    print("🔍 OLLAMA /completion endpoint hit")

    try:
        #  filtered content from security middleware
        if hasattr(request.state, "filtered_body"):
            filtered_request = OllamaCompletionRequests(**request.state.filtered_body)
            code_context = filtered_request.prompt
            language = filtered_request.language
            print("🔒 Using FILTERED code")
        else:
            code_context = request_body.prompt
            language = request_body.language
            print("⚠️ Using ORIGINAL code (no filtering)")

        global pipeline
        if pipeline is not None:
            print("⚙️ Using RAG pipeline for code completion...")
            result = await pipeline.send_rag_completion_to_llm(code_context, language)
            return {"response": result["answer"], "sources": result.get("sources", [])}
        else:
            print("⚙️ Using Ollama fallback...")

            # [SECURITY]: System message for instructions, user message for context
            system_instructions = COMPLETION_SYSTEM_PROMPT + f"\nTarget language: {language}"

            response = chat_with_ollama(
                user_message=code_context, system_message=system_instructions
            )
            return {"response": response}

    except PromptInjectionBlocked as error:
        print(f"❌ ERROR in /chat: {type(error).__name__}: {str(error)}")
        security_logger.error(
            event_type="chat.prompt_injection_blocked",
            message="A prompt injection was detected and blocked from being sent to ScribePilot",
        )
        raise HTTPException(status_code=403, detail={"error": str(error)})
    except Exception as e:
        print(f"❌ ERROR in /completion: {type(e).__name__}: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail={"error": str(e)})
