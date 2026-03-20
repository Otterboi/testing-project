import re

from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from starlette.concurrency import run_in_threadpool

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pymongo import ASCENDING, DESCENDING

from app.db import sessions_col, messages_col
from app.models.chat import (
    ChatRequest,
    ChatAccepted,
    AssistantRequest,
    AssistantSaved,
    SessionListResponse,
    SessionSummary,
)
from app.utils.chat import (
    utcnow,
    ensure_session_for_user_sync,
    insert_message_idempotent,
    generate_message_id,
)
from app.services.conversation_context import get_context_debug_info
from app.services.prompt_injection_detector import InvalidSessionIdError, InvalidUserIdError

router = APIRouter(prefix="/chat", tags=["chat"])

################################################################################################
# SECURITY: Input Sanitization Functions (FIXED TO SUPPORT BOTH UUID AND GENERATED IDS)
################################################################################################


def sanitize_session_id(session_id: str) -> str:
    """
    Validates and sanitizes session ID to prevent NoSQL injection (CRITICAL ISSUE 1 🛑)
    Supports BOTH formats:
    1. UUID: 1ea6b89c-7d4c-4737-86bb-f3f0bf19f9be
    2. Generated: session-1234567890-abc123

    Raises:
        InvalidSessionIdError: If session ID is empty or invalid

    Returns:
        Sanitized session ID
    """
    if not session_id:
        raise InvalidSessionIdError("Session ID cannot be empty")

    session_id = str(session_id).strip()

    if len(session_id) > 100:
        raise InvalidSessionIdError("Session ID too long (max 100 characters)")

    # pattern 1: UUID (8-4-4-4-12 hex format)
    uuid_pattern = r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$"

    # pattern 2: Generated ID (session-timestamp-randomchars)
    generated_pattern = r"^[a-zA-Z0-9_-]+$"

    if re.match(uuid_pattern, session_id):
        return session_id
    elif re.match(generated_pattern, session_id) and session_id.startswith("session-"):
        return session_id
    else:
        raise InvalidSessionIdError(
            "Invalid session ID format. Must be either UUID or generated format (session-*)"
        )


def sanitize_user_id(user_id: str) -> str:
    """
    Validates and sanitizes user ID to prevent NoSQL injection

    Raises:
        InvalidUserIdError: If user ID is empty or invalid

    Returns:
        Sanitized user ID
    """
    if not user_id:
        raise InvalidUserIdError("User ID cannot be empty")

    user_id = str(user_id).strip()

    if len(user_id) > 100:
        raise InvalidUserIdError("User ID too long (max 100 characters)")

    # Add your user ID validation pattern here
    valid_pattern = r"^[a-zA-Z0-9_-]+$"

    if not re.match(valid_pattern, user_id):
        raise InvalidUserIdError("Invalid user ID format")

    return user_id


################################################################################################
# SECURITY: Rate Limiting
################################################################################################

_rate_limit_store = defaultdict(list)
_MAX_REQUESTS_PER_MINUTE = 60
_MAX_SESSIONS_PER_USER = 100


def check_rate_limit(user_id: str) -> bool:
    """Simple in-memory rate limiter - prevents DoS"""
    now = datetime.now(timezone.utc)
    minute_ago = now - timedelta(minutes=1)

    _rate_limit_store[user_id] = [ts for ts in _rate_limit_store[user_id] if ts > minute_ago]

    if len(_rate_limit_store[user_id]) >= _MAX_REQUESTS_PER_MINUTE:
        return False

    _rate_limit_store[user_id].append(now)
    return True


################################################################################################
# ENDPOINT: POST /query (CREATE MESSAGE)
################################################################################################


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    user_id: str = Query(..., alias="userId", description="The user ID from frontend"),
    search: Optional[str] = Query(None, description="Optional search query"),
    limit: int = Query(50, ge=1, le=200),
):
    filter_doc = {"userId": user_id}

    if search:
        search_str = search.strip()
        if search_str:
            search_regex = re.compile(re.escape(search_str), re.IGNORECASE)
            filter_doc["$or"] = [
                {"title": search_regex},
                {"firstMessagePreview": search_regex},
            ]

    projection = {
        "_id": 1,
        "title": 1,
        "firstMessagePreview": 1,
        "createdAt": 1,
        "updatedAt": 1,
        "lastMessageAt": 1,
        "messageCount": 1,
    }

    cursor = (
        sessions_col().find(filter_doc, projection).sort("lastMessageAt", DESCENDING).limit(limit)
    )

    raw = await run_in_threadpool(list, cursor)

    sessions = [
        SessionSummary(
            sessionId=str(doc.get("_id")),
            title=doc.get("title"),
            firstMessagePreview=doc.get("firstMessagePreview"),
            createdAt=doc.get("createdAt"),
            updatedAt=doc.get("updatedAt"),
            lastMessageAt=doc.get("lastMessageAt"),
            messageCount=int(doc.get("messageCount", 0)),
        )
        for doc in raw
    ]

    return SessionListResponse(sessions=sessions)


################################################################################
#             REFACTORED - REDUCE METHOD SIZE & COGNITIVE LOAD                 #
################################################################################


@router.post("/query", response_model=ChatAccepted, status_code=status.HTTP_201_CREATED)
async def post_user_message(body: ChatRequest):
    """
    SECURITY FIXES:
    1. Input validation (supports UUID + generated session IDs)
    2. Rate limiting to prevent DoS
    3. Session limit per user
    4. Atomic session creation with race condition handling
    5. Explicit type casting for MongoDB queries
    """
    # Validate inputs
    user_id, session_id = _validate_and_sanitize_inputs(body)

    # Check rate limit
    _check_user_rate_limit(user_id)

    # Handle session (create || verify)
    now = utcnow()
    session_id, session_created = await _handle_session(session_id, user_id, body.message, now)

    # Create user message
    user_msg_id = await _create_user_message(body, session_id, user_id, now)

    # Update session metadata
    await _update_session_metadata(session_id, user_id, now)

    return ChatAccepted(
        sessionId=session_id,
        userMessageId=user_msg_id,
        sessionCreated=session_created,
        createdAt=now,
    )


# Helper functions -- Refactoring #172


def _validate_and_sanitize_inputs(body: ChatRequest) -> tuple[str, Optional[str]]:
    """Validate and sanitize user inputs"""
    try:
        user_id = sanitize_user_id(body.userId)
        session_id = sanitize_session_id(body.sessionId) if body.sessionId else None
        return user_id, session_id
    except (InvalidSessionIdError, InvalidUserIdError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def _check_user_rate_limit(user_id: str) -> None:
    """Check if user has exceeded rate limit"""
    if not check_rate_limit(user_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please slow down.",
        )


async def _handle_session(
    session_id: Optional[str], user_id: str, message: str, now: datetime
) -> tuple[str, bool]:
    """Handle session creation or verification"""
    if session_id:
        return await _verify_existing_session(session_id, user_id, now)
    else:
        return await _create_new_session(user_id, message, now)


async def _verify_existing_session(
    session_id: str, user_id: str, now: datetime
) -> tuple[str, bool]:
    """Verify existing session belongs to user"""
    created = await run_in_threadpool(ensure_session_for_user_sync, session_id, user_id, now)
    return session_id, created


async def _create_new_session(user_id: str, message: str, now: datetime) -> tuple[str, bool]:
    """Create a new session for the user"""
    # Check session limit
    await _check_session_limit(user_id)

    # Generate new session
    session_id = generate_message_id("session", None, "id")

    new_session_doc = {
        "_id": str(session_id),
        "userId": str(user_id),
        "createdAt": now,
        "updatedAt": now,
        "lastMessageAt": now,
        "messageCount": 0,
        "title": str(message[:60]),
        "firstMessagePreview": str(message[:160]),
    }

    # Insert with ** race condition handling **
    await _insert_session_with_retry(session_id, user_id, new_session_doc)

    return session_id, True


async def _check_session_limit(user_id: str) -> None:
    """Check if user has reached maximum session limit"""
    user_session_count = await run_in_threadpool(
        sessions_col().count_documents,
        {"userId": user_id},
    )

    if user_session_count >= _MAX_SESSIONS_PER_USER:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Session limit exceeded. Maximum {_MAX_SESSIONS_PER_USER} sessions per user.",
        )


async def _insert_session_with_retry(session_id: str, user_id: str, new_session_doc: dict) -> None:
    """Insert session with duplicate key handling"""
    try:
        await run_in_threadpool(sessions_col().insert_one, new_session_doc)
    except Exception as e:
        await _handle_session_insert_error(e, session_id, user_id)


async def _handle_session_insert_error(error: Exception, session_id: str, user_id: str) -> None:
    """Handle errors during session insertion"""
    if "duplicate key" not in str(error).lower():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create session",
        )

    # Check if duplicate belongs to this user
    existing = await run_in_threadpool(
        sessions_col().find_one, {"_id": str(session_id), "userId": str(user_id)}
    )

    if not existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Session ID collision. Please retry.",
        )


async def _create_user_message(
    body: ChatRequest, session_id: str, user_id: str, now: datetime
) -> str:
    """Create and insert user message document"""
    user_msg_id = generate_message_id(session_id, body.clientMessageId, "user")

    doc = {
        "_id": str(user_msg_id),
        "sessionId": str(session_id),
        "userId": str(user_id),
        "role": "user",
        "content": str(body.message),
        "createdAt": now,
        "parentId": None,
        "clientMessageId": str(body.clientMessageId) if body.clientMessageId else None,
        "meta": {},
    }

    user_msg_id = await run_in_threadpool(insert_message_idempotent, doc)
    return user_msg_id


async def _update_session_metadata(session_id: str, user_id: str, now: datetime) -> None:
    """Update session with latest message timestamp and count"""
    update_fields = {"updatedAt": now, "lastMessageAt": now}

    await run_in_threadpool(
        sessions_col().update_one,
        {"_id": str(session_id), "userId": str(user_id)},
        {"$set": update_fields, "$inc": {"messageCount": 1}},
    )


################################################################################################
# ENDPOINT: POST /assistant (SAVE ASSISTANT MESSAGE)
################################################################################################


@router.post("/assistant", response_model=AssistantSaved, status_code=status.HTTP_201_CREATED)
async def post_assistant_message(body: AssistantRequest):
    """
    SECURITY FIXES:
    1. Input validation
    2. Authorization check (verify parent message ownership)
    3. Explicit type casting
    """

    # Validate inputs
    try:
        user_id = sanitize_user_id(body.userId)
        session_id = sanitize_session_id(body.sessionId)
    except (InvalidSessionIdError, InvalidUserIdError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Rate limiting
    if not check_rate_limit(user_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded"
        )

    now = utcnow()

    await run_in_threadpool(ensure_session_for_user_sync, session_id, user_id, now)

    # Verify parent message ownership - CRITICAL
    parent = await run_in_threadpool(
        messages_col().find_one,
        {
            "_id": str(body.parentUserMessageId),
            "sessionId": str(session_id),
            "role": "user",
            "userId": str(user_id),  # Authorization check
        },
    )

    if not parent:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Parent message not found or access denied",
        )

    asst_msg_id = generate_message_id(session_id, body.clientMessageId, "assistant")

    doc = {
        "_id": str(asst_msg_id),
        "sessionId": str(session_id),
        "userId": str(user_id),
        "role": "assistant",
        "content": str(body.content),
        "createdAt": now,
        "parentId": str(body.parentUserMessageId),
        "clientMessageId": str(body.clientMessageId) if body.clientMessageId else None,
        "meta": {},
    }

    asst_msg_id = await run_in_threadpool(insert_message_idempotent, doc)

    await run_in_threadpool(
        sessions_col().update_one,
        {"_id": str(session_id), "userId": str(user_id)},
        {"$set": {"updatedAt": now, "lastMessageAt": now}, "$inc": {"messageCount": 1}},
    )

    return AssistantSaved(
        sessionId=session_id,
        messageId=asst_msg_id,
        createdAt=now,
    )


################################################################################################
# ENDPOINT: GET /history/{session_id} (LOAD CHAT HISTORY)
################################################################################################


@router.get("/history/{session_id}")
async def get_chat_history(
    session_id: str,
    user_id: str = Query(..., alias="userId", description="The user ID from frontend"),
    limit: int = Query(200, ge=1, le=500),
):
    """
    SECURITY FIXES:
    1. Input validation (supports UUID + generated formats)
    2. Authorization check (verify session ownership)
    3. Query parameterization (prevents NoSQL injection)
    4. Result limit enforcement
    """

    # validate inputs
    try:
        validated_session_id = sanitize_session_id(session_id)
        validated_user_id = sanitize_user_id(user_id)
    except (InvalidSessionIdError, InvalidUserIdError) as e:
        raise HTTPException(status_code=400, detail=str(e))

    # rate limiting
    if not check_rate_limit(validated_user_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded"
        )

    # verify session ownership - CRITICAL
    existing_session = await run_in_threadpool(
        sessions_col().find_one,
        {"_id": str(validated_session_id)},  # Sanitized input
        {"userId": 1},
    )

    if existing_session:
        owner = existing_session.get("userId")
        if owner and str(owner) != str(validated_user_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Session belongs to another user",
            )

    try:
        # parameterized query - PREVENTS NOSQL INJECTION
        cursor = (
            messages_col()
            .find(
                {
                    "sessionId": str(validated_session_id),  # sanitized string
                    "userId": str(validated_user_id),  # sanitized string + authZ
                }
            )
            .sort("createdAt", ASCENDING)
            .limit(min(limit, 500))
        )

        results = await run_in_threadpool(list, cursor)

        # sanitized output and normalize datetimes to UTC ISO strings
        for msg in results:
            msg["_id"] = str(msg["_id"])
            msg.pop("_internal", None)
            # normalize createdAt to an explicit UTC ISO string ending with 'Z'
            try:
                ca = msg.get("createdAt")
                if isinstance(ca, datetime):
                    # timezone-aware and convert to UTC & # isoformat +00:00 for UTC thus convert to 'Z'
                    msg["createdAt"] = (
                        ca.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                    )
                else:
                    msg["createdAt"] = ca
            except Exception:
                msg.pop("createdAt", None)

        return {"sessionId": validated_session_id, "messages": results, "count": len(results)}

    except Exception as e:
        print(f"ERROR fetching history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve chat history",
        )


@router.get("/context-debug/{session_id}")
async def get_context_debug(
    session_id: str, user_id: str = Query(..., description="User ID for context")
):
    try:
        debug_info = await get_context_debug_info(session_id, user_id)
        return debug_info
    except Exception as e:
        print(f"Failed to get context debug info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve context debug information",
        )
