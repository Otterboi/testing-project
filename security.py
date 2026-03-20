"""
Security Filtering Middleware - ENHANCED
Multi-layer defense: Keyword Blocker → Guard LLM → PII/Secret Detection → Response Filtering
"""

import time
import json
import re
from typing import Optional, Dict, Any
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services import PIIDetector, SecretDetector, GuardLLM, KeywordBlocker
from app.db import get_db
from app.models.policy import PolicySet


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Multi-layer bidirectional security filter.

    REQUEST FLOW:
    1. Keyword Blocker (instant, <1ms)
    2. Guard LLM (semantic, ~50ms)
    3. PII/Secret Detection
    4. Pass to LLM

    RESPONSE FLOW:
    1. Keyword Blocker (instant leak check)
    2. Guard LLM (semantic leak check)
    3. PII/Secret Redaction
    4. Return to user
    """

    # Paths filtered by SecurityMiddleware (NO /api prefix - nginx strips it)
    PROTECTED_PATHS = [
        "/ollama/chat",
        "/ollama/completion",
        "/completions",
        "/chat",
        "/repository",
    ]

    def __init__(self, app):
        super().__init__(app)

        # Detectors
        self.pii_detector = None
        self.secret_detector = None
        self.guard_llm = None  # NEW SECURITY LAYER : Guard LLM for semantic analysis
        self.keyword_blocker = None  # NEW SECURITY LAYER : Fast keyword matching
        self.default_policy = None

        self._stats = {
            "total_requests": 0,
            "filtered_requests": 0,
            "blocked_requests": 0,
            "blocked_by_keyword": 0,  # 🔒 NEW
            "blocked_by_guard_llm": 0,  # 🔒 NEW
            "prompt_extraction_blocked": 0,
            "credential_theft_blocked": 0,
            "total_redactions": 0,
            "prompt_leaks_blocked": 0,
        }

    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch - orchestrates security filtering"""
        start_time = time.time()
        print(f"\n🔍 MIDDLEWARE: Request to {request.url.path}")

        # Early return for unprotected paths
        if not self._should_filter(request.url.path):
            print(f"⏭️  MIDDLEWARE: Skipping filtering for {request.url.path}")
            return await call_next(request)

        print(f"🔒 MIDDLEWARE: Will filter {request.url.path}")
        self._stats["total_requests"] += 1

        # Initialize security components
        if not await self._initialize_security_components():
            return await call_next(request)

        # Get user context and policies
        user_id, user_role = await self._get_user_context(request)
        policies = await self._load_policies(user_id, user_role)
        print(f"👤 MIDDLEWARE: User {user_id} with role {user_role}")
        print(f"📋 MIDDLEWARE: Loaded {len(policies)} policies")

        # Process inbound request
        request, blocked_response = await self._process_inbound_request(
            request, user_id, user_role, policies
        )
        if blocked_response:
            return blocked_response

        # Pass to controller
        print("⏭️  MIDDLEWARE: Passing to controller...")
        response = await call_next(request)
        print(f"📨 MIDDLEWARE: Got response with status {response.status_code}")

        # Process outbound response
        response = await self._process_outbound_response(response, policies, user_id)

        # Add timing header
        duration_ms = (time.time() - start_time) * 1000
        response.headers["X-Security-Filter-Duration-Ms"] = str(round(duration_ms, 2))
        print(f"✅ MIDDLEWARE: Done in {duration_ms:.2f}ms\n")

        return response

    async def _initialize_security_components(self) -> bool:
        """Initialize all security detectors. Returns False if initialization fails."""
        try:
            await self._ensure_detectors_loaded()
            print("✅ MIDDLEWARE: All detectors loaded")
            return True
        except Exception as e:
            print(f"❌ MIDDLEWARE: Failed to load detectors: {e}")
            return False

    async def _process_inbound_request(
        self, request: Request, user_id: str, user_role: str, policies: list
    ) -> tuple[Request, Optional[Response]]:
        """
        Process inbound request through security layers.
        Returns (updated_request, blocking_response).
        If blocking_response is not None, request should be blocked.
        """
        request_body = await self._get_request_body(request)
        print(
            f"📥 MIDDLEWARE: Request body: {json.dumps(request_body, indent=2) if request_body else 'None'}"
        )

        if not request_body:
            return request, None

        # Layer 1 & 2: Malicious intent detection
        blocked_response = await self._check_malicious_intent(request_body, user_id)
        if blocked_response:
            return request, blocked_response

        # Layer 3: PII/Secret filtering
        request, blocked_response = await self._apply_content_filtering(
            request, request_body, policies, user_id, user_role
        )

        return request, blocked_response

    async def _check_malicious_intent(
        self, request_body: Dict[str, Any], user_id: str
    ) -> Optional[Response]:
        """Check for malicious intent and return blocking response if detected."""
        malicious_intent = await self._detect_malicious_intent(request_body, user_id)

        if not malicious_intent:
            return None

        # Log detection
        self._log_malicious_detection(malicious_intent)

        # Update statistics
        self._update_malicious_intent_stats(
            malicious_intent.get("attack_type", "unknown"),
            malicious_intent.get("detection_method", "unknown"),
        )

        # Log security event
        await self._log_malicious_intent_event(user_id, malicious_intent)

        # Return blocking response
        return self._create_malicious_intent_response(
            malicious_intent.get("attack_type", "unknown"),
            malicious_intent.get("confidence", 0.0),
            malicious_intent.get("detection_method", "unknown"),
        )

    def _log_malicious_detection(self, malicious_intent: Dict[str, Any]) -> None:
        """Log details of malicious intent detection."""
        attack_type = malicious_intent.get("attack_type", "unknown")
        confidence = malicious_intent.get("confidence", 0.0)
        detection_method = malicious_intent.get("detection_method", "unknown")

        print("🚫 MIDDLEWARE: MALICIOUS INTENT DETECTED!")
        print(f"   Type: {attack_type}")
        print(f"   Confidence: {confidence:.2%}")
        print(f"   Method: {detection_method}")

    def _update_malicious_intent_stats(self, attack_type: str, detection_method: str) -> None:
        """Update statistics for malicious intent detection."""
        self._stats["blocked_requests"] += 1

        if detection_method == "keyword_blocker":
            self._stats["blocked_by_keyword"] += 1
        elif detection_method == "guard_llm":
            self._stats["blocked_by_guard_llm"] += 1

        if attack_type in ["prompt_extraction", "keyword_match", "pattern_match"]:
            self._stats["prompt_extraction_blocked"] += 1
        elif attack_type == "credential_theft":
            self._stats["credential_theft_blocked"] += 1

    async def _log_malicious_intent_event(
        self, user_id: str, malicious_intent: Dict[str, Any]
    ) -> None:
        """Log malicious intent detection event."""
        await self._log_security_event(
            user_id,
            "malicious_intent_blocked",
            [
                {
                    "type": "malicious_intent",
                    "attack_type": malicious_intent.get("attack_type", "unknown"),
                    "confidence": malicious_intent.get("confidence", 0.0),
                    "detection_method": malicious_intent.get("detection_method", "unknown"),
                    "matched_text": malicious_intent.get("user_text", "")[:100],
                    "reasoning": malicious_intent.get("reasoning", ""),
                }
            ],
        )

    def _create_malicious_intent_response(
        self, attack_type: str, confidence: float, detection_method: str
    ) -> Response:
        """Create appropriate error response for malicious intent."""
        error_message, violation_type = self._get_error_message_for_attack(attack_type)

        return JSONResponse(
            status_code=403,
            content={
                "error": "Security policy violation",
                "message": error_message,
                "violation_type": violation_type,
                "confidence": confidence,
                "detection_method": detection_method,
            },
        )

    def _get_error_message_for_attack(self, attack_type: str) -> tuple[str, str]:
        """Get appropriate error message and violation type for attack type."""
        if attack_type in [
            "prompt_extraction",
            "keyword_match",
            "pattern_match",
            "jailbreak_attempt",
        ]:
            return (
                "I cannot reveal my system instructions, internal prompts, or bypass my guidelines. "
                "This is a security policy. I'm here to help you with legitimate coding tasks instead.",
                "prompt_extraction_attempt",
            )
        elif attack_type == "credential_theft":
            return (
                "I cannot help with requests to retrieve or expose sensitive information like API keys, "
                "secrets, passwords, or credentials. This is a security policy. "
                "I can help you learn about security best practices instead.",
                "sensitive_information_request",
            )
        else:
            return (
                "This request violates our security policy. "
                "Please rephrase your question to focus on legitimate coding assistance.",
                "security_policy_violation",
            )

    async def _apply_content_filtering(
        self,
        request: Request,
        request_body: Dict[str, Any],
        policies: list,
        user_id: str,
        user_role: str,
    ) -> tuple[Request, Optional[Response]]:
        """Apply PII/Secret filtering and access control."""
        print("🔍 MIDDLEWARE: Scanning for PII/secrets...")

        filtered_request, request_violations = await self._filter_request(
            request_body, policies, user_id, user_role
        )

        self._log_violations(request_violations)

        # Check if should block
        if self._should_block(request_violations):
            return request, self._create_blocking_response(user_id, request_violations)

        # Update request with filtered content
        request = await self._update_request_body(request, filtered_request)
        print("✅ MIDDLEWARE: Request filtered and stored in state")

        if request_violations:
            self._stats["filtered_requests"] += 1
            await self._log_security_event(user_id, "request_filtered", request_violations)

        return request, None

    def _log_violations(self, violations: list) -> None:
        """Log detected violations."""
        if violations:
            print(f"⚠️  MIDDLEWARE: Found {len(violations)} violations")
            for v in violations[:3]:
                violation_type = v.type if hasattr(v, "type") else v.get("type", "unknown")
                print(f"   - {violation_type}")
        else:
            print("✅ MIDDLEWARE: No violations found")

    def _create_blocking_response(self, user_id: str, violations: list) -> Response:
        """Create response for blocked request."""
        print("🚫 MIDDLEWARE: BLOCKING request due to violations")
        self._stats["blocked_requests"] += 1
        # Fire and forget logging
        import asyncio

        task = asyncio.create_task(self._log_security_event(user_id, "request_blocked", violations))

        # Keep reference to prevent premature garbage collection
        self._background_tasks = getattr(self, "_background_tasks", set())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked due to security policy",
                "violations": [v.type if hasattr(v, "type") else v.get("type") for v in violations],
            },
        )

    async def _process_outbound_response(
        self, response: Response, policies: list, user_id: str
    ) -> Response:
        """Process outbound response through security filters."""
        if response.status_code != 200:
            return response

        try:
            content_type = response.headers.get("content-type", "")
            if "application/json" not in content_type:
                return response

            response_body = await self._get_response_body(response)
            if not response_body:
                return response

            return await self._filter_and_update_response(
                response_body, response, policies, user_id
            )

        except Exception as e:
            print(f"❌ MIDDLEWARE: Response filtering failed: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": "Response filtering failed", "detail": str(e)},
            )

    async def _filter_and_update_response(
        self,
        response_body: Dict[str, Any],
        original_response: Response,
        policies: list,
        user_id: str,
    ) -> Response:
        """Filter response body and create updated response."""
        print("🔍 MIDDLEWARE: Scanning response...")

        # Apply multi-layer response filtering
        filtered_response, response_violations = await self._filter_response(
            response_body, policies, user_id
        )

        if response_violations:
            print(f"⚠️  MIDDLEWARE: Found {len(response_violations)} violations in response")
            self._stats["total_redactions"] += len(response_violations)
            await self._log_security_event(user_id, "response_filtered", response_violations)

        # Create new response with filtered content
        response = await self._create_filtered_response(filtered_response, original_response)
        print("✅ MIDDLEWARE: Response filtered successfully")

        return response

    # =========================================================================
    # SECURITY LAYER 1 & 2: Malicious Intent Detection (Hybrid Approach)
    # =========================================================================
    async def _detect_malicious_intent(
        self, request_body: Dict[str, Any], user_id: str
    ) -> Optional[Dict]:
        """
        Multi-layer malicious intent detection.

        LAYER 1: Keyword Blocker (~1ms upon execution) - catches obvious attacks
        LAYER 2: Guard LLM (~50ms upon execution) - catches sophisticated attacks

        This is the industry-standard approach used by Claude and ChatGPT.
        """
        text_fields = ["prompt", "message", "query", "code"]
        text_to_check = " ".join(
            str(request_body.get(field, "")) for field in text_fields if field in request_body
        )

        if not text_to_check.strip():
            return None

        # 🔒 LAYER 1: Keyword blocker (instant, obvious attacks)
        keyword_result = self.keyword_blocker.check(text_to_check)
        if keyword_result:
            print("⚡ KEYWORD BLOCKER: Instant block")
            print(
                f"   Matched: {keyword_result.get('matched_phrase', keyword_result.get('matched_text', 'N/A'))}"
            )
            return keyword_result

        # 🔒 LAYER 2: Guard LLM (semantic, sophisticated attacks)
        guard_result = await self.guard_llm.classify_intent(text_to_check, user_id)
        if guard_result:
            print("🛡️  GUARD LLM: Malicious intent detected")
            print(f"   Type: {guard_result.get('attack_type', 'unknown')}")
            print(f"   Confidence: {guard_result.get('confidence', 0.0):.2%}")
            print(f"   Reason: {guard_result.get('reasoning', 'No reasoning provided')}")
            return guard_result

        # ✅ if both layers passed -> request is benign
        return None

    # =========================================================================
    # SECURITY LAYER 3: PII/Secret Detection
    # =========================================================================
    def _scan_and_redact_fields(
        self, body: Dict[str, Any], text_fields: list[str], violations: list
    ) -> Dict[str, Any]:
        """Scan and redact PII/secrets from specified fields"""
        filtered_body = body.copy()

        text_to_scan = " ".join(str(body.get(field, "")) for field in text_fields if field in body)

        if not text_to_scan.strip():
            return filtered_body

        # PII detection
        pii_result = self.pii_detector.scan(text_to_scan)
        if pii_result.detected:
            violations.extend(pii_result.violations)
            for field in text_fields:
                if field in filtered_body:
                    filtered_body[field] = self.pii_detector.redact(
                        str(filtered_body[field]), pii_result.violations
                    )

        # Secret detection
        secret_result = self.secret_detector.scan(text_to_scan)
        if secret_result.detected:
            violations.extend(secret_result.violations)
            for field in text_fields:
                if field in filtered_body:
                    filtered_body[field] = self.secret_detector.redact(
                        str(filtered_body[field]), secret_result.violations
                    )

        return filtered_body

    async def _filter_request(
        self, request_body: Dict[str, Any], policies: list[PolicySet], user_id: str, user_role: str
    ):
        """Filter request for PII/secrets and access control"""
        violations = []
        text_fields = ["prompt", "message", "query", "code"]

        # PII/Secret scanning
        filtered_body = self._scan_and_redact_fields(request_body, text_fields, violations)

        # Access control
        if "file_path" in request_body:
            file_path = request_body["file_path"]
            access_violations = await self._check_access_control(file_path, user_role, policies)
            violations.extend(access_violations)

        return filtered_body, violations

    # =========================================================================
    # SECURITY LAYER 4: Response Leak Detection (Multi-Layer)
    # =========================================================================
    async def _filter_response(
        self, response_body: Dict[str, Any], policies: list[PolicySet], user_id: str
    ):
        """
        Multi-layer response filtering.
        LAYER 1: Keyword Blocker (instant, obvious leaks)
        LAYER 2: Guard LLM (semantic, sophisticated leaks)
        LAYER 3: PII/Secret Redaction
        """
        violations = []
        filtered_body = response_body.copy()
        text_fields = ["completion", "response", "message", "content", "code"]

        text_to_scan = self._extract_text_from_fields(response_body, text_fields)
        if not text_to_scan:
            return filtered_body, violations

        # Layer 1: Keyword blocker check
        filtered_body = await self._check_keyword_leak(
            text_to_scan, filtered_body, text_fields, violations
        )

        # Layer 2: Guard LLM check (only if keyword check passed)
        if not any(v.get("type") == "prompt_leak" for v in violations):
            filtered_body = await self._check_guard_llm_leak(
                text_to_scan, filtered_body, text_fields, violations
            )

        # Layer 3: PII/Secret scanning (always run)
        filtered_body = self._scan_and_redact_fields(filtered_body, text_fields, violations)

        return filtered_body, violations

    def _extract_text_from_fields(self, body: Dict[str, Any], fields: list[str]) -> str:
        """Extract and combine text from specified fields."""
        text_parts = [str(body.get(field, "")) for field in fields if field in body]
        return " ".join(text_parts).strip()

    async def _check_keyword_leak(
        self,
        text_to_scan: str,
        filtered_body: Dict[str, Any],
        text_fields: list[str],
        violations: list,
    ) -> Dict[str, Any]:
        """Check for keyword-based leaks in response."""
        keyword_leak = self.keyword_blocker.check_response_leak(text_to_scan)

        if not keyword_leak:
            return filtered_body

        print("⚡ KEYWORD BLOCKER: Response leak detected (obvious)")
        print(f"   Leaked phrases: {keyword_leak['leaked_phrases']}")

        # Replace response with safe message
        filtered_body = self._replace_with_safe_message(filtered_body, text_fields)
        violations.append(keyword_leak)
        self._stats["prompt_leaks_blocked"] += 1

        return filtered_body

    async def _check_guard_llm_leak(
        self,
        text_to_scan: str,
        filtered_body: Dict[str, Any],
        text_fields: list[str],
        violations: list,
    ) -> Dict[str, Any]:
        """Check for semantic leaks using Guard LLM."""
        guard_leak = await self.guard_llm.check_response_leak(text_to_scan)

        if not guard_leak:
            return filtered_body

        print("🛡️ GUARD LLM: Response leak detected (semantic)")
        print(f"   Confidence: {guard_leak['confidence']:.2%}")
        print(f"   Reasoning: {guard_leak['reasoning']}")

        # Replace response with safe message
        filtered_body = self._replace_with_safe_message(filtered_body, text_fields)
        violations.append(guard_leak)
        self._stats["prompt_leaks_blocked"] += 1

        return filtered_body

    def _replace_with_safe_message(
        self, body: Dict[str, Any], text_fields: list[str]
    ) -> Dict[str, Any]:
        """Replace all text fields with safe message."""
        safe_message = (
            "🛡️ I apologize, but I cannot provide that information. "
            "How can I help you with your code today?"
        )

        for field in text_fields:
            if field in body:
                body[field] = safe_message

        return body

    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    async def _ensure_detectors_loaded(self):
        """Initialize all security detectors"""
        if self.pii_detector is None:
            self.pii_detector = PIIDetector()

        if self.secret_detector is None:
            self.secret_detector = SecretDetector()

        # SECURITY ENHANCEMENT: initialize keyword blocker
        if self.keyword_blocker is None:
            self.keyword_blocker = KeywordBlocker()

        # SECURITY ENHANCEMENT: initialize guard LLM
        if self.guard_llm is None:
            self.guard_llm = GuardLLM()

        if self.default_policy is None:
            db = get_db()
            policy_data = await db.policies.find_one({"is_default": True})
            if policy_data:
                self.default_policy = PolicySet(**policy_data)

    async def _check_access_control(
        self, file_path: str, user_role: str, policies: list[PolicySet]
    ):
        """Check file access permissions"""
        violations = []
        for policy in policies:
            for access_control in policy.access_controls:
                if re.search(access_control.path_pattern, file_path, re.IGNORECASE):
                    if user_role in access_control.denied_roles:
                        violations.append(
                            {
                                "type": "access_denied",
                                "matched_text": file_path,
                                "start_pos": 0,
                                "end_pos": len(file_path),
                                "pattern_id": access_control.rule_id,
                                "pattern_name": f"Access Control: {access_control.description}",
                                "redaction_text": "[ACCESS_DENIED]",
                                "confidence": 1.0,
                                "context": f"User role '{user_role}' denied access to: {file_path}",
                            }
                        )
        return violations

    def _should_filter(self, path: str) -> bool:
        """Check if path requires filtering"""
        return any(path.startswith(protected) for protected in self.PROTECTED_PATHS)

    def _should_block(self, violations) -> bool:
        """Determine if violations should block the request"""
        for v in violations:
            if isinstance(v, dict):
                if v.get("type") == "access_denied":
                    return True
            else:
                if v.type in ["private_key", "access_denied"]:
                    return True
        return False

    async def _get_user_context(self, request: Request):
        """Extract user context from JWT token (SECURITY ENHANCED)"""
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            print("⚠️  MIDDLEWARE: No Bearer token found, using anonymous")
            return "anonymous", "guest"

        token = auth_header[7:].strip()

        # check token format
        if not token or not re.match(r"^[A-Za-z0-9_\-\.]+$", token):
            print("⚠️  MIDDLEWARE: Invalid token format detected")
            return "anonymous", "guest"

        if len(token) > 2000:
            print(f"⚠️  MIDDLEWARE: Token too long ({len(token)} chars)")
            return "anonymous", "guest"

        try:
            import base64

            parts = token.split(".")
            if len(parts) != 3:
                print("⚠️  MIDDLEWARE: Invalid JWT structure")
                return "anonymous", "guest"

            for i, part in enumerate(parts):
                if not re.match(r"^[A-Za-z0-9_\-]+$", part):
                    print(f"⚠️  MIDDLEWARE: Invalid characters in JWT part {i}")
                    return "anonymous", "guest"

            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)

            user_id = claims.get("sub", "anonymous")

            if not isinstance(user_id, str) or not re.match(r"^[a-zA-Z0-9\-_]+$", str(user_id)):
                print("⚠️  MIDDLEWARE: Invalid user_id format")
                return "anonymous", "guest"

            user_role = (
                claims.get("role")
                or claims.get("realm_access", {}).get("roles", ["guest"])[0]
                or claims.get("resource_access", {})
                .get("scribepilot", {})
                .get("roles", ["guest"])[0]
                or "developer"
            )

            if not isinstance(user_role, str) or not re.match(r"^[a-zA-Z0-9_\-]+$", str(user_role)):
                print("⚠️  MIDDLEWARE: Invalid role format")
                user_role = "guest"

            print(f"✅ MIDDLEWARE: Extracted user_id={user_id}, role={user_role}")
            return user_id, user_role

        except Exception as e:
            print(f"⚠️  MIDDLEWARE: Failed to decode JWT: {e}")
            return "anonymous", "guest"

    async def _load_policies(self, user_id: str, user_role: str):
        """Load security policies"""
        if self.default_policy:
            return [self.default_policy]
        return []

    async def _get_request_body(self, request: Request) -> Optional[Dict]:
        """Extract request body"""
        if request.method not in ["POST", "PUT", "PATCH"]:
            return None
        try:
            body = await request.body()
            return json.loads(body.decode())
        except Exception as e:
            print(f"❌ MIDDLEWARE: Failed to parse request body: {e}")
            return None

    async def _get_response_body(self, response: Response) -> Optional[Dict]:
        """Extract response body"""
        try:
            body_bytes = b""
            async for chunk in response.body_iterator:
                body_bytes += chunk
            return json.loads(body_bytes.decode())
        except Exception as e:
            print(f"❌ MIDDLEWARE: Failed to parse response body: {e}")
            return None

    async def _update_request_body(self, request: Request, new_body: Dict):
        """Store filtered request body in request state"""
        request.state.filtered_body = new_body
        return request

    async def _create_filtered_response(
        self, filtered_body: Dict, original_response: Response
    ) -> Response:
        """Create new response with filtered content"""
        return JSONResponse(
            content=filtered_body,
            status_code=original_response.status_code,
            headers=dict(original_response.headers),
        )

    async def _log_security_event(self, user_id: str, event_type: str, violations: list):
        """Log security events to database"""
        db = get_db()
        log_entry = {
            "timestamp": time.time(),
            "user_id": user_id,
            "event_type": event_type,
            "violation_count": len(violations),
            "violations": [
                {
                    "type": v.type if hasattr(v, "type") else v.get("type"),
                    "confidence": v.confidence
                    if hasattr(v, "confidence")
                    else v.get("confidence", 1.0),
                }
                for v in violations[:10]
            ],
        }
        try:
            await db.audit_logs.insert_one(log_entry)
        except Exception as e:
            print(f"⚠️  MIDDLEWARE: Failed to log security event: {e}")

    def get_stats(self) -> Dict:
        """Get security statistics"""
        return self._stats.copy()
