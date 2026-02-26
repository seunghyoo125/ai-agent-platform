from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import time
import base64
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import quote
from uuid import UUID, uuid4

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Path, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from src.api.db import get_conn
from src.api.services.judge import (
    JudgeConfigurationError,
    ProviderJudgeNotReadyError,
    ProviderJudgeRuntimeError,
    compute_agreement,
    get_judge_service,
)
from src.api.services.policy import (
    PolicyContractError,
    parse_profile_contract,
    validate_answer_result,
    validate_criteria_result,
)
from src.api.services.notify import send_webhook_event, webhook_is_enabled
from src.api.services.execution import (
    ExecutionConfigurationError,
    ExecutionRuntimeError,
    get_execution_service,
    validate_agent_invoke_contract,
)

RunType = Literal["eval", "regression", "ab_comparison", "calibration"]
RunStatus = Literal["pending", "running", "completed", "failed", "cancelled"]
AgentType = Literal[
    "search_retrieval",
    "document_generator",
    "dashboard_assistant",
    "triage_classification",
    "analysis",
]
AgentStatus = Literal["backlog", "build", "testing", "production", "retired"]
GenerationMethod = Literal["documents", "prd_schema", "data_fixtures", "manual", "clone", "prod_logs"]
EvaluationMode = Literal["answer", "criteria"]
DifficultyLevel = Literal["easy", "medium", "hard"]
CapabilityType = Literal["retrieval", "synthesis", "reasoning", "extraction"]
ScenarioType = Literal[
    "straightforward",
    "cross_reference",
    "contradiction",
    "version_conflict",
    "authority",
    "temporal",
    "entity_ambiguity",
    "dense_technical",
]
VerificationStatus = Literal["unverified", "verified", "disputed"]
IssueStatus = Literal[
    "detected",
    "diagnosed",
    "assigned",
    "in_progress",
    "fixed",
    "verifying",
    "resolved",
    "regressed",
    "wont_fix",
]
IssuePriority = Literal["critical", "high", "medium", "low"]
RootCauseType = Literal["retrieval", "prompt", "data", "model", "config"]
ReadinessDecision = Literal["go", "no_go", "deferred"]
ActivitySeverity = Literal["info", "warning", "error"]
SloViolationSource = Literal["run_execute", "run_compare"]
SloViolationStatus = Literal["open", "resolved"]
LaunchDecisionAction = Literal["go", "no_go", "deferred"]
ApiKeyRole = Literal["admin", "member", "viewer"]
RunRefKind = Literal["baseline", "candidate"]
LaunchCertificationStatus = Literal["certified", "blocked"]
NotificationOutboxStatus = Literal["pending", "sending", "sent", "dead"]
ReviewStatus = Literal["unreviewed", "accepted", "overridden"]
ReviewDecision = Literal["accept", "override"]

OPENAPI_TAGS = [
    {"name": "System", "description": "Health checks, API keys, and system audit endpoints."},
    {"name": "Agents", "description": "Agent registry and agent-level summaries."},
    {"name": "Evaluation", "description": "Eval run creation, execution, status, results, and compare."},
    {"name": "Golden Sets", "description": "Golden set upload and list APIs."},
    {"name": "Calibration", "description": "Judge calibration run APIs."},
    {"name": "Issue Patterns", "description": "Pattern creation, transitions, and history."},
    {"name": "Guardrails", "description": "SLO policies, violations, and launch gate checks."},
    {"name": "Operations", "description": "Readiness tracking, decisions, and activity feed APIs."},
]

app = FastAPI(title="Greenlight API", version="v1", openapi_tags=OPENAPI_TAGS)
REQUEST_ID_CTX: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
ROLE_RANK: Dict[str, int] = {"viewer": 1, "member": 2, "admin": 3}
API_KEY_DEFAULT_TTL_DAYS = int(os.getenv("API_KEY_DEFAULT_TTL_DAYS", "90"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "120"))
_RATE_LIMIT_STATE: Dict[str, Dict[str, Any]] = {}
SUPPORTED_GATE_EVALUATORS = {"calibration_freshness", "golden_set_quality"}
SUPPORTED_EVALUATOR_KINDS = {"judge_service"}
SUPPORTED_RUN_TYPE_HANDLERS = {"default", "sync_only", "async_only"}


def _parse_semver(version: str) -> Optional[tuple[int, int, int]]:
    raw = (version or "").strip()
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:
        return None


_CONTRACT_DEFINITION_META: Dict[str, Dict[str, str]] = {
    "gate": {
        "definition_table": "public.gate_definitions",
        "definition_id_col": "id",
        "binding_table": "public.agent_gate_bindings",
        "binding_definition_fk_col": "gate_definition_id",
    },
    "evaluator": {
        "definition_table": "public.evaluator_definitions",
        "definition_id_col": "id",
        "binding_table": "public.agent_evaluator_bindings",
        "binding_definition_fk_col": "evaluator_definition_id",
    },
    "run_type": {
        "definition_table": "public.run_type_definitions",
        "definition_id_col": "id",
        "binding_table": "public.agent_run_type_bindings",
        "binding_definition_fk_col": "run_type_definition_id",
    },
}


class EvalRunCancelledError(Exception):
    pass


class EvalRunStateTransitionError(Exception):
    pass


def _derive_openapi_tag(path: str) -> Optional[str]:
    if path == "/health" or path.startswith("/api/system/"):
        return "System"
    if path.startswith("/api/eval/"):
        return "Evaluation"
    if path.startswith("/api/evaluator-") or "/evaluator-bindings" in path:
        return "Evaluation"
    if path.startswith("/api/run-type-") or "/run-type-bindings" in path:
        return "Evaluation"
    if path.startswith("/api/calibration/") or "/calibration/" in path:
        return "Calibration"
    if path.startswith("/api/golden-sets/") or path.endswith("/golden-sets"):
        return "Golden Sets"
    if "/patterns" in path:
        return "Issue Patterns"
    if "/slo-" in path or "/launch-" in path:
        return "Guardrails"
    if path.startswith("/api/gate-") or "/gate-bindings" in path:
        return "Guardrails"
    if path.endswith("/readiness") or path.endswith("/activity"):
        return "Operations"
    if path.startswith("/api/agents"):
        return "Agents"
    return None


def _derive_operation_id(path: str, method: str) -> str:
    normalized = path.strip("/")
    for prefix in ("api/v1/", "api/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    normalized = normalized.replace("{", "by_").replace("}", "")
    normalized = normalized.replace("/", "_").replace("-", "_")
    normalized = normalized or "root"
    return f"{method.lower()}_{normalized}"


def custom_openapi() -> Dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
    components = schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["BearerAuth"] = {"type": "http", "scheme": "bearer", "bearerFormat": "APIKey"}

    for path, methods in schema.get("paths", {}).items():
        tag = _derive_openapi_tag(path)
        for method, operation in methods.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            operation["operationId"] = _derive_operation_id(path, method)
            if tag and not operation.get("tags"):
                operation["tags"] = [tag]
            if path.startswith("/api/"):
                operation.setdefault("security", [{"BearerAuth": []}])

    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi


def _error(code: str, message: str, http_status: int) -> None:
    raise HTTPException(
        status_code=http_status,
        detail={"ok": False, "error": {"code": code, "message": message}},
    )


def _api_key_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _current_request_id() -> Optional[str]:
    return REQUEST_ID_CTX.get()


def _coerce_uuid_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(UUID(str(value)))
    except Exception:
        return None


def _validate_db_api_key(token: str, touch_last_used: bool = True) -> Optional[Dict[str, Any]]:
    token_hash = _api_key_hash(token)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id, org_id, name, role::text
                    from public.api_keys
                    where key_hash = %s
                      and status = 'active'
                      and (expires_at is null or expires_at > now())
                    limit 1
                    """,
                    (token_hash,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                if row[1] is None and str(row[3]) != "admin":
                    return None
                if touch_last_used:
                    cur.execute("update public.api_keys set last_used_at = now() where id = %s", (row[0],))
                return {
                    "key_id": str(row[0]),
                    "org_id": str(row[1]) if row[1] is not None else None,
                    "name": row[2],
                    "role": str(row[3]),
                }
    except Exception:
        return None


def require_api_key(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        _error(
            code="UNAUTHORIZED",
            message="Missing or invalid Authorization header.",
            http_status=status.HTTP_401_UNAUTHORIZED,
        )
    token = authorization.removeprefix("Bearer ").strip()

    # Primary auth source: hashed keys in DB.
    key_ctx = _validate_db_api_key(token)
    if key_ctx:
        return key_ctx

    _error(
        code="UNAUTHORIZED",
        message="Invalid API key.",
        http_status=status.HTTP_401_UNAUTHORIZED,
    )
    return {}


def _assert_min_role(api_key_ctx: Dict[str, Any], required_role: ApiKeyRole) -> None:
    actual_role = str(api_key_ctx.get("role", "viewer"))
    actual_rank = ROLE_RANK.get(actual_role, 0)
    required_rank = ROLE_RANK.get(required_role, 999)
    if actual_rank < required_rank:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "ok": False,
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Insufficient role for this operation.",
                    "details": {"required_role": required_role, "actual_role": actual_role},
                },
            },
        )


def _caller_org_id(api_key_ctx: Dict[str, Any]) -> Optional[str]:
    raw = api_key_ctx.get("org_id")
    return str(raw) if raw is not None else None


def _assert_org_access(api_key_ctx: Dict[str, Any], target_org_id: Optional[str], context: str = "resource") -> None:
    caller_org = _caller_org_id(api_key_ctx)
    if not caller_org:
        return
    if not target_org_id or str(target_org_id) != caller_org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "ok": False,
                "error": {
                    "code": "FORBIDDEN_ORG_SCOPE",
                    "message": f"Access denied for org-scoped key on {context}.",
                    "details": {"caller_org_id": caller_org, "target_org_id": target_org_id},
                },
            },
        )


def _effective_org_for_scope(api_key_ctx: Dict[str, Any], requested_org_id: Optional[UUID], context: str) -> Optional[str]:
    caller_org = _caller_org_id(api_key_ctx)
    if caller_org:
        target = str(requested_org_id) if requested_org_id is not None else caller_org
        _assert_org_access(api_key_ctx, target, context=context)
        return target
    return str(requested_org_id) if requested_org_id is not None else None


def require_viewer(api_key_ctx: Dict[str, Any] = Depends(require_api_key)) -> Dict[str, Any]:
    _assert_min_role(api_key_ctx, "viewer")
    return api_key_ctx


def require_member(api_key_ctx: Dict[str, Any] = Depends(require_api_key)) -> Dict[str, Any]:
    _assert_min_role(api_key_ctx, "member")
    return api_key_ctx


def require_admin(api_key_ctx: Dict[str, Any] = Depends(require_api_key)) -> Dict[str, Any]:
    _assert_min_role(api_key_ctx, "admin")
    return api_key_ctx


def require_idempotency_key(idempotency_key: str = Header(..., alias="Idempotency-Key", max_length=200)) -> str:
    key = idempotency_key.strip()
    if not key:
        _error("IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key header is required for this operation.", status.HTTP_400_BAD_REQUEST)
    return key


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-Id") or str(uuid4())
    token = REQUEST_ID_CTX.set(request_id)
    try:
        response = await call_next(request)
    finally:
        REQUEST_ID_CTX.reset(token)
    response.headers["X-Request-Id"] = request_id
    return response


@app.middleware("http")
async def api_versioning_middleware(request: Request, call_next):
    original_path = request.url.path
    request.state.api_requested_path = original_path
    request.state.api_is_v1 = original_path.startswith("/api/v1/")
    request.state.api_is_legacy = original_path.startswith("/api/")

    # Canonical routing: /api/v1/* is internally served by /api/* handlers.
    if request.state.api_is_v1:
        request.scope["path"] = "/api" + original_path[len("/api/v1") :]

    response = await call_next(request)

    if request.state.api_is_v1 or request.state.api_is_legacy:
        response.headers["X-API-Version"] = "v1"
        if request.state.api_is_legacy and not request.state.api_is_v1:
            response.headers["Deprecation"] = "true"

    return response


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if RATE_LIMIT_PER_MINUTE <= 0 or not request.url.path.startswith("/api/"):
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        key_ctx = _validate_db_api_key(token, touch_last_used=False)
        key = f"key:{key_ctx.get('key_id')}" if key_ctx else f"anon:{request.client.host if request.client else 'unknown'}"
    else:
        key = f"anon:{request.client.host if request.client else 'unknown'}"

    now_bucket = int(time.time() // 60)
    state = _RATE_LIMIT_STATE.get(key)
    if state is None or int(state.get("bucket", -1)) != now_bucket:
        state = {"bucket": now_bucket, "count": 0}
        _RATE_LIMIT_STATE[key] = state
    state["count"] = int(state.get("count", 0)) + 1

    if int(state["count"]) > RATE_LIMIT_PER_MINUTE:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": "60"},
            content={
                "ok": False,
                "error": {
                    "code": "RATE_LIMITED",
                    "message": "Rate limit exceeded. Retry after 60 seconds.",
                },
            },
        )

    return await call_next(request)


@app.middleware("http")
async def idempotency_middleware(request: Request, call_next):
    # Apply idempotency only to mutating API requests with explicit key header.
    if request.method not in {"POST", "PATCH", "PUT", "DELETE"} or not request.url.path.startswith("/api/"):
        return await call_next(request)

    idem_key = request.headers.get("Idempotency-Key")
    if not idem_key:
        return await call_next(request)

    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return await call_next(request)
    token = authorization.removeprefix("Bearer ").strip()
    key_ctx = _validate_db_api_key(token)
    if not key_ctx:
        return await call_next(request)

    body = await request.body()
    req_hash = _hash_bytes(body)

    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(request.scope, _receive)
    api_key_id = key_ctx.get("key_id")
    method = request.method
    path = request.url.path

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select request_hash, status::text, response_status, response_body
                    from public.idempotency_keys
                    where api_key_id = %s and method = %s and path = %s and idempotency_key = %s
                    limit 1
                    """,
                    (str(api_key_id), method, path, idem_key),
                )
                existing = cur.fetchone()

                if existing:
                    existing_hash = existing[0]
                    existing_status = existing[1]
                    existing_code = existing[2]
                    existing_body = existing[3]
                    if existing_hash != req_hash:
                        resp = JSONResponse(
                            status_code=status.HTTP_409_CONFLICT,
                            content={
                                "ok": False,
                                "error": {
                                    "code": "IDEMPOTENCY_KEY_REUSED",
                                    "message": "Idempotency-Key was already used with a different request payload.",
                                },
                            },
                        )
                        req_id = _current_request_id()
                        if req_id:
                            resp.headers["X-Request-Id"] = req_id
                        return resp
                    if existing_status == "completed" and existing_code is not None and existing_body is not None:
                        resp = JSONResponse(status_code=int(existing_code), content=existing_body)
                        req_id = _current_request_id()
                        if req_id:
                            resp.headers["X-Request-Id"] = req_id
                        return resp
                    resp = JSONResponse(
                        status_code=status.HTTP_409_CONFLICT,
                        content={
                            "ok": False,
                            "error": {
                                "code": "IDEMPOTENCY_IN_PROGRESS",
                                "message": "An identical request is currently in progress. Retry shortly.",
                            },
                        },
                    )
                    req_id = _current_request_id()
                    if req_id:
                        resp.headers["X-Request-Id"] = req_id
                    return resp

                cur.execute(
                    """
                    insert into public.idempotency_keys (
                        api_key_id, method, path, idempotency_key, request_hash, status
                    )
                    values (%s, %s, %s, %s, %s, 'in_progress'::public.idempotency_status)
                    """,
                    (str(api_key_id), method, path, idem_key, req_hash),
                )
    except Exception:
        # Best-effort: if idempotency infra fails, do not block product flow.
        return await call_next(request)

    response = await call_next(request)
    body_bytes = b""
    async for chunk in response.body_iterator:
        body_bytes += chunk

    headers = dict(response.headers)
    media_type = response.media_type or headers.get("content-type")
    final_response: Response = Response(
        content=body_bytes,
        status_code=response.status_code,
        headers=headers,
        media_type=media_type,
    )
    req_id = _current_request_id()
    if req_id:
        final_response.headers["X-Request-Id"] = req_id

    decoded = body_bytes.decode("utf-8", errors="replace") if body_bytes else "{}"
    try:
        parsed_body = json.loads(decoded) if decoded else {}
    except Exception:
        parsed_body = {"ok": False, "error": {"code": "NON_JSON_RESPONSE", "message": decoded[:2000]}}

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update public.idempotency_keys
                    set
                        status = 'completed'::public.idempotency_status,
                        response_status = %s,
                        response_body = %s::jsonb,
                        completed_at = now()
                    where api_key_id = %s and method = %s and path = %s and idempotency_key = %s
                    """,
                    (response.status_code, json.dumps(parsed_body), str(api_key_id), method, path, idem_key),
                )
    except Exception:
        pass

    return final_response


@app.middleware("http")
async def api_audit_middleware(request: Request, call_next):
    if request.method not in {"POST", "PATCH", "PUT", "DELETE"} or not request.url.path.startswith("/api/"):
        return await call_next(request)

    started = time.perf_counter()
    auth_header = request.headers.get("Authorization", "")
    key_ctx: Optional[Dict[str, Any]] = None
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        key_ctx = _validate_db_api_key(token, touch_last_used=False)

    response = await call_next(request)
    latency_ms = int(round((time.perf_counter() - started) * 1000))
    request_id = response.headers.get("X-Request-Id") or request.headers.get("X-Request-Id") or str(uuid4())

    error_code: Optional[str] = None
    raw_body = getattr(response, "body", None)
    if isinstance(raw_body, (bytes, bytearray)) and raw_body:
        try:
            parsed = json.loads(bytes(raw_body).decode("utf-8"))
            if isinstance(parsed, dict):
                err = parsed.get("error")
                if isinstance(err, dict):
                    code = err.get("code")
                    if code is not None:
                        error_code = str(code)
        except Exception:
            pass

    _record_api_audit_log(
        request_id=request_id,
        api_key_id=key_ctx.get("key_id") if key_ctx else None,
        org_id=key_ctx.get("org_id") if key_ctx else None,
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        latency_ms=latency_ms,
        error_code=error_code,
    )
    return response


class EvalRunCreateRequest(BaseModel):
    org_id: UUID
    agent_id: UUID
    golden_set_id: Optional[UUID] = None
    template_id: Optional[UUID] = None
    name: str = Field(min_length=1, max_length=255)
    type: RunType
    config: Dict[str, Any] = Field(default_factory=dict)
    design_context: Dict[str, Any] = Field(default_factory=dict)


class EvalRunCreateData(BaseModel):
    run_id: UUID
    status: RunStatus
    created_at: datetime


class EvalTemplateCreateRequest(BaseModel):
    org_id: UUID
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = None
    run_type: RunType = "eval"
    agent_type: Optional[AgentType] = None
    default_golden_set_id: Optional[UUID] = None
    config: Dict[str, Any] = Field(default_factory=dict)
    design_context: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True


class EvalTemplateItem(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    description: Optional[str]
    run_type: RunType
    agent_type: Optional[AgentType]
    default_golden_set_id: Optional[UUID]
    config: Dict[str, Any]
    design_context: Dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime


class EvalTemplateListData(BaseModel):
    items: List[EvalTemplateItem]
    count: int
    limit: int
    offset: int


class EvalTemplateCreateResponse(BaseModel):
    ok: bool
    data: EvalTemplateItem


class EvalTemplateListResponse(BaseModel):
    ok: bool
    data: EvalTemplateListData


class EvalTemplateDetailResponse(BaseModel):
    ok: bool
    data: EvalTemplateItem


class EvalRunResultItem(BaseModel):
    id: UUID
    case_id: Optional[UUID]
    evaluation_mode: str
    match_type: str
    answer_correct: Optional[str]
    source_correct: Optional[str]
    response_quality: Optional[str]
    overall_score: Optional[str]
    created_at: datetime


class EvalRunResultDetailItem(BaseModel):
    id: UUID
    eval_run_id: UUID
    case_id: Optional[UUID]
    agent_id: UUID
    evaluation_mode: str
    actual_response: Optional[str]
    actual_sources: Optional[str]
    answer_correct: Optional[str]
    answer_issues: List[str]
    source_correct: Optional[str]
    source_issues: List[str]
    response_quality: Optional[str]
    quality_issues: List[str]
    criteria_results: Optional[Any]
    dimension_scores: Optional[Dict[str, Any]]
    overall_score: Optional[str]
    reasoning: Optional[str]
    tester: Optional[str]
    search_mode: Optional[str]
    eval_date: Optional[str]
    notes: Optional[str]
    match_type: str
    matched_case_id: Optional[UUID]
    created_at: datetime


class EvalRunReviewQueueItem(BaseModel):
    id: UUID
    eval_run_id: UUID
    case_id: Optional[UUID]
    agent_id: UUID
    evaluation_mode: EvaluationMode
    answer_correct: Optional[str]
    source_correct: Optional[str]
    response_quality: Optional[str]
    overall_score: Optional[str]
    reasoning: Optional[str]
    review_status: ReviewStatus
    review_decision: Optional[ReviewDecision]
    review_reason: Optional[str]
    review_override: Dict[str, Any]
    reviewed_by_api_key_id: Optional[UUID]
    reviewed_at: Optional[datetime]
    review_diff: Dict[str, Any]
    created_at: datetime


class EvalRunResultReviewRequest(BaseModel):
    decision: ReviewDecision
    reason: Optional[str] = None
    override: Dict[str, Any] = Field(default_factory=dict)


class EvalRunResultReviewData(BaseModel):
    run_id: UUID
    result_id: UUID
    review_status: ReviewStatus
    review_decision: ReviewDecision
    review_reason: Optional[str]
    review_override: Dict[str, Any]
    reviewed_by_api_key_id: Optional[UUID]
    reviewed_at: datetime
    review_diff: Dict[str, Any]


class EvalRunArtifactItem(BaseModel):
    id: UUID
    eval_run_id: UUID
    eval_result_id: Optional[UUID]
    case_id: Optional[UUID]
    agent_id: UUID
    evaluation_mode: EvaluationMode
    judge_mode: str
    judge_model: Optional[str]
    judge_prompt_version: Optional[str]
    judge_prompt_hash: str
    executor_mode: str
    case_latency_ms: Optional[float]
    execution_latency_ms: Optional[float]
    judge_latency_ms: Optional[float]
    token_usage: Dict[str, Any]
    judge_input: Dict[str, Any]
    judge_output: Dict[str, Any]
    execution_trace: Dict[str, Any]
    created_at: datetime


class EvalRunData(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    golden_set_id: Optional[UUID]
    name: str
    type: RunType
    status: RunStatus
    config: Dict[str, Any]
    design_context: Dict[str, Any]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    failure_reason: Optional[str]
    result_count: int
    results: Optional[List[EvalRunResultItem]] = None


class EvalRunSummaryData(BaseModel):
    run_id: UUID
    status: RunStatus
    total_results: int
    answer_yes_count: int
    answer_partially_count: int
    answer_no_count: int
    source_yes_count: int
    source_partially_count: int
    source_no_count: int
    quality_good_count: int
    quality_average_count: int
    quality_not_good_count: int
    answer_yes_rate: float
    source_yes_rate: float
    quality_good_rate: float
    created_at: datetime
    completed_at: Optional[datetime]


class EvalRunListItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    golden_set_id: Optional[UUID]
    name: str
    type: RunType
    status: RunStatus
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    failure_reason: Optional[str]
    result_count: int
    answer_yes_rate: float
    source_yes_rate: float
    quality_good_rate: float


class EvalRunListData(BaseModel):
    items: List[EvalRunListItem]
    count: int
    total_count: int
    limit: int
    offset: int


class EvalRunRegressionItem(BaseModel):
    case_id: UUID
    evaluation_mode: str
    metric: str
    baseline_value: str
    candidate_value: str


class EvalRunComparisonData(BaseModel):
    baseline_run_id: UUID
    candidate_run_id: UUID
    agent_id: UUID
    baseline_summary: EvalRunSummaryData
    candidate_summary: EvalRunSummaryData
    total_compared_cases: int
    regression_count: int
    regressions: List[EvalRunRegressionItem]
    answer_yes_rate_delta: float
    source_yes_rate_delta: float
    quality_good_rate_delta: float
    auto_pattern: Optional[Dict[str, Any]] = None
    notification: Optional[Dict[str, Any]] = None
    slo: Optional[Dict[str, Any]] = None
    remediation: Optional[Dict[str, Any]] = None


class CalibrationCaseComparison(BaseModel):
    case_id: Optional[UUID] = None
    human_label: str = Field(min_length=1)
    judge_label: str = Field(min_length=1)
    is_clean: bool = False
    notes: Optional[str] = None


class CalibrationRunCreateRequest(BaseModel):
    org_id: UUID
    agent_id: UUID
    prompt_version: str = Field(min_length=1, max_length=255)
    judge_model: str = Field(min_length=1, max_length=255)
    per_case_comparison: List[CalibrationCaseComparison] = Field(min_length=1)


class CalibrationRunData(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    prompt_version: str
    judge_model: str
    overall_agreement: float
    clean_agreement: Optional[float]
    per_case_comparison: List[Dict[str, Any]]
    created_at: datetime


class EvalRunExecuteData(BaseModel):
    run_id: UUID
    status: RunStatus
    case_count: int
    completed_at: datetime
    slo_status: Optional[str] = None
    slo_violations: List[Dict[str, Any]] = Field(default_factory=list)


class EvalRunQueueStartData(BaseModel):
    job_id: UUID
    run_id: UUID
    status: str
    enqueued: bool = True
    attempt_count: int
    max_attempts: int
    created_at: datetime


class EvalRunQueueCancelData(BaseModel):
    run_id: UUID
    cancelled: bool
    job_id: Optional[UUID]
    status: Optional[str]


class EvalRunEventItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    event_type: str
    severity: ActivitySeverity
    title: str
    details: Optional[str]
    metadata: Dict[str, Any]
    created_at: datetime


class EvalRunEventsData(BaseModel):
    run_id: UUID
    items: List[EvalRunEventItem]
    count: int
    total_count: int
    limit: int
    offset: int


class QueueStatsData(BaseModel):
    org_id: Optional[UUID]
    queued_count: int
    running_count: int
    succeeded_count: int
    failed_count: int
    cancelled_count: int
    retry_backlog_count: int
    oldest_queued_age_seconds: Optional[int]
    checked_at: datetime


class QueueJobItem(BaseModel):
    job_id: UUID
    run_id: UUID
    org_id: UUID
    agent_id: Optional[UUID]
    run_name: Optional[str]
    run_status: Optional[str]
    job_status: str
    attempt_count: int
    max_attempts: int
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime]


class QueueJobListData(BaseModel):
    items: List[QueueJobItem]
    count: int
    total_count: int
    limit: int
    offset: int


class QueueJobRetryData(BaseModel):
    job_id: UUID
    run_id: UUID
    status: str
    attempt_count: int
    max_attempts: int
    not_before: Optional[datetime]


class QueueJobCancelData(BaseModel):
    job_id: UUID
    run_id: UUID
    status: str
    cancelled: bool


class QueueJobsReplayData(BaseModel):
    org_id: Optional[UUID]
    dry_run: bool
    requested_limit: int
    delay_seconds: int
    selected_count: int
    replayed_count: int
    job_ids: List[UUID]


class QueueJobsReapItem(BaseModel):
    job_id: UUID
    run_id: UUID
    org_id: UUID
    agent_id: Optional[UUID]
    reason: str


class QueueJobsReapStaleData(BaseModel):
    org_id: Optional[UUID]
    dry_run: bool
    stale_heartbeat_seconds: int
    max_runtime_seconds: int
    requested_limit: int
    selected_count: int
    reaped_count: int
    items: List[QueueJobsReapItem]


class QueueJobsPruneData(BaseModel):
    org_id: Optional[UUID]
    dry_run: bool
    retention_days: int
    requested_limit: int
    selected_count: int
    deleted_count: int
    job_ids: List[UUID]


class QueueMaintenancePolicyData(BaseModel):
    org_id: UUID
    stale_heartbeat_seconds: int
    max_runtime_seconds: int
    retention_days: int
    reap_limit: int
    prune_limit: int
    schedule_alert_enabled: bool = False
    schedule_alert_dedupe_hit_rate_threshold: float = 0.7
    schedule_alert_min_execution_success_rate: float = 0.9
    schedule_alert_cooldown_minutes: int = 60
    updated_by_api_key_id: Optional[UUID]
    created_at: datetime
    updated_at: datetime


class QueueMaintenancePolicyUpsertRequest(BaseModel):
    org_id: UUID
    stale_heartbeat_seconds: int = Field(default=60, ge=5, le=86400)
    max_runtime_seconds: int = Field(default=900, ge=30, le=86400)
    retention_days: int = Field(default=14, ge=1, le=3650)
    reap_limit: int = Field(default=100, ge=1, le=5000)
    prune_limit: int = Field(default=500, ge=1, le=10000)
    schedule_alert_enabled: bool = False
    schedule_alert_dedupe_hit_rate_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    schedule_alert_min_execution_success_rate: float = Field(default=0.9, ge=0.0, le=1.0)
    schedule_alert_cooldown_minutes: int = Field(default=60, ge=0, le=10080)


class QueueMaintenanceRunPolicy(BaseModel):
    stale_heartbeat_seconds: int
    max_runtime_seconds: int
    retention_days: int
    reap_limit: int
    prune_limit: int


class QueueMaintenanceRunData(BaseModel):
    run_id: Optional[UUID] = None
    org_id: UUID
    dry_run: bool
    status: str = "completed"
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None
    triggered_by_api_key_id: Optional[UUID] = None
    policy: QueueMaintenanceRunPolicy
    reap: QueueJobsReapStaleData
    prune: QueueJobsPruneData
    started_at: datetime
    completed_at: datetime


class QueueMaintenanceRunListItem(BaseModel):
    id: UUID
    org_id: UUID
    dry_run: bool
    status: str
    error_message: Optional[str]
    duration_ms: Optional[int]
    triggered_by_api_key_id: Optional[UUID]
    started_at: datetime
    completed_at: Optional[datetime]


class QueueMaintenanceRunListData(BaseModel):
    items: List[QueueMaintenanceRunListItem]
    count: int
    total_count: int
    limit: int
    offset: int


class QueueMaintenanceRunDetailData(BaseModel):
    id: UUID
    org_id: UUID
    dry_run: bool
    status: str
    policy_snapshot: Dict[str, Any]
    reap_summary: Optional[Dict[str, Any]]
    prune_summary: Optional[Dict[str, Any]]
    error_message: Optional[str]
    duration_ms: Optional[int]
    triggered_by_api_key_id: Optional[UUID]
    started_at: datetime
    completed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class QueueMaintenanceReapItem(BaseModel):
    run_id: UUID
    org_id: UUID
    dry_run: bool
    reason: str
    started_at: datetime
    duration_ms: Optional[int]
    status: str


class QueueMaintenanceReapStaleData(BaseModel):
    org_id: Optional[UUID]
    dry_run: bool
    max_runtime_seconds: int
    requested_limit: int
    selected_count: int
    reaped_count: int
    items: List[QueueMaintenanceReapItem]


class QueueMaintenanceScheduleTriggerRequest(BaseModel):
    org_id: UUID
    schedule_name: str = Field(default="default", min_length=1, max_length=80)
    window_minutes: int = Field(default=60, ge=5, le=1440)
    dry_run: bool = False
    force: bool = False
    stale_heartbeat_seconds: Optional[int] = Field(default=None, ge=5, le=86400)
    max_runtime_seconds: Optional[int] = Field(default=None, ge=30, le=86400)
    retention_days: Optional[int] = Field(default=None, ge=1, le=3650)
    reap_limit: Optional[int] = Field(default=None, ge=1, le=500)
    prune_limit: Optional[int] = Field(default=None, ge=1, le=5000)


class QueueMaintenanceScheduleTriggerData(BaseModel):
    org_id: UUID
    schedule_name: str
    window_minutes: int
    window_started_at: datetime
    dedupe_key: str
    executed: bool
    deduped: bool
    run: QueueMaintenanceRunData


class QueueMaintenanceScheduleSummaryData(BaseModel):
    org_id: UUID
    schedule_name: Optional[str]
    window_days: int
    trigger_count: int
    executed_count: int
    deduped_count: int
    dedupe_hit_rate: float
    successful_executions: int
    failed_executions: int
    execution_success_rate: float
    last_triggered_at: Optional[datetime]
    last_executed_run_started_at: Optional[datetime]
    last_executed_run_status: Optional[str]


class QueueMaintenanceScheduleAlertDeliveryData(BaseModel):
    org_id: UUID
    schedule_name: Optional[str]
    window_days: int
    total_notify_events: int
    sent_count: int
    failed_count: int
    suppressed_count: int
    skipped_count: int
    dry_run_count: int
    last_event_at: Optional[datetime]
    last_sent_at: Optional[datetime]
    last_failed_at: Optional[datetime]
    last_suppressed_at: Optional[datetime]
    last_notified_at: Optional[datetime]


class QueueMaintenanceScheduleNotifyRequest(BaseModel):
    org_id: UUID
    schedule_name: Optional[str] = Field(default=None, min_length=1, max_length=80)
    window_days: int = Field(default=30, ge=1, le=365)
    dry_run: bool = True
    force_notify: bool = False


class QueueMaintenanceScheduleNotifyData(BaseModel):
    org_id: UUID
    schedule_name: Optional[str]
    window_days: int
    anomaly_detected: bool
    dedupe_hit_rate: float
    execution_success_rate: float
    threshold_dedupe_hit_rate: float
    threshold_min_execution_success_rate: float
    alerts: List[str]
    dry_run: bool
    notified: bool
    notification: Dict[str, Any]
    summary: QueueMaintenanceScheduleSummaryData


class QueueMaintenanceMetricsData(BaseModel):
    org_id: UUID
    window_days: int
    total_runs: int
    running_count: int
    completed_count: int
    failed_count: int
    dry_run_count: int
    failure_rate: float
    avg_duration_ms: Optional[float]
    p50_duration_ms: Optional[int]
    p95_duration_ms: Optional[int]
    last_run_started_at: Optional[datetime]
    last_run_status: Optional[str]


class NotificationOutboxDrainData(BaseModel):
    picked: int
    sent: int
    failed: int
    dead: int


class NotificationOutboxItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: Optional[UUID]
    event_type: str
    status: NotificationOutboxStatus
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime
    sent_at: Optional[datetime]
    last_error: Optional[str]
    source_request_id: Optional[str]
    created_at: datetime
    updated_at: datetime


class NotificationOutboxListData(BaseModel):
    items: List[NotificationOutboxItem]
    count: int
    total_count: int
    limit: int
    offset: int


class NotificationOutboxRetryData(BaseModel):
    id: UUID
    org_id: UUID
    status: NotificationOutboxStatus
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime


class NotificationOutboxReasonGroup(BaseModel):
    reason: str
    count: int


class NotificationOutboxAgeBucket(BaseModel):
    bucket: str
    count: int


class NotificationOutboxDeadLetterSummaryData(BaseModel):
    org_id: Optional[UUID]
    event_type: Optional[str]
    total_dead: int
    oldest_dead_age_seconds: Optional[int]
    reason_groups: List[NotificationOutboxReasonGroup]
    age_buckets: List[NotificationOutboxAgeBucket]


class AgentListItem(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    description: Optional[str]
    agent_type: str
    status: str
    model: Optional[str]
    api_endpoint: Optional[str]
    owner_user_id: Optional[UUID]
    eval_profile_id: Optional[UUID]
    created_at: datetime
    updated_at: datetime


class AgentCreateRequest(BaseModel):
    org_id: UUID
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    agent_type: AgentType
    status: AgentStatus = "backlog"
    model: Optional[str] = None
    api_endpoint: Optional[str] = None
    owner_user_id: Optional[UUID] = None
    eval_profile_id: Optional[UUID] = None


class AgentInvokeContractValidateRequest(BaseModel):
    endpoint_override: Optional[str] = None
    sample_input: str = Field(default="contract validation probe", min_length=1, max_length=4000)
    timeout_ms: int = Field(default=15000, ge=1000, le=120000)
    headers: Dict[str, str] = Field(default_factory=dict)


class AgentInvokeContractData(BaseModel):
    agent_id: UUID
    endpoint: str
    valid: bool
    issues: List[str]
    status_code: int
    latency_ms: float
    content_type: str
    response_preview: str
    request_hash: str
    response_hash: str
    response_key_used: Optional[str]
    source_key_used: Optional[str]
    extracted_response: str
    extracted_sources: Optional[str]


class AgentLatestRunSummary(BaseModel):
    run_id: UUID
    run_name: str
    run_type: str
    run_status: str
    created_at: datetime
    completed_at: Optional[datetime]
    total_results: int
    answer_yes_count: int
    answer_partially_count: int
    answer_no_count: int
    source_yes_count: int
    source_partially_count: int
    source_no_count: int
    quality_good_count: int
    quality_average_count: int
    quality_not_good_count: int
    answer_yes_rate: float
    source_yes_rate: float
    quality_good_rate: float


class AgentScoreTrendPoint(BaseModel):
    run_id: UUID
    run_name: str
    run_type: RunType
    run_status: RunStatus
    created_at: datetime
    completed_at: Optional[datetime]
    total_results: int
    answer_yes_rate: float
    source_yes_rate: float
    quality_good_rate: float


class AgentScoreTrendData(BaseModel):
    agent_id: UUID
    window_days: int
    items: List[AgentScoreTrendPoint]
    count: int
    total_count: int
    limit: int
    offset: int


class AgentHealthData(BaseModel):
    agent_id: UUID
    org_id: UUID
    can_launch: bool
    blockers: List[str]
    latest_run_id: Optional[UUID]
    latest_run_status: Optional[str]
    latest_completed_run_id: Optional[UUID]
    latest_completed_at: Optional[datetime]
    answer_yes_rate: Optional[float]
    source_yes_rate: Optional[float]
    quality_good_rate: Optional[float]
    active_issue_count: int
    active_critical_issues: int
    open_slo_violations: int
    readiness_pending_items: int
    readiness_decision: Optional[str]
    readiness_decision_date: Optional[str]


class PortfolioHealthAgentItem(BaseModel):
    agent_id: UUID
    name: str
    status: str
    can_launch: bool
    latest_run_status: Optional[str]
    answer_yes_rate: Optional[float]
    source_yes_rate: Optional[float]
    quality_good_rate: Optional[float]
    active_critical_issues: int
    open_slo_violations: int
    readiness_pending_items: int


class PortfolioHealthData(BaseModel):
    org_id: UUID
    total_agents: int
    healthy_agents: int
    blocked_agents: int
    avg_answer_yes_rate: Optional[float]
    avg_source_yes_rate: Optional[float]
    avg_quality_good_rate: Optional[float]
    items: List[PortfolioHealthAgentItem]
    count: int
    limit: int
    offset: int


class AgentGoldenSetItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    name: str
    description: Optional[str]
    generation_method: str
    case_count: int
    created_at: datetime


class IssuePatternItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    title: str
    primary_tag: str
    related_tags: List[str]
    status: IssueStatus
    priority: IssuePriority
    root_cause: Optional[str]
    root_cause_type: Optional[str]
    suggested_fix: Optional[str]
    owner: Optional[str]
    linked_case_ids: List[UUID]
    created_at: datetime
    updated_at: datetime
    resolved_date: Optional[str]


class LaunchReadinessData(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    items: List[Any]
    thresholds: Dict[str, Any]
    decision: Optional[str]
    decision_notes: Optional[str]
    decision_date: Optional[str]
    created_at: datetime
    updated_at: datetime


class PatternHistoryData(BaseModel):
    pattern_id: UUID
    agent_id: UUID
    status: str
    status_history: List[Any]
    updated_at: datetime


class ActivityEventItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    event_type: str
    severity: ActivitySeverity
    title: str
    details: Optional[str]
    metadata: Dict[str, Any]
    created_at: datetime


class ApiAuditLogItem(BaseModel):
    id: UUID
    request_id: str
    api_key_id: Optional[UUID]
    org_id: Optional[UUID]
    method: str
    path: str
    status_code: int
    latency_ms: int
    error_code: Optional[str]
    created_at: datetime


class SloPolicyUpsertRequest(BaseModel):
    min_answer_yes_rate: Optional[float] = None
    min_source_yes_rate: Optional[float] = None
    min_quality_good_rate: Optional[float] = None
    max_run_duration_ms: Optional[int] = None
    max_regression_count: Optional[int] = None
    require_calibration_gate: bool = False
    min_calibration_overall_agreement: float = Field(default=0.7, ge=0.0, le=1.0)
    max_calibration_age_days: int = Field(default=14, ge=1, le=3650)
    require_golden_set_quality_gate: bool = False
    min_verified_case_ratio: float = Field(default=0.7, ge=0.0, le=1.0)
    min_active_case_count: int = Field(default=20, ge=1, le=1_000_000)


class SloPolicyData(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    min_answer_yes_rate: Optional[float]
    min_source_yes_rate: Optional[float]
    min_quality_good_rate: Optional[float]
    max_run_duration_ms: Optional[int]
    max_regression_count: Optional[int]
    require_calibration_gate: bool = False
    min_calibration_overall_agreement: float = 0.7
    max_calibration_age_days: int = 14
    require_golden_set_quality_gate: bool = False
    min_verified_case_ratio: float = 0.7
    min_active_case_count: int = 20
    created_at: datetime
    updated_at: datetime


class SloViolationItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    policy_id: Optional[UUID]
    source: SloViolationSource
    source_ref_id: Optional[UUID]
    metric: str
    actual_value: float
    expected_value: float
    comparator: str
    details: Dict[str, Any]
    created_at: datetime


class LaunchGateData(BaseModel):
    agent_id: UUID
    can_launch: bool
    blockers: List[str]
    latest_run_id: Optional[UUID]
    latest_run_status: Optional[str]
    active_critical_issues: int
    open_slo_violations: int
    readiness_pending_items: int


class LaunchDecisionCreateRequest(BaseModel):
    decision: LaunchDecisionAction
    reason: Optional[str] = None


class LaunchCertificationCreateRequest(BaseModel):
    decision: LaunchDecisionAction = "go"
    reason: Optional[str] = None


class LaunchDecisionItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    decision: LaunchDecisionAction
    reason: Optional[str]
    blockers: List[Any]
    decided_by_api_key_id: Optional[UUID]
    decided_at: datetime
    notification: Optional[Dict[str, Any]] = None


class LaunchCertificationItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    decision: LaunchDecisionAction
    certification_status: LaunchCertificationStatus
    reason: Optional[str]
    blockers: List[Any]
    evidence: Dict[str, Any]
    created_by_api_key_id: Optional[UUID]
    created_at: datetime


class IssuePatternCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    primary_tag: str = Field(min_length=1, max_length=100)
    related_tags: List[str] = Field(default_factory=list)
    status: IssueStatus = "detected"
    priority: IssuePriority = "medium"
    root_cause: Optional[str] = None
    root_cause_type: Optional[RootCauseType] = None
    suggested_fix: Optional[str] = None
    owner: Optional[str] = None
    linked_case_ids: List[UUID] = Field(default_factory=list)
    history: List[Any] = Field(default_factory=list)
    status_history: List[Any] = Field(default_factory=list)
    fix_notes: List[Any] = Field(default_factory=list)
    verification_result: Dict[str, Any] = Field(default_factory=dict)
    resolved_date: Optional[str] = None


class IssuePatternUpdateRequest(BaseModel):
    status: Optional[IssueStatus] = None
    priority: Optional[IssuePriority] = None
    root_cause: Optional[str] = None
    root_cause_type: Optional[RootCauseType] = None
    suggested_fix: Optional[str] = None
    owner: Optional[str] = None
    related_tags: Optional[List[str]] = None
    linked_case_ids: Optional[List[UUID]] = None
    verification_result: Optional[Dict[str, Any]] = None
    resolved_date: Optional[str] = None
    status_note: Optional[str] = None
    force: bool = False


class LaunchReadinessUpsertRequest(BaseModel):
    items: List[Any] = Field(default_factory=list)
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    decision: Optional[ReadinessDecision] = None
    decision_notes: Optional[str] = None
    decision_date: Optional[str] = None


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    org_id: Optional[UUID] = None
    expires_at: Optional[datetime] = None
    role: ApiKeyRole = "member"


class ApiKeyListItem(BaseModel):
    id: UUID
    org_id: Optional[UUID]
    name: str
    role: ApiKeyRole
    key_prefix: str
    status: str
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    created_at: datetime


class GoldenSetCaseUpload(BaseModel):
    input: str = Field(min_length=1)
    expected_output: Optional[str] = None
    acceptable_sources: Optional[str] = None
    evaluation_mode: EvaluationMode = "answer"
    evaluation_criteria: Optional[Any] = None
    difficulty: DifficultyLevel
    capability: CapabilityType
    scenario_type: ScenarioType
    domain: Optional[str] = None
    verification_status: VerificationStatus = "unverified"
    verified_by: Optional[UUID] = None
    verified_date: Optional[str] = None


class GoldenSetCaseItem(BaseModel):
    id: UUID
    golden_set_id: UUID
    input: str
    expected_output: Optional[str]
    acceptable_sources: Optional[str]
    evaluation_mode: EvaluationMode
    evaluation_criteria: Optional[Any]
    difficulty: DifficultyLevel
    capability: CapabilityType
    scenario_type: ScenarioType
    domain: Optional[str]
    verification_status: VerificationStatus
    verified_by: Optional[UUID]
    verified_date: Optional[str]
    version: int
    is_active: bool
    superseded_by: Optional[UUID]
    last_reviewed_at: Optional[datetime]
    review_notes: Optional[str]
    created_at: datetime


class GoldenSetCaseListData(BaseModel):
    golden_set_id: UUID
    items: List[GoldenSetCaseItem]
    count: int
    total_count: int
    limit: int
    offset: int


class GoldenSetCaseListResponse(BaseModel):
    ok: bool
    data: GoldenSetCaseListData


class GoldenSetCaseVerifyRequest(BaseModel):
    verification_status: VerificationStatus
    notes: Optional[str] = None


class GoldenSetCaseVerifyResponse(BaseModel):
    ok: bool
    data: GoldenSetCaseItem


class GoldenSetCaseSupersedeRequest(BaseModel):
    input: str = Field(min_length=1)
    expected_output: Optional[str] = None
    acceptable_sources: Optional[str] = None
    evaluation_mode: EvaluationMode = "answer"
    evaluation_criteria: Optional[Any] = None
    difficulty: DifficultyLevel
    capability: CapabilityType
    scenario_type: ScenarioType
    domain: Optional[str] = None
    verification_status: VerificationStatus = "unverified"
    verified_by: Optional[UUID] = None
    verified_date: Optional[str] = None
    notes: Optional[str] = None


class GoldenSetCaseSupersedeData(BaseModel):
    previous_case_id: UUID
    new_case: GoldenSetCaseItem


class GoldenSetCaseSupersedeResponse(BaseModel):
    ok: bool
    data: GoldenSetCaseSupersedeData


class GoldenSetUploadRequest(BaseModel):
    org_id: UUID
    agent_id: UUID
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    generation_method: GenerationMethod
    source_files: List[Any] = Field(default_factory=list)
    cases: List[GoldenSetCaseUpload] = Field(min_length=1)


class GoldenSetFileUploadRequest(BaseModel):
    org_id: UUID
    agent_id: UUID
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    generation_method: GenerationMethod
    source_files: List[Any] = Field(default_factory=list)
    filename: str = Field(min_length=1, max_length=512)
    file_content_base64: str = Field(min_length=1)


class GoldenSetUploadValidationIssue(BaseModel):
    row: int
    message: str


class GoldenSetUploadValidationReport(BaseModel):
    input_format: str
    total_rows: int
    accepted_rows: int
    rejected_rows: int
    issues: List[GoldenSetUploadValidationIssue]


class HealthData(BaseModel):
    status: str


class HealthResponse(BaseModel):
    ok: bool
    data: HealthData


class EvalRunCreateResponse(BaseModel):
    ok: bool
    data: EvalRunCreateData


class EvalRunExecuteResponse(BaseModel):
    ok: bool
    data: EvalRunExecuteData


class EvalRunQueueStartResponse(BaseModel):
    ok: bool
    data: EvalRunQueueStartData


class EvalRunQueueCancelResponse(BaseModel):
    ok: bool
    data: EvalRunQueueCancelData


class EvalRunEventsResponse(BaseModel):
    ok: bool
    data: EvalRunEventsData


class QueueStatsResponse(BaseModel):
    ok: bool
    data: QueueStatsData


class QueueJobListResponse(BaseModel):
    ok: bool
    data: QueueJobListData


class QueueJobRetryResponse(BaseModel):
    ok: bool
    data: QueueJobRetryData


class QueueJobCancelResponse(BaseModel):
    ok: bool
    data: QueueJobCancelData


class QueueJobsReplayResponse(BaseModel):
    ok: bool
    data: QueueJobsReplayData


class QueueJobsReapStaleResponse(BaseModel):
    ok: bool
    data: QueueJobsReapStaleData


class QueueJobsPruneResponse(BaseModel):
    ok: bool
    data: QueueJobsPruneData


class QueueMaintenancePolicyResponse(BaseModel):
    ok: bool
    data: QueueMaintenancePolicyData


class QueueMaintenanceRunResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceRunData


class QueueMaintenanceRunListResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceRunListData


class QueueMaintenanceRunDetailResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceRunDetailData


class QueueMaintenanceReapStaleResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceReapStaleData


class QueueMaintenanceScheduleTriggerResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceScheduleTriggerData


class QueueMaintenanceScheduleSummaryResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceScheduleSummaryData


class QueueMaintenanceScheduleAlertDeliveryResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceScheduleAlertDeliveryData


class QueueMaintenanceScheduleNotifyResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceScheduleNotifyData


class QueueMaintenanceMetricsResponse(BaseModel):
    ok: bool
    data: QueueMaintenanceMetricsData


class NotificationOutboxDrainResponse(BaseModel):
    ok: bool
    data: NotificationOutboxDrainData


class NotificationOutboxListResponse(BaseModel):
    ok: bool
    data: NotificationOutboxListData


class NotificationOutboxRetryResponse(BaseModel):
    ok: bool
    data: NotificationOutboxRetryData


class NotificationOutboxDeadLetterSummaryResponse(BaseModel):
    ok: bool
    data: NotificationOutboxDeadLetterSummaryData


class EvalRunResponse(BaseModel):
    ok: bool
    data: EvalRunData


class EvalRunListResponse(BaseModel):
    ok: bool
    data: EvalRunListData


class EvalRunResultsData(BaseModel):
    items: List[EvalRunResultDetailItem]
    count: int
    total_count: int
    limit: int
    offset: int


class EvalRunReviewQueueData(BaseModel):
    run_id: UUID
    items: List[EvalRunReviewQueueItem]
    count: int
    total_count: int
    limit: int
    offset: int


class EvalRunArtifactsData(BaseModel):
    run_id: UUID
    items: List[EvalRunArtifactItem]
    count: int
    total_count: int
    limit: int
    offset: int


class EvalRunResultsResponse(BaseModel):
    ok: bool
    data: EvalRunResultsData


class EvalRunReviewQueueResponse(BaseModel):
    ok: bool
    data: EvalRunReviewQueueData


class EvalRunResultReviewResponse(BaseModel):
    ok: bool
    data: EvalRunResultReviewData


class EvalRunArtifactsResponse(BaseModel):
    ok: bool
    data: EvalRunArtifactsData


class EvalRunSummaryResponse(BaseModel):
    ok: bool
    data: EvalRunSummaryData


class EvalRunComparisonResponse(BaseModel):
    ok: bool
    data: EvalRunComparisonData


class CalibrationRunResponse(BaseModel):
    ok: bool
    data: CalibrationRunData


class AgentLatestCalibrationData(BaseModel):
    agent_id: UUID
    latest_calibration: Optional[CalibrationRunData]


class AgentLatestCalibrationResponse(BaseModel):
    ok: bool
    data: AgentLatestCalibrationData


class AgentListData(BaseModel):
    items: List[AgentListItem]
    count: int
    limit: int
    offset: int


class AgentListResponse(BaseModel):
    ok: bool
    data: AgentListData


class AgentDetailResponse(BaseModel):
    ok: bool
    data: AgentListItem


class AgentInvokeContractResponse(BaseModel):
    ok: bool
    data: AgentInvokeContractData


class AgentLatestData(BaseModel):
    agent_id: UUID
    latest_run: Optional[AgentLatestRunSummary]


class AgentLatestResponse(BaseModel):
    ok: bool
    data: AgentLatestData


class AgentScoreTrendResponse(BaseModel):
    ok: bool
    data: AgentScoreTrendData


class AgentHealthResponse(BaseModel):
    ok: bool
    data: AgentHealthData


class PortfolioHealthResponse(BaseModel):
    ok: bool
    data: PortfolioHealthData


class RunRegistryUpsertRequest(BaseModel):
    kind: RunRefKind
    name: str = Field(default="default", min_length=1, max_length=100)
    run_id: UUID
    is_active: bool = True
    notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RunRegistryPromoteRequest(BaseModel):
    candidate_run_id: Optional[UUID] = None
    candidate_ref: Optional[str] = "active"
    baseline_run_id: Optional[UUID] = None
    baseline_name: str = Field(default="default", min_length=1, max_length=100)
    require_clean_compare: bool = True
    clean_compare_window_minutes: int = Field(default=60, ge=1, le=10080)
    notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RunRegistryItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    kind: RunRefKind
    name: str
    run_id: UUID
    is_active: bool
    notes: Optional[str]
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class RunRegistryListData(BaseModel):
    agent_id: UUID
    items: List[RunRegistryItem]
    count: int
    limit: int
    offset: int


class RunRegistryResolveData(BaseModel):
    agent_id: UUID
    kind: RunRefKind
    ref: Optional[RunRegistryItem]


class RunRegistryItemResponse(BaseModel):
    ok: bool
    data: RunRegistryItem


class RunRegistryListResponse(BaseModel):
    ok: bool
    data: RunRegistryListData


class RunRegistryResolveResponse(BaseModel):
    ok: bool
    data: RunRegistryResolveData


class RunRegistryPromoteData(BaseModel):
    agent_id: UUID
    candidate_run_id: UUID
    baseline_ref: RunRegistryItem


class RunRegistryPromoteResponse(BaseModel):
    ok: bool
    data: RunRegistryPromoteData


class GoldenSetUploadData(BaseModel):
    golden_set_id: UUID
    name: str
    case_count: int
    case_ids: List[UUID]
    created_at: datetime
    validation_report: Optional[GoldenSetUploadValidationReport] = None


class GoldenSetUploadResponse(BaseModel):
    ok: bool
    data: GoldenSetUploadData


class AgentGoldenSetListData(BaseModel):
    items: List[AgentGoldenSetItem]
    count: int
    limit: int
    offset: int


class AgentGoldenSetListResponse(BaseModel):
    ok: bool
    data: AgentGoldenSetListData


class ApiKeyCreateData(BaseModel):
    id: UUID
    org_id: Optional[UUID]
    name: str
    role: ApiKeyRole
    key_prefix: str
    status: str
    expires_at: Optional[datetime]
    created_at: datetime
    api_key: str


class ApiKeyCreateResponse(BaseModel):
    ok: bool
    data: ApiKeyCreateData


class ApiKeyListData(BaseModel):
    items: List[ApiKeyListItem]
    count: int
    total_count: int
    limit: int
    offset: int


class ApiKeyListResponse(BaseModel):
    ok: bool
    data: ApiKeyListData


class ApiKeyRevokeData(BaseModel):
    id: UUID
    status: str


class ApiKeyRevokeResponse(BaseModel):
    ok: bool
    data: ApiKeyRevokeData


class ApiAuditLogListData(BaseModel):
    items: List[ApiAuditLogItem]
    count: int
    total_count: int
    limit: int
    offset: int


class ApiAuditLogListResponse(BaseModel):
    ok: bool
    data: ApiAuditLogListData


class AgentSloPolicyData(BaseModel):
    agent_id: UUID
    slo_policy: Optional[SloPolicyData]


class AgentSloPolicyResponse(BaseModel):
    ok: bool
    data: AgentSloPolicyData


class AgentSloStatusData(BaseModel):
    agent_id: UUID
    slo_status: str
    open_violation_count: int
    recent_violations: List[SloViolationItem]


class CalibrationGateStatusData(BaseModel):
    agent_id: UUID
    enabled: bool
    status: str
    reasons: List[str]
    min_overall_agreement: float
    max_age_days: int
    latest_calibration_id: Optional[UUID]
    latest_calibration_created_at: Optional[datetime]
    latest_overall_agreement: Optional[float]


class AgentSloStatusResponse(BaseModel):
    ok: bool
    data: AgentSloStatusData


class CalibrationGateStatusResponse(BaseModel):
    ok: bool
    data: CalibrationGateStatusData


class GoldenSetQualityGateStatusData(BaseModel):
    golden_set_id: UUID
    enabled: bool
    status: str
    reasons: List[str]
    min_verified_case_ratio: float
    min_active_case_count: int
    total_case_count: int
    active_case_count: int
    verified_case_count: int
    verified_case_ratio: float


class GoldenSetQualityGateStatusResponse(BaseModel):
    ok: bool
    data: GoldenSetQualityGateStatusData


class GateDefinitionItem(BaseModel):
    id: UUID
    org_id: Optional[UUID]
    key: str
    name: str
    description: Optional[str]
    evaluator_key: str
    contract_version: str = "1.0.0"
    config_schema: Dict[str, Any]
    default_config: Dict[str, Any]
    applies_to_run_types: List[str]
    is_builtin: bool
    active: bool
    created_at: datetime
    updated_at: datetime


class GateDefinitionListData(BaseModel):
    items: List[GateDefinitionItem]
    count: int
    total_count: int
    limit: int
    offset: int


class GateDefinitionListResponse(BaseModel):
    ok: bool
    data: GateDefinitionListData


class GateDefinitionCreateRequest(BaseModel):
    org_id: UUID
    key: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None
    evaluator_key: str = Field(min_length=1, max_length=120)
    contract_version: str = Field(default="1.0.0", pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    config_schema: Dict[str, Any] = Field(default_factory=dict)
    default_config: Dict[str, Any] = Field(default_factory=dict)
    applies_to_run_types: List[RunType] = Field(default_factory=lambda: ["eval", "regression", "ab_comparison"])
    active: bool = True


class GateDefinitionCreateResponse(BaseModel):
    ok: bool
    data: GateDefinitionItem


class AgentGateBindingItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    gate_definition_id: UUID
    gate_key: str
    gate_name: str
    evaluator_key: str
    definition_contract_version: str = "1.0.0"
    enabled: bool
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class AgentGateBindingListData(BaseModel):
    agent_id: UUID
    items: List[AgentGateBindingItem]
    count: int
    total_count: int
    limit: int
    offset: int


class AgentGateBindingListResponse(BaseModel):
    ok: bool
    data: AgentGateBindingListData


class AgentGateBindingUpsertRequest(BaseModel):
    gate_definition_id: UUID
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)


class AgentGateBindingUpsertData(BaseModel):
    agent_id: UUID
    binding: AgentGateBindingItem


class AgentGateBindingUpsertResponse(BaseModel):
    ok: bool
    data: AgentGateBindingUpsertData


class EvaluatorDefinitionItem(BaseModel):
    id: UUID
    org_id: Optional[UUID]
    key: str
    name: str
    description: Optional[str]
    evaluation_mode: EvaluationMode
    evaluator_kind: str
    contract_version: str = "1.0.0"
    default_config: Dict[str, Any]
    is_builtin: bool
    active: bool
    created_at: datetime
    updated_at: datetime


class EvaluatorDefinitionListData(BaseModel):
    items: List[EvaluatorDefinitionItem]
    count: int
    total_count: int
    limit: int
    offset: int


class EvaluatorDefinitionListResponse(BaseModel):
    ok: bool
    data: EvaluatorDefinitionListData


class EvaluatorDefinitionCreateRequest(BaseModel):
    org_id: UUID
    key: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None
    evaluation_mode: EvaluationMode
    evaluator_kind: str = Field(default="judge_service", min_length=1, max_length=120)
    contract_version: str = Field(default="1.0.0", pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    default_config: Dict[str, Any] = Field(default_factory=dict)
    active: bool = True


class EvaluatorDefinitionCreateResponse(BaseModel):
    ok: bool
    data: EvaluatorDefinitionItem


class AgentEvaluatorBindingItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    evaluator_definition_id: UUID
    evaluation_mode: EvaluationMode
    evaluator_key: str
    evaluator_name: str
    evaluator_kind: str
    definition_contract_version: str = "1.0.0"
    enabled: bool
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class AgentEvaluatorBindingListData(BaseModel):
    agent_id: UUID
    items: List[AgentEvaluatorBindingItem]
    count: int
    total_count: int
    limit: int
    offset: int


class AgentEvaluatorBindingListResponse(BaseModel):
    ok: bool
    data: AgentEvaluatorBindingListData


class AgentEvaluatorBindingUpsertRequest(BaseModel):
    evaluator_definition_id: UUID
    evaluation_mode: EvaluationMode
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)


class AgentEvaluatorBindingUpsertData(BaseModel):
    agent_id: UUID
    binding: AgentEvaluatorBindingItem


class AgentEvaluatorBindingUpsertResponse(BaseModel):
    ok: bool
    data: AgentEvaluatorBindingUpsertData


class RunTypeDefinitionItem(BaseModel):
    id: UUID
    org_id: Optional[UUID]
    run_type: RunType
    key: str
    name: str
    description: Optional[str]
    handler_key: str
    contract_version: str = "1.0.0"
    default_config: Dict[str, Any]
    is_builtin: bool
    active: bool
    created_at: datetime
    updated_at: datetime


class RunTypeDefinitionListData(BaseModel):
    items: List[RunTypeDefinitionItem]
    count: int
    total_count: int
    limit: int
    offset: int


class RunTypeDefinitionListResponse(BaseModel):
    ok: bool
    data: RunTypeDefinitionListData


class RunTypeDefinitionCreateRequest(BaseModel):
    org_id: UUID
    run_type: RunType
    key: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None
    handler_key: str = Field(default="default", min_length=1, max_length=120)
    contract_version: str = Field(default="1.0.0", pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    default_config: Dict[str, Any] = Field(default_factory=dict)
    active: bool = True


class RunTypeDefinitionCreateResponse(BaseModel):
    ok: bool
    data: RunTypeDefinitionItem


class AgentRunTypeBindingItem(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: UUID
    run_type: RunType
    run_type_definition_id: UUID
    definition_key: str
    definition_name: str
    handler_key: str
    definition_contract_version: str = "1.0.0"
    enabled: bool
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class AgentRunTypeBindingListData(BaseModel):
    agent_id: UUID
    items: List[AgentRunTypeBindingItem]
    count: int
    total_count: int
    limit: int
    offset: int


class AgentRunTypeBindingListResponse(BaseModel):
    ok: bool
    data: AgentRunTypeBindingListData


class AgentRunTypeBindingUpsertRequest(BaseModel):
    run_type_definition_id: UUID
    run_type: RunType
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)


class AgentRunTypeBindingUpsertData(BaseModel):
    agent_id: UUID
    binding: AgentRunTypeBindingItem


class AgentRunTypeBindingUpsertResponse(BaseModel):
    ok: bool
    data: AgentRunTypeBindingUpsertData


class ContractValidationIssue(BaseModel):
    severity: Literal["error", "warning"]
    code: str
    message: str
    component: str


class AgentContractStatusData(BaseModel):
    agent_id: UUID
    run_type: RunType
    entrypoint: Literal["start", "execute"]
    golden_set_id: Optional[UUID]
    status: Literal["pass", "fail"]
    issues: List[ContractValidationIssue]
    resolved_handler_key: str
    enabled_gate_binding_count: int
    enabled_evaluator_binding_count: int


class AgentContractStatusResponse(BaseModel):
    ok: bool
    data: AgentContractStatusData


ContractDefinitionType = Literal["gate", "evaluator", "run_type"]
ContractUpgradeRolloutMode = Literal["definition_only", "sync_bindings"]


class ContractUpgradeImpactItem(BaseModel):
    binding_id: UUID
    agent_id: UUID
    definition_contract_version: str
    impact: Literal["none", "warning", "breaking", "invalid"]
    message: str


class ContractUpgradePreviewRequest(BaseModel):
    definition_type: ContractDefinitionType
    definition_id: UUID
    target_contract_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    include_items: bool = True
    max_items: int = Field(default=200, ge=1, le=1000)


class ContractUpgradePreviewData(BaseModel):
    definition_type: ContractDefinitionType
    definition_id: UUID
    definition_key: str
    definition_name: str
    current_contract_version: str
    target_contract_version: str
    impacted_binding_count: int
    breaking_count: int
    warning_count: int
    invalid_count: int
    unchanged_count: int
    status: Literal["safe", "risky"]
    items: List[ContractUpgradeImpactItem]


class ContractUpgradePreviewResponse(BaseModel):
    ok: bool
    data: ContractUpgradePreviewData


class ContractUpgradeApplyRequest(BaseModel):
    definition_type: ContractDefinitionType
    definition_id: UUID
    target_contract_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    rollout_mode: ContractUpgradeRolloutMode = "definition_only"


class ContractUpgradeApplyData(BaseModel):
    definition_type: ContractDefinitionType
    definition_id: UUID
    target_contract_version: str
    rollout_mode: ContractUpgradeRolloutMode
    bindings_updated: int
    preview: ContractUpgradePreviewData


class ContractUpgradeApplyResponse(BaseModel):
    ok: bool
    data: ContractUpgradeApplyData


class ContractDriftItem(BaseModel):
    agent_id: UUID
    definition_type: ContractDefinitionType
    binding_id: UUID
    definition_id: UUID
    definition_key: str
    bound_contract_version: str
    current_contract_version: str
    drift: Literal["none", "warning", "breaking", "invalid"]
    severity: Literal["info", "warning", "error"]
    message: str


class ContractDriftData(BaseModel):
    org_id: UUID
    agent_id: Optional[UUID]
    item_count: int
    breaking_count: int
    warning_count: int
    invalid_count: int
    checked_agent_count: int
    items: List[ContractDriftItem]


class ContractDriftResponse(BaseModel):
    ok: bool
    data: ContractDriftData


class ContractDriftPromotePatternsRequest(BaseModel):
    org_id: UUID
    agent_id: Optional[UUID] = None
    min_drift: Literal["warning", "breaking", "invalid"] = "breaking"
    dry_run: bool = False
    limit: int = Field(default=200, ge=1, le=1000)


class ContractDriftPromotePatternsData(BaseModel):
    org_id: UUID
    agent_id: Optional[UUID]
    min_drift: Literal["warning", "breaking", "invalid"]
    dry_run: bool
    scanned_item_count: int
    eligible_item_count: int
    created_pattern_count: int
    reused_pattern_count: int
    pattern_ids: List[UUID]
    notification: Optional[Dict[str, Any]] = None


class ContractDriftPromotePatternsResponse(BaseModel):
    ok: bool
    data: ContractDriftPromotePatternsData


class ContractDriftPolicyData(BaseModel):
    org_id: UUID
    enabled: bool
    min_drift: Literal["warning", "breaking", "invalid"]
    promote_to_patterns: bool
    scan_limit: int
    schedule_name: str
    schedule_window_minutes: int
    alert_enabled: bool = False
    alert_max_dedupe_hit_rate: float = 0.7
    alert_min_execution_rate: float = 0.5
    alert_cooldown_minutes: int = 60
    updated_by_api_key_id: Optional[UUID]
    created_at: datetime
    updated_at: datetime


class ContractDriftPolicyUpsertRequest(BaseModel):
    org_id: UUID
    enabled: bool = False
    min_drift: Literal["warning", "breaking", "invalid"] = "breaking"
    promote_to_patterns: bool = True
    scan_limit: int = Field(default=200, ge=1, le=1000)
    schedule_name: str = Field(default="daily", min_length=1, max_length=80)
    schedule_window_minutes: int = Field(default=1440, ge=5, le=10080)
    alert_enabled: bool = False
    alert_max_dedupe_hit_rate: float = Field(default=0.7, ge=0.0, le=1.0)
    alert_min_execution_rate: float = Field(default=0.5, ge=0.0, le=1.0)
    alert_cooldown_minutes: int = Field(default=60, ge=0, le=10080)


class ContractDriftPolicyResponse(BaseModel):
    ok: bool
    data: ContractDriftPolicyData


class ContractDriftTriggerRequest(BaseModel):
    org_id: UUID
    schedule_name: str = Field(default="manual", min_length=1, max_length=80)
    window_minutes: int = Field(default=60, ge=5, le=10080)
    dry_run: bool = False
    force: bool = False
    agent_id: Optional[UUID] = None
    min_drift: Optional[Literal["warning", "breaking", "invalid"]] = None
    limit: Optional[int] = Field(default=None, ge=1, le=1000)


class ContractDriftTriggerData(BaseModel):
    org_id: UUID
    schedule_name: str
    window_minutes: int
    window_started_at: datetime
    dedupe_key: str
    executed: bool
    deduped: bool
    policy_enabled: bool
    min_drift: Literal["warning", "breaking", "invalid"]
    scan_limit: int
    dry_run: bool
    reason: Optional[str]
    promote_result: Optional[ContractDriftPromotePatternsData] = None


class ContractDriftTriggerResponse(BaseModel):
    ok: bool
    data: ContractDriftTriggerData


class ContractDriftTriggerEventItem(BaseModel):
    request_id: str
    status_code: int
    error_code: str
    created_at: datetime
    path: str


class ContractDriftTriggerSummaryData(BaseModel):
    org_id: UUID
    schedule_name: Optional[str]
    window_days: int
    trigger_count: int
    executed_count: int
    deduped_count: int
    policy_disabled_count: int
    promotion_disabled_count: int
    execution_rate: float
    dedupe_hit_rate: float
    last_triggered_at: Optional[datetime]
    items: List[ContractDriftTriggerEventItem]
    count: int
    limit: int


class ContractDriftTriggerSummaryResponse(BaseModel):
    ok: bool
    data: ContractDriftTriggerSummaryData


class ContractDriftTriggerAlertDeliveryData(BaseModel):
    org_id: UUID
    schedule_name: Optional[str]
    window_days: int
    total_notify_events: int
    sent_count: int
    failed_count: int
    suppressed_count: int
    skipped_count: int
    dry_run_count: int
    last_event_at: Optional[datetime]
    last_sent_at: Optional[datetime]
    last_failed_at: Optional[datetime]
    last_suppressed_at: Optional[datetime]
    last_notified_at: Optional[datetime]


class ContractDriftTriggerNotifyRequest(BaseModel):
    org_id: UUID
    schedule_name: Optional[str] = Field(default=None, min_length=1, max_length=80)
    agent_id: Optional[UUID] = None
    window_days: int = Field(default=30, ge=1, le=365)
    dry_run: bool = True
    force_notify: bool = False


class ContractDriftTriggerNotifyData(BaseModel):
    org_id: UUID
    schedule_name: Optional[str]
    agent_id: Optional[UUID] = None
    window_days: int
    anomaly_detected: bool
    dedupe_hit_rate: float
    execution_rate: float
    threshold_max_dedupe_hit_rate: float
    threshold_min_execution_rate: float
    alerts: List[str]
    dry_run: bool
    notified: bool
    notification: Dict[str, Any]
    escalation_pattern: Optional[Dict[str, Any]] = None
    summary: ContractDriftTriggerSummaryData


class ContractDriftTriggerAlertDeliveryResponse(BaseModel):
    ok: bool
    data: ContractDriftTriggerAlertDeliveryData


class ContractDriftTriggerNotifyResponse(BaseModel):
    ok: bool
    data: ContractDriftTriggerNotifyData


class ContractDriftScheduleRunRequest(BaseModel):
    org_id: UUID
    schedule_name: Optional[str] = Field(default=None, min_length=1, max_length=80)
    window_minutes: Optional[int] = Field(default=None, ge=5, le=10080)
    summary_window_days: int = Field(default=30, ge=1, le=365)
    dry_run: bool = False
    force: bool = False
    force_notify: bool = False
    agent_id: Optional[UUID] = None
    min_drift: Optional[Literal["warning", "breaking", "invalid"]] = None
    limit: Optional[int] = Field(default=None, ge=1, le=1000)


class ContractDriftScheduleRunData(BaseModel):
    org_id: UUID
    schedule_name: str
    window_minutes: int
    summary_window_days: int
    dry_run: bool
    force: bool
    force_notify: bool
    trigger: ContractDriftTriggerData
    notify: ContractDriftTriggerNotifyData


class ContractDriftScheduleRunResponse(BaseModel):
    ok: bool
    data: ContractDriftScheduleRunData


class SloViolationResolveData(BaseModel):
    agent_id: UUID
    violation_id: UUID
    status: str


class SloViolationResolveResponse(BaseModel):
    ok: bool
    data: SloViolationResolveData


class IssuePatternListData(BaseModel):
    items: List[IssuePatternItem]
    count: int
    limit: int
    offset: int


class IssuePatternListResponse(BaseModel):
    ok: bool
    data: IssuePatternListData


class PatternHistoryResponse(BaseModel):
    ok: bool
    data: PatternHistoryData


class AgentActivityData(BaseModel):
    agent_id: UUID
    items: List[ActivityEventItem]
    count: int
    total_count: int
    limit: int
    offset: int


class AgentActivityResponse(BaseModel):
    ok: bool
    data: AgentActivityData


class AgentReadinessData(BaseModel):
    agent_id: UUID
    readiness: Optional[LaunchReadinessData]


class AgentReadinessResponse(BaseModel):
    ok: bool
    data: AgentReadinessData


class LaunchGateResponse(BaseModel):
    ok: bool
    data: LaunchGateData


class LaunchDecisionListData(BaseModel):
    agent_id: UUID
    items: List[LaunchDecisionItem]
    count: int
    limit: int
    offset: int


class LaunchDecisionListResponse(BaseModel):
    ok: bool
    data: LaunchDecisionListData


class LaunchDecisionCreateData(BaseModel):
    agent_id: UUID
    decision: LaunchDecisionItem
    gate: Dict[str, Any]


class LaunchDecisionCreateResponse(BaseModel):
    ok: bool
    data: LaunchDecisionCreateData


class LaunchCertificationCreateData(BaseModel):
    agent_id: UUID
    certification: LaunchCertificationItem


class LaunchCertificationCreateResponse(BaseModel):
    ok: bool
    data: LaunchCertificationCreateData


class LaunchCertificationListData(BaseModel):
    agent_id: UUID
    items: List[LaunchCertificationItem]
    count: int
    limit: int
    offset: int


class LaunchCertificationListResponse(BaseModel):
    ok: bool
    data: LaunchCertificationListData


class IssuePatternDataWithNotification(IssuePatternItem):
    notification: Optional[Dict[str, Any]] = None


class IssuePatternResponse(BaseModel):
    ok: bool
    data: IssuePatternItem


class IssuePatternUpdateResponse(BaseModel):
    ok: bool
    data: IssuePatternDataWithNotification


_YNP_SCORE_ORDER = {"no": 0, "partially": 1, "yes": 2}
_QUALITY_SCORE_ORDER = {"not_good": 0, "average": 1, "good": 2}
_PATTERN_ALLOWED_TRANSITIONS: Dict[str, set[str]] = {
    "detected": {"diagnosed", "assigned", "wont_fix"},
    "diagnosed": {"assigned", "in_progress", "wont_fix"},
    "assigned": {"in_progress", "diagnosed", "wont_fix"},
    "in_progress": {"fixed", "regressed", "wont_fix"},
    "fixed": {"verifying", "regressed"},
    "verifying": {"resolved", "regressed", "in_progress"},
    "resolved": {"regressed"},
    "regressed": {"assigned", "in_progress", "fixed", "wont_fix"},
    "wont_fix": {"regressed"},
}


def _summary_from_row(row: Any) -> EvalRunSummaryData:
    total = int(row[4])

    def rate(n: int) -> float:
        if total == 0:
            return 0.0
        return n / total

    return EvalRunSummaryData(
        run_id=row[0],
        status=row[1],
        created_at=row[2],
        completed_at=row[3],
        total_results=total,
        answer_yes_count=int(row[5] or 0),
        answer_partially_count=int(row[6] or 0),
        answer_no_count=int(row[7] or 0),
        source_yes_count=int(row[8] or 0),
        source_partially_count=int(row[9] or 0),
        source_no_count=int(row[10] or 0),
        quality_good_count=int(row[11] or 0),
        quality_average_count=int(row[12] or 0),
        quality_not_good_count=int(row[13] or 0),
        answer_yes_rate=rate(int(row[5] or 0)),
        source_yes_rate=rate(int(row[8] or 0)),
        quality_good_rate=rate(int(row[11] or 0)),
    )


def _compute_judge_prompt_hash(
    *,
    judge_mode: str,
    judge_model: Optional[str],
    judge_prompt_version: Optional[str],
    evaluation_mode: str,
) -> str:
    payload = {
        "judge_mode": judge_mode,
        "judge_model": judge_model,
        "judge_prompt_version": judge_prompt_version,
        "evaluation_mode": evaluation_mode,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _public_judge_output_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in raw.items():
        if str(key).startswith("_"):
            continue
        out[str(key)] = value
    return out


def _compute_review_diff(
    *,
    evaluation_mode: str,
    answer_correct: Optional[str],
    source_correct: Optional[str],
    response_quality: Optional[str],
    overall_score: Optional[str],
    review_override: Dict[str, Any],
) -> Dict[str, Any]:
    diff: Dict[str, Any] = {}
    if evaluation_mode == "answer":
        for key, base_val in {
            "answer_correct": answer_correct,
            "source_correct": source_correct,
            "response_quality": response_quality,
        }.items():
            if key in review_override:
                override_val = review_override.get(key)
                if override_val != base_val:
                    diff[key] = {"judge": base_val, "review": override_val}
    else:
        if "overall_score" in review_override and review_override.get("overall_score") != overall_score:
            diff["overall_score"] = {"judge": overall_score, "review": review_override.get("overall_score")}
        if "dimension_scores" in review_override:
            override_dims = review_override.get("dimension_scores")
            if isinstance(override_dims, dict):
                diff["dimension_scores"] = {"review": override_dims}
    return diff


def _is_value_regression(metric: str, baseline_value: Optional[str], candidate_value: Optional[str]) -> bool:
    if baseline_value is None or candidate_value is None:
        return False

    if metric in {"answer_correct", "source_correct"}:
        return _YNP_SCORE_ORDER.get(candidate_value, -1) < _YNP_SCORE_ORDER.get(baseline_value, -1)
    if metric == "response_quality":
        return _QUALITY_SCORE_ORDER.get(candidate_value, -1) < _QUALITY_SCORE_ORDER.get(baseline_value, -1)
    return False


def _append_status_history(
    existing_history: List[Any],
    old_status: str,
    new_status: str,
    note: Optional[str],
) -> List[Any]:
    if old_status == new_status:
        return existing_history
    entry: Dict[str, Any] = {
        "from": old_status,
        "to": new_status,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    if note:
        entry["note"] = note
    return [*existing_history, entry]


def _is_allowed_pattern_transition(from_status: str, to_status: str) -> bool:
    if from_status == to_status:
        return True
    return to_status in _PATTERN_ALLOWED_TRANSITIONS.get(from_status, set())


def _record_activity_event(
    *,
    org_id: UUID,
    agent_id: UUID,
    event_type: str,
    title: str,
    details: Optional[str] = None,
    severity: ActivitySeverity = "info",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    req_id = _current_request_id()
    merged_metadata = dict(metadata or {})
    if req_id and "request_id" not in merged_metadata:
        merged_metadata["request_id"] = req_id

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.activity_events (
                        org_id, agent_id, event_type, severity, title, details, metadata
                    )
                    values (%s, %s, %s, %s::public.activity_severity, %s, %s, %s::jsonb)
                    """,
                    (
                        str(org_id),
                        str(agent_id),
                        event_type,
                        severity,
                        title,
                        details,
                        json.dumps(merged_metadata),
                    ),
                )
    except Exception:
        # Best-effort telemetry; never block core product flows.
        return


def _notification_max_attempts() -> int:
    return int(os.getenv("NOTIFY_OUTBOX_MAX_ATTEMPTS", "5"))


def _notification_retry_base_seconds() -> int:
    return int(os.getenv("NOTIFY_OUTBOX_RETRY_BASE_SECONDS", "30"))


def _notification_retry_max_seconds() -> int:
    return int(os.getenv("NOTIFY_OUTBOX_RETRY_MAX_SECONDS", "1800"))


def _notification_backoff_seconds(attempt_count: int) -> int:
    base = max(1, _notification_retry_base_seconds())
    max_delay = max(base, _notification_retry_max_seconds())
    computed = base * (2 ** max(0, int(attempt_count) - 1))
    return min(computed, max_delay)


def _enqueue_notification_outbox(
    *,
    org_id: UUID,
    agent_id: Optional[UUID],
    event_type: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    request_id = _current_request_id()
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.notification_outbox (
                        org_id, agent_id, event_type, payload, status, attempt_count, max_attempts, next_attempt_at, source_request_id
                    )
                    values (%s, %s, %s, %s::jsonb, 'pending', 0, %s, now(), %s)
                    returning id, status, attempt_count, max_attempts, created_at
                    """,
                    (
                        str(org_id),
                        str(agent_id) if agent_id is not None else None,
                        event_type,
                        json.dumps(payload),
                        _notification_max_attempts(),
                        request_id,
                    ),
                )
                row = cur.fetchone()
                return {
                    "queued": True,
                    "outbox_id": str(row[0]),  # type: ignore[index]
                    "status": str(row[1]),  # type: ignore[index]
                    "attempt_count": int(row[2]),  # type: ignore[index]
                    "max_attempts": int(row[3]),  # type: ignore[index]
                    "created_at": row[4],  # type: ignore[index]
                }
    except Exception as exc:
        return {"queued": False, "error": str(exc)}


def _deliver_notification_outbox_item(
    *,
    outbox_id: UUID,
    event_type: str,
    payload: Dict[str, Any],
    attempt_count: int,
    max_attempts: int,
) -> Dict[str, Any]:
    notify_error = send_webhook_event(event_type, payload, delivery_id=str(outbox_id))
    sent = notify_error is None
    next_status = "sent" if sent else ("dead" if attempt_count >= max_attempts else "pending")
    retry_after_seconds = 0 if sent or next_status == "dead" else _notification_backoff_seconds(attempt_count)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                if sent:
                    cur.execute(
                        """
                        update public.notification_outbox
                        set status = 'sent',
                            sent_at = now(),
                            last_error = null,
                            updated_at = now()
                        where id = %s
                        """,
                        (str(outbox_id),),
                    )
                else:
                    cur.execute(
                        """
                        update public.notification_outbox
                        set status = %s,
                            next_attempt_at = case
                              when %s > 0 then now() + (%s || ' seconds')::interval
                              else now()
                            end,
                            last_error = %s,
                            updated_at = now()
                        where id = %s
                        """,
                        (next_status, retry_after_seconds, retry_after_seconds, str(notify_error)[:2000], str(outbox_id)),
                    )
    except Exception:
        # Keep flow best-effort; if update fails, caller still receives send result.
        pass

    response: Dict[str, Any] = {
        "sent": sent,
        "event_type": event_type,
        "queued": True,
        "outbox_id": str(outbox_id),
        "status": next_status,
        "attempt_count": int(attempt_count),
        "max_attempts": int(max_attempts),
    }
    if notify_error:
        response["error"] = str(notify_error)
    return response


def _dispatch_notification(
    *,
    org_id: UUID,
    agent_id: Optional[UUID],
    event_type: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    if not webhook_is_enabled(event_type):
        return {"event_type": event_type, "queued": False, "sent": False, "skipped": True}

    queued = _enqueue_notification_outbox(org_id=org_id, agent_id=agent_id, event_type=event_type, payload=payload)
    if not queued.get("queued"):
        return {"event_type": event_type, "queued": False, "sent": False, "error": queued.get("error")}

    # Best-effort immediate delivery so UX remains responsive; durable retry stays in outbox on failure.
    if os.getenv("NOTIFY_OUTBOX_SYNC_DELIVERY", "true").strip().lower() not in {"1", "true", "yes", "on"}:
        return {
            "event_type": event_type,
            "queued": True,
            "sent": False,
            "outbox_id": queued["outbox_id"],
            "status": queued["status"],
        }

    return _deliver_notification_outbox_item(
        outbox_id=UUID(str(queued["outbox_id"])),
        event_type=event_type,
        payload=payload,
        attempt_count=int(queued["attempt_count"]),
        max_attempts=int(queued["max_attempts"]),
    )


def _drain_notification_outbox_batch(limit: int = 20) -> Dict[str, int]:
    picked = 0
    sent = 0
    failed = 0
    dead = 0
    limit = max(1, min(int(limit), 200))
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    with picked as (
                        select id
                        from public.notification_outbox
                        where status = 'pending'
                          and next_attempt_at <= now()
                        order by created_at asc, id asc
                        for update skip locked
                        limit %s
                    )
                    update public.notification_outbox n
                    set status = 'sending',
                        attempt_count = n.attempt_count + 1,
                        updated_at = now()
                    from picked p
                    where n.id = p.id
                    returning n.id, n.event_type, n.payload, n.attempt_count, n.max_attempts
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
    except Exception:
        return {"picked": 0, "sent": 0, "failed": 0, "dead": 0}

    for row in rows:
        picked += 1
        result = _deliver_notification_outbox_item(
            outbox_id=UUID(str(row[0])),
            event_type=str(row[1]),
            payload=row[2] or {},
            attempt_count=int(row[3] or 1),
            max_attempts=int(row[4] or _notification_max_attempts()),
        )
        if result.get("sent"):
            sent += 1
        elif result.get("status") == "dead":
            dead += 1
        else:
            failed += 1
    return {"picked": picked, "sent": sent, "failed": failed, "dead": dead}


def _record_api_audit_log(
    *,
    request_id: str,
    api_key_id: Optional[str],
    org_id: Optional[str],
    method: str,
    path: str,
    status_code: int,
    latency_ms: int,
    error_code: Optional[str] = None,
) -> None:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.api_audit_logs (
                        request_id, api_key_id, org_id, method, path, status_code, latency_ms, error_code
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (request_id, api_key_id, org_id, method, path, status_code, latency_ms, error_code),
                )
    except Exception:
        return


def _enqueue_eval_run_job(
    run_id: UUID,
    org_id: UUID,
    max_attempts: int = 3,
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into public.eval_run_jobs (
                    org_id,
                    run_id,
                    status,
                    attempt_count,
                    max_attempts
                )
                values (%s, %s, 'queued', 0, %s)
                on conflict (run_id) where status in ('queued', 'running')
                do nothing
                returning id, run_id, status, attempt_count, max_attempts, created_at
                """,
                (str(org_id), str(run_id), int(max_attempts)),
            )
            row = cur.fetchone()
            if row:
                return {
                    "job_id": row[0],
                    "run_id": row[1],
                    "status": row[2],
                    "enqueued": True,
                    "attempt_count": int(row[3]),
                    "max_attempts": int(row[4]),
                    "created_at": row[5],
                }

            cur.execute(
                """
                select id, run_id, status, attempt_count, max_attempts, created_at
                from public.eval_run_jobs
                where run_id = %s
                  and status in ('queued', 'running')
                limit 1
                """,
                (str(run_id),),
            )
            existing = cur.fetchone()
            if existing:
                return {
                    "job_id": existing[0],
                    "run_id": existing[1],
                    "status": existing[2],
                    "enqueued": False,
                    "attempt_count": int(existing[3]),
                    "max_attempts": int(existing[4]),
                    "created_at": existing[5],
                }
    _error("EVAL_RUN_QUEUE_FAILED", "Could not enqueue eval run job.", status.HTTP_400_BAD_REQUEST)
    return {}


def _cancel_eval_run_job(run_id: UUID) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update public.eval_run_jobs
                set status = 'cancelled',
                    cancelled_at = now(),
                    completed_at = now(),
                    updated_at = now()
                where run_id = %s
                  and status in ('queued', 'running')
                returning id, status
                """,
                (str(run_id),),
            )
            row = cur.fetchone()
            if row:
                return {"cancelled": True, "job_id": row[0], "status": row[1]}
    return {"cancelled": False, "job_id": None, "status": None}


def _is_eval_run_cancel_requested(run_id: UUID) -> bool:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select 1
                    from public.eval_run_jobs
                    where run_id = %s
                      and status = 'cancelled'
                    limit 1
                    """,
                    (str(run_id),),
                )
                return cur.fetchone() is not None
    except Exception:
        return False


def _assert_eval_run_transition_allowed(from_status: str, to_status: str) -> None:
    from_norm = str(from_status)
    to_norm = str(to_status)
    if from_norm == to_norm:
        return
    allowed = {
        "pending": {"running", "cancelled"},
        "running": {"completed", "failed", "cancelled"},
        "completed": {"pending"},
        "failed": {"pending"},
        "cancelled": {"pending"},
    }
    if to_norm not in allowed.get(from_norm, set()):
        raise EvalRunStateTransitionError(f"Invalid eval run status transition: {from_norm} -> {to_norm}")


def _get_queue_maintenance_policy(org_id: UUID) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    org_id,
                    stale_heartbeat_seconds,
                    max_runtime_seconds,
                    retention_days,
                    reap_limit,
                    prune_limit,
                    schedule_alert_enabled,
                    schedule_alert_dedupe_hit_rate_threshold,
                    schedule_alert_min_execution_success_rate,
                    schedule_alert_cooldown_minutes,
                    updated_by_api_key_id,
                    created_at,
                    updated_at
                from public.queue_maintenance_policies
                where org_id = %s
                """,
                (str(org_id),),
            )
            row = cur.fetchone()
            if not row:
                return None
    return {
        "org_id": row[0],
        "stale_heartbeat_seconds": int(row[1]),
        "max_runtime_seconds": int(row[2]),
        "retention_days": int(row[3]),
        "reap_limit": int(row[4]),
        "prune_limit": int(row[5]),
        "schedule_alert_enabled": bool(row[6]),
        "schedule_alert_dedupe_hit_rate_threshold": float(row[7]),
        "schedule_alert_min_execution_success_rate": float(row[8]),
        "schedule_alert_cooldown_minutes": int(row[9]),
        "updated_by_api_key_id": row[10],
        "created_at": row[11],
        "updated_at": row[12],
    }


def _get_contract_drift_policy(org_id: UUID) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    org_id,
                    enabled,
                    min_drift::text,
                    promote_to_patterns,
                    scan_limit,
                    schedule_name,
                    schedule_window_minutes,
                    alert_enabled,
                    alert_max_dedupe_hit_rate,
                    alert_min_execution_rate,
                    alert_cooldown_minutes,
                    updated_by_api_key_id,
                    created_at,
                    updated_at
                from public.contract_drift_policies
                where org_id = %s
                """,
                (str(org_id),),
            )
            row = cur.fetchone()
            if not row:
                return None
    return {
        "org_id": row[0],
        "enabled": bool(row[1]),
        "min_drift": str(row[2]),
        "promote_to_patterns": bool(row[3]),
        "scan_limit": int(row[4]),
        "schedule_name": str(row[5]),
        "schedule_window_minutes": int(row[6]),
        "alert_enabled": bool(row[7]),
        "alert_max_dedupe_hit_rate": float(row[8]),
        "alert_min_execution_rate": float(row[9]),
        "alert_cooldown_minutes": int(row[10]),
        "updated_by_api_key_id": row[11],
        "created_at": row[12],
        "updated_at": row[13],
    }


def _compute_queue_maintenance_schedule_summary_data(
    *,
    org_id: UUID,
    schedule_name: Optional[str],
    window_days: int,
) -> "QueueMaintenanceScheduleSummaryData":
    audit_base_path = "/api/system/queue/maintenance/schedule-trigger"
    encoded_schedule_name = quote(str(schedule_name), safe="") if schedule_name else None
    audit_path = f"{audit_base_path}?schedule_name={encoded_schedule_name}" if encoded_schedule_name else None
    with get_conn() as conn:
        with conn.cursor() as cur:
            audit_where = [
                "org_id = %s",
                "path like %s",
                "created_at >= (now() - (%s::int * interval '1 day'))",
            ]
            audit_params: List[Any] = [str(org_id), f"{audit_base_path}%", int(window_days)]
            if audit_path:
                audit_where.append("path = %s")
                audit_params.append(audit_path)
            cur.execute(
                f"""
                select
                    count(*)::bigint as trigger_count,
                    count(*) filter (where error_code = 'SCHEDULE_TRIGGER_EXECUTED')::bigint as executed_count,
                    count(*) filter (where error_code = 'SCHEDULE_TRIGGER_DEDUPED')::bigint as deduped_count,
                    max(created_at) as last_triggered_at
                from public.api_audit_logs
                where {' and '.join(audit_where)}
                """,
                tuple(audit_params),
            )
            trigger_stats = cur.fetchone()

            run_where = [
                "org_id = %s",
                "started_at >= (now() - (%s::int * interval '1 day'))",
                "coalesce(policy_snapshot->>'_schedule_name', '') <> ''",
            ]
            run_params: List[Any] = [str(org_id), int(window_days)]
            if schedule_name:
                run_where.append("coalesce(policy_snapshot->>'_schedule_name', '') = %s")
                run_params.append(schedule_name)
            run_where_sql = " and ".join(run_where)
            cur.execute(
                f"""
                select
                    count(*) filter (where status = 'completed')::bigint as successful_executions,
                    count(*) filter (where status = 'failed')::bigint as failed_executions
                from public.queue_maintenance_runs
                where {run_where_sql}
                """,
                tuple(run_params),
            )
            exec_stats = cur.fetchone()
            cur.execute(
                f"""
                select started_at, status
                from public.queue_maintenance_runs
                where {run_where_sql}
                order by started_at desc, id desc
                limit 1
                """,
                tuple(run_params),
            )
            latest_exec = cur.fetchone()

    trigger_count = int(trigger_stats[0] or 0)  # type: ignore[index]
    executed_count = int(trigger_stats[1] or 0)  # type: ignore[index]
    deduped_count = int(trigger_stats[2] or 0)  # type: ignore[index]
    dedupe_hit_rate = float(deduped_count / trigger_count) if trigger_count > 0 else 0.0
    successful_executions = int(exec_stats[0] or 0)  # type: ignore[index]
    failed_executions = int(exec_stats[1] or 0)  # type: ignore[index]
    exec_total = successful_executions + failed_executions
    execution_success_rate = float(successful_executions / exec_total) if exec_total > 0 else 0.0

    return QueueMaintenanceScheduleSummaryData(
        org_id=org_id,
        schedule_name=schedule_name,
        window_days=int(window_days),
        trigger_count=trigger_count,
        executed_count=executed_count,
        deduped_count=deduped_count,
        dedupe_hit_rate=dedupe_hit_rate,
        successful_executions=successful_executions,
        failed_executions=failed_executions,
        execution_success_rate=execution_success_rate,
        last_triggered_at=trigger_stats[3],  # type: ignore[index]
        last_executed_run_started_at=latest_exec[0] if latest_exec else None,
        last_executed_run_status=str(latest_exec[1]) if latest_exec else None,
    )


def _check_and_mark_schedule_alert_cooldown(
    *,
    org_id: UUID,
    schedule_name: Optional[str],
    alert_fingerprint: str,
    cooldown_minutes: int,
) -> Dict[str, Any]:
    schedule_key = (schedule_name or "_all").strip() or "_all"
    cooldown_minutes = max(0, int(cooldown_minutes))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select alert_fingerprint, last_notified_at
                from public.queue_maintenance_schedule_alert_state
                where org_id = %s and schedule_name = %s
                limit 1
                """,
                (str(org_id), schedule_key),
            )
            row = cur.fetchone()
            if row is not None:
                previous_fingerprint = str(row[0] or "")
                previous_notified_at = row[1]
                if (
                    cooldown_minutes > 0
                    and previous_notified_at is not None
                    and previous_fingerprint == alert_fingerprint
                ):
                    cur.execute(
                        """
                        select now() < (%s::timestamptz + (%s::int * interval '1 minute'))
                        """,
                        (previous_notified_at, cooldown_minutes),
                    )
                    in_cooldown = bool(cur.fetchone()[0])  # type: ignore[index]
                    if in_cooldown:
                        return {
                            "suppressed": True,
                            "reason": "cooldown",
                            "last_notified_at": previous_notified_at,
                            "cooldown_minutes": cooldown_minutes,
                        }

            cur.execute(
                """
                insert into public.queue_maintenance_schedule_alert_state (
                    org_id, schedule_name, alert_fingerprint, last_notified_at
                )
                values (%s, %s, %s, now())
                on conflict (org_id, schedule_name)
                do update set
                    alert_fingerprint = excluded.alert_fingerprint,
                    last_notified_at = excluded.last_notified_at,
                    updated_at = now()
                """,
                (str(org_id), schedule_key, alert_fingerprint),
            )
    return {"suppressed": False, "reason": None, "cooldown_minutes": cooldown_minutes}


def _check_and_mark_contract_drift_alert_cooldown(
    *,
    org_id: UUID,
    schedule_name: Optional[str],
    alert_fingerprint: str,
    cooldown_minutes: int,
) -> Dict[str, Any]:
    schedule_key = (schedule_name or "_all").strip() or "_all"
    cooldown_minutes = max(0, int(cooldown_minutes))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select alert_fingerprint, last_notified_at
                from public.contract_drift_trigger_alert_state
                where org_id = %s and schedule_name = %s
                limit 1
                """,
                (str(org_id), schedule_key),
            )
            row = cur.fetchone()
            if row is not None:
                previous_fingerprint = str(row[0] or "")
                previous_notified_at = row[1]
                if (
                    cooldown_minutes > 0
                    and previous_notified_at is not None
                    and previous_fingerprint == alert_fingerprint
                ):
                    cur.execute(
                        """
                        select now() < (%s::timestamptz + (%s::int * interval '1 minute'))
                        """,
                        (previous_notified_at, cooldown_minutes),
                    )
                    in_cooldown = bool(cur.fetchone()[0])  # type: ignore[index]
                    if in_cooldown:
                        return {
                            "suppressed": True,
                            "reason": "cooldown",
                            "last_notified_at": previous_notified_at,
                            "cooldown_minutes": cooldown_minutes,
                        }

            cur.execute(
                """
                insert into public.contract_drift_trigger_alert_state (
                    org_id, schedule_name, alert_fingerprint, last_notified_at
                )
                values (%s, %s, %s, now())
                on conflict (org_id, schedule_name)
                do update set
                    alert_fingerprint = excluded.alert_fingerprint,
                    last_notified_at = excluded.last_notified_at,
                    updated_at = now()
                """,
                (str(org_id), schedule_key, alert_fingerprint),
            )
    return {"suppressed": False, "reason": None, "cooldown_minutes": cooldown_minutes}


def _get_slo_policy(agent_id: UUID) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    id,
                    org_id,
                    agent_id,
                    min_answer_yes_rate,
                    min_source_yes_rate,
                    min_quality_good_rate,
                    max_run_duration_ms,
                    max_regression_count,
                    require_calibration_gate,
                    min_calibration_overall_agreement,
                    max_calibration_age_days,
                    require_golden_set_quality_gate,
                    min_verified_case_ratio,
                    min_active_case_count
                from public.slo_policies
                where agent_id = %s
                """,
                (str(agent_id),),
            )
            row = cur.fetchone()
            if not row:
                return None
    return {
        "id": row[0],
        "org_id": row[1],
        "agent_id": row[2],
        "min_answer_yes_rate": float(row[3]) if row[3] is not None else None,
        "min_source_yes_rate": float(row[4]) if row[4] is not None else None,
        "min_quality_good_rate": float(row[5]) if row[5] is not None else None,
        "max_run_duration_ms": int(row[6]) if row[6] is not None else None,
        "max_regression_count": int(row[7]) if row[7] is not None else None,
        "require_calibration_gate": bool(row[8]),
        "min_calibration_overall_agreement": float(row[9]),
        "max_calibration_age_days": int(row[10]),
        "require_golden_set_quality_gate": bool(row[11]),
        "min_verified_case_ratio": float(row[12]),
        "min_active_case_count": int(row[13]),
    }


def _get_calibration_gate_status(agent_id: UUID, policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    policy_data = policy or _get_slo_policy(agent_id)
    enabled = bool((policy_data or {}).get("require_calibration_gate", False))
    min_overall = float((policy_data or {}).get("min_calibration_overall_agreement", 0.7))
    max_age_days = int((policy_data or {}).get("max_calibration_age_days", 14))
    if not enabled:
        return {
            "enabled": False,
            "status": "disabled",
            "reasons": [],
            "min_overall_agreement": min_overall,
            "max_age_days": max_age_days,
            "latest_calibration_id": None,
            "latest_calibration_created_at": None,
            "latest_overall_agreement": None,
        }

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, created_at, overall_agreement
                from public.calibration_runs
                where agent_id = %s
                order by created_at desc
                limit 1
                """,
                (str(agent_id),),
            )
            latest = cur.fetchone()

    reasons: List[str] = []
    latest_id: Optional[UUID] = None
    latest_created_at: Optional[datetime] = None
    latest_overall: Optional[float] = None
    if not latest:
        reasons.append("No calibration run found.")
    else:
        latest_id = latest[0]  # type: ignore[index]
        latest_created_at = latest[1]  # type: ignore[index]
        latest_overall = float(latest[2]) if latest[2] is not None else None  # type: ignore[index]
        if latest_overall is None:
            reasons.append("Latest calibration run has no overall agreement.")
        elif latest_overall < min_overall:
            reasons.append(f"Calibration overall_agreement {latest_overall:.3f} < required {min_overall:.3f}.")
        if latest_created_at is not None:
            age_days = (datetime.now(timezone.utc) - latest_created_at).total_seconds() / 86400.0
            if age_days > max_age_days:
                reasons.append(f"Latest calibration is stale ({age_days:.1f} days > max {max_age_days}).")
        else:
            reasons.append("Latest calibration has no timestamp.")

    return {
        "enabled": True,
        "status": "pass" if not reasons else "fail",
        "reasons": reasons,
        "min_overall_agreement": min_overall,
        "max_age_days": max_age_days,
        "latest_calibration_id": latest_id,
        "latest_calibration_created_at": latest_created_at,
        "latest_overall_agreement": latest_overall,
    }


def _enforce_calibration_gate(*, agent_id: UUID, run_type: str, run_config: Dict[str, Any]) -> None:
    if run_type == "calibration":
        return
    policy = _get_slo_policy(agent_id)
    enabled_by_policy = bool((policy or {}).get("require_calibration_gate", False))
    enabled_by_run = bool(run_config.get("enforce_calibration_gate", False))
    if not (enabled_by_policy or enabled_by_run):
        return
    status_data = _get_calibration_gate_status(agent_id=agent_id, policy=policy)
    if status_data.get("status") == "pass":
        return
    reasons = status_data.get("reasons") or ["Calibration gate failed."]
    _error(
        "EVAL_CALIBRATION_GATE_FAILED",
        "Calibration gate blocked run execution: " + " ".join(str(x) for x in reasons),
        status.HTTP_409_CONFLICT,
    )


def _get_golden_set_quality_gate_status(
    *, golden_set_id: UUID, policy: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    policy_data = policy or {}
    enabled = bool((policy_data or {}).get("require_golden_set_quality_gate", False))
    min_verified_case_ratio = float((policy_data or {}).get("min_verified_case_ratio", 0.7))
    min_active_case_count = int((policy_data or {}).get("min_active_case_count", 20))

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    count(*)::int as total_case_count,
                    count(*) filter (where verification_status::text <> 'disputed')::int as active_case_count,
                    count(*) filter (where verification_status::text = 'verified')::int as verified_case_count
                from public.golden_set_cases
                where golden_set_id = %s
                """,
                (str(golden_set_id),),
            )
            row = cur.fetchone()

    total_case_count = int(row[0]) if row and row[0] is not None else 0
    active_case_count = int(row[1]) if row and row[1] is not None else 0
    verified_case_count = int(row[2]) if row and row[2] is not None else 0
    verified_case_ratio = (float(verified_case_count) / float(active_case_count)) if active_case_count > 0 else 0.0

    if not enabled:
        return {
            "enabled": False,
            "status": "disabled",
            "reasons": [],
            "min_verified_case_ratio": min_verified_case_ratio,
            "min_active_case_count": min_active_case_count,
            "total_case_count": total_case_count,
            "active_case_count": active_case_count,
            "verified_case_count": verified_case_count,
            "verified_case_ratio": verified_case_ratio,
        }

    reasons: List[str] = []
    if active_case_count < min_active_case_count:
        reasons.append(f"Active case count {active_case_count} < required {min_active_case_count}.")
    if verified_case_ratio < min_verified_case_ratio:
        reasons.append(
            f"Verified case ratio {verified_case_ratio:.3f} < required {min_verified_case_ratio:.3f}."
        )

    return {
        "enabled": True,
        "status": "pass" if not reasons else "fail",
        "reasons": reasons,
        "min_verified_case_ratio": min_verified_case_ratio,
        "min_active_case_count": min_active_case_count,
        "total_case_count": total_case_count,
        "active_case_count": active_case_count,
        "verified_case_count": verified_case_count,
        "verified_case_ratio": verified_case_ratio,
    }


def _enforce_golden_set_quality_gate(
    *, agent_id: UUID, golden_set_id: Optional[UUID], run_config: Dict[str, Any]
) -> None:
    policy = _get_slo_policy(agent_id)
    enabled_by_policy = bool((policy or {}).get("require_golden_set_quality_gate", False))
    enabled_by_run = bool(run_config.get("enforce_golden_set_quality_gate", False))
    if not (enabled_by_policy or enabled_by_run):
        return
    if golden_set_id is None:
        _error(
            "EVAL_GOLDEN_SET_QUALITY_GATE_FAILED",
            "Golden set quality gate blocked run execution: run has no golden_set_id.",
            status.HTTP_409_CONFLICT,
        )
    status_data = _get_golden_set_quality_gate_status(golden_set_id=golden_set_id, policy=policy)
    if status_data.get("status") == "pass":
        return
    reasons = status_data.get("reasons") or ["Golden set quality gate failed."]
    _error(
        "EVAL_GOLDEN_SET_QUALITY_GATE_FAILED",
        "Golden set quality gate blocked run execution: " + " ".join(str(x) for x in reasons),
        status.HTTP_409_CONFLICT,
    )


def _get_agent_gate_bindings(agent_id: UUID) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    b.id,
                    b.org_id,
                    b.agent_id,
                    b.gate_definition_id,
                    b.enabled,
                    b.config,
                    b.definition_contract_version,
                    b.created_at,
                    b.updated_at,
                    d.key,
                    d.name,
                    d.evaluator_key,
                    d.contract_version,
                    d.default_config,
                    d.applies_to_run_types,
                    d.active
                from public.agent_gate_bindings b
                join public.gate_definitions d on d.id = b.gate_definition_id
                where b.agent_id = %s
                order by b.updated_at desc
                """,
                (str(agent_id),),
            )
            rows = cur.fetchall()
    items: List[Dict[str, Any]] = []
    for r in rows:
        items.append(
            {
                "id": r[0],
                "org_id": r[1],
                "agent_id": r[2],
                "gate_definition_id": r[3],
                "enabled": bool(r[4]),
                "config": r[5] or {},
                "definition_contract_version": str(r[6] or "1.0.0"),
                "created_at": r[7],
                "updated_at": r[8],
                "gate_key": str(r[9]),
                "gate_name": str(r[10]),
                "evaluator_key": str(r[11]),
                "contract_version": str(r[12] or "1.0.0"),
                "default_config": r[13] or {},
                "applies_to_run_types": [str(x) for x in (r[14] or [])],
                "gate_active": bool(r[15]),
            }
        )
    return items


def _get_agent_evaluator_bindings(agent_id: UUID) -> Dict[str, Dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    b.id,
                    b.org_id,
                    b.agent_id,
                    b.evaluator_definition_id,
                    b.evaluation_mode::text,
                    b.enabled,
                    b.config,
                    b.definition_contract_version,
                    b.created_at,
                    b.updated_at,
                    d.key,
                    d.name,
                    d.evaluator_kind,
                    d.contract_version,
                    d.default_config,
                    d.active
                from public.agent_evaluator_bindings b
                join public.evaluator_definitions d on d.id = b.evaluator_definition_id
                where b.agent_id = %s
                order by b.updated_at desc
                """,
                (str(agent_id),),
            )
            rows = cur.fetchall()
    bindings: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        eval_mode = str(r[4])
        bindings[eval_mode] = {
            "id": r[0],
            "org_id": r[1],
            "agent_id": r[2],
            "evaluator_definition_id": r[3],
            "evaluation_mode": eval_mode,
            "enabled": bool(r[5]),
            "config": r[6] or {},
            "definition_contract_version": str(r[7] or "1.0.0"),
            "created_at": r[8],
            "updated_at": r[9],
            "evaluator_key": str(r[10]),
            "evaluator_name": str(r[11]),
            "evaluator_kind": str(r[12]),
            "contract_version": str(r[13] or "1.0.0"),
            "default_config": r[14] or {},
            "definition_active": bool(r[15]),
        }
    return bindings


def _resolve_judge_config_for_eval_mode(
    *, eval_mode: str, run_config: Dict[str, Any], evaluator_bindings: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    judge_mode = str(run_config.get("judge_mode", "deterministic"))
    judge_model = run_config.get("judge_model")
    judge_prompt_version = run_config.get("judge_prompt_version")

    binding = evaluator_bindings.get(eval_mode)
    if binding and bool(binding.get("enabled", False)) and bool(binding.get("definition_active", False)):
        evaluator_kind = str(binding.get("evaluator_kind", "")).strip()
        if evaluator_kind not in SUPPORTED_EVALUATOR_KINDS:
            _error(
                "EVALUATOR_CONFIG_ERROR",
                f"Unsupported evaluator_kind '{evaluator_kind}' for eval_mode='{eval_mode}'.",
                status.HTTP_400_BAD_REQUEST,
            )
        merged: Dict[str, Any] = {}
        default_config = binding.get("default_config") or {}
        binding_config = binding.get("config") or {}
        if isinstance(default_config, dict):
            merged.update(default_config)
        if isinstance(binding_config, dict):
            merged.update(binding_config)
        judge_mode = str(run_config.get("judge_mode", merged.get("judge_mode", judge_mode)))
        judge_model = run_config.get("judge_model", merged.get("judge_model", judge_model))
        judge_prompt_version = run_config.get("judge_prompt_version", merged.get("judge_prompt_version", judge_prompt_version))
        return {
            "judge_mode": judge_mode,
            "judge_model": judge_model,
            "judge_prompt_version": judge_prompt_version,
            "evaluator_binding": binding,
        }

    return {
        "judge_mode": judge_mode,
        "judge_model": judge_model,
        "judge_prompt_version": judge_prompt_version,
        "evaluator_binding": None,
    }


def _get_agent_run_type_bindings(agent_id: UUID) -> Dict[str, Dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    b.id,
                    b.org_id,
                    b.agent_id,
                    b.run_type::text,
                    b.run_type_definition_id,
                    b.enabled,
                    b.config,
                    b.definition_contract_version,
                    b.created_at,
                    b.updated_at,
                    d.key,
                    d.name,
                    d.handler_key,
                    d.contract_version,
                    d.default_config,
                    d.active
                from public.agent_run_type_bindings b
                join public.run_type_definitions d on d.id = b.run_type_definition_id
                where b.agent_id = %s
                order by b.updated_at desc
                """,
                (str(agent_id),),
            )
            rows = cur.fetchall()
    items: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        run_type = str(r[3])
        items[run_type] = {
            "id": r[0],
            "org_id": r[1],
            "agent_id": r[2],
            "run_type": run_type,
            "run_type_definition_id": r[4],
            "enabled": bool(r[5]),
            "config": r[6] or {},
            "definition_contract_version": str(r[7] or "1.0.0"),
            "created_at": r[8],
            "updated_at": r[9],
            "definition_key": str(r[10]),
            "definition_name": str(r[11]),
            "handler_key": str(r[12]),
            "contract_version": str(r[13] or "1.0.0"),
            "default_config": r[14] or {},
            "definition_active": bool(r[15]),
        }
    return items


def _resolve_run_type_handler(*, agent_id: UUID, run_type: str, run_config: Dict[str, Any]) -> Dict[str, Any]:
    bindings: Dict[str, Dict[str, Any]] = {}
    try:
        bindings = _get_agent_run_type_bindings(agent_id)
    except Exception:
        bindings = {}

    resolved: Dict[str, Any] = {"handler_key": "default", "handler_config": {}, "binding": None}
    binding = bindings.get(run_type)
    if binding and bool(binding.get("enabled", False)) and bool(binding.get("definition_active", False)):
        merged: Dict[str, Any] = {}
        default_config = binding.get("default_config") or {}
        binding_config = binding.get("config") or {}
        if isinstance(default_config, dict):
            merged.update(default_config)
        if isinstance(binding_config, dict):
            merged.update(binding_config)
        resolved["handler_key"] = str(binding.get("handler_key", "default"))
        resolved["handler_config"] = merged
        resolved["binding"] = binding

    override = run_config.get("run_handler")
    if isinstance(override, dict):
        override_key = override.get("handler_key")
        if override_key is not None:
            resolved["handler_key"] = str(override_key)
        override_cfg = override.get("config")
        if isinstance(override_cfg, dict):
            merged_cfg = dict(resolved.get("handler_config") or {})
            merged_cfg.update(override_cfg)
            resolved["handler_config"] = merged_cfg

    handler_key = str(resolved.get("handler_key", "default"))
    if handler_key not in SUPPORTED_RUN_TYPE_HANDLERS:
        _error(
            "EVAL_RUN_HANDLER_CONFIG_ERROR",
            f"Unsupported run handler_key '{handler_key}' for run_type='{run_type}'.",
            status.HTTP_400_BAD_REQUEST,
        )
    return resolved


def _enforce_run_type_handler_mode(*, handler_key: str, handler_config: Dict[str, Any], entrypoint: str) -> None:
    if entrypoint == "start" and handler_key == "sync_only":
        _error(
            "EVAL_RUN_HANDLER_MODE_INVALID",
            "Run type handler is configured as sync_only and cannot be started asynchronously.",
            status.HTTP_409_CONFLICT,
        )
    if entrypoint == "execute" and handler_key == "async_only":
        _error(
            "EVAL_RUN_HANDLER_MODE_INVALID",
            "Run type handler is configured as async_only and cannot be executed synchronously.",
            status.HTTP_409_CONFLICT,
        )
    if entrypoint == "start" and bool(handler_config.get("allow_start", True)) is False:
        _error(
            "EVAL_RUN_HANDLER_MODE_INVALID",
            "Run type handler configuration disallows async start.",
            status.HTTP_409_CONFLICT,
        )
    if entrypoint == "execute" and bool(handler_config.get("allow_execute", True)) is False:
        _error(
            "EVAL_RUN_HANDLER_MODE_INVALID",
            "Run type handler configuration disallows sync execute.",
            status.HTTP_409_CONFLICT,
        )


def _get_contract_definition_and_bindings(
    *,
    definition_type: str,
    definition_id: UUID,
) -> Dict[str, Any]:
    meta = _CONTRACT_DEFINITION_META.get(str(definition_type))
    if not meta:
        _error("CONTRACT_DEFINITION_TYPE_INVALID", "Unsupported definition type.", status.HTTP_400_BAD_REQUEST)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select id, org_id, key, name, contract_version
                from {meta["definition_table"]}
                where {meta["definition_id_col"]} = %s
                """,
                (str(definition_id),),
            )
            def_row = cur.fetchone()
            if not def_row:
                _error(
                    "CONTRACT_DEFINITION_NOT_FOUND",
                    f"Definition {definition_id} was not found.",
                    status.HTTP_404_NOT_FOUND,
                )
            cur.execute(
                f"""
                select id, agent_id, definition_contract_version
                from {meta["binding_table"]}
                where {meta["binding_definition_fk_col"]} = %s
                order by updated_at desc
                """,
                (str(definition_id),),
            )
            binding_rows = cur.fetchall()
    return {
        "definition_id": def_row[0],  # type: ignore[index]
        "org_id": def_row[1],  # type: ignore[index]
        "definition_key": str(def_row[2]),  # type: ignore[index]
        "definition_name": str(def_row[3]),  # type: ignore[index]
        "current_contract_version": str(def_row[4] or "1.0.0"),  # type: ignore[index]
        "bindings": [
            {
                "binding_id": r[0],
                "agent_id": r[1],
                "definition_contract_version": str(r[2] or "1.0.0"),
            }
            for r in (binding_rows or [])
        ],
    }


def _compute_contract_upgrade_preview(
    *,
    definition_type: str,
    definition_id: UUID,
    target_contract_version: str,
    include_items: bool = True,
    max_items: int = 200,
) -> Dict[str, Any]:
    target_parsed = _parse_semver(str(target_contract_version))
    if target_parsed is None:
        _error(
            "CONTRACT_VERSION_INVALID",
            "target_contract_version must be semantic version x.y.z.",
            status.HTTP_400_BAD_REQUEST,
        )
    loaded = _get_contract_definition_and_bindings(definition_type=definition_type, definition_id=definition_id)
    current_ver = str(loaded["current_contract_version"])
    current_parsed = _parse_semver(current_ver)
    if current_parsed is None:
        _error(
            "CONTRACT_VERSION_INVALID",
            "Current definition contract_version is not valid semantic version x.y.z.",
            status.HTTP_400_BAD_REQUEST,
        )

    items: List[Dict[str, Any]] = []
    breaking_count = 0
    warning_count = 0
    invalid_count = 0
    unchanged_count = 0
    bindings = loaded["bindings"]
    for b in bindings:
        bound_ver = str(b.get("definition_contract_version", "1.0.0"))
        parsed_bound = _parse_semver(bound_ver)
        if parsed_bound is None:
            impact = "invalid"
            message = f"Invalid bound contract version '{bound_ver}'."
            invalid_count += 1
        elif parsed_bound[0] != target_parsed[0]:
            impact = "breaking"
            message = (
                f"Major version mismatch after upgrade: bound={bound_ver}, target={target_contract_version}."
            )
            breaking_count += 1
        elif parsed_bound != target_parsed:
            impact = "warning"
            message = f"Minor/patch drift after upgrade: bound={bound_ver}, target={target_contract_version}."
            warning_count += 1
        else:
            impact = "none"
            message = "Binding version already matches target."
            unchanged_count += 1
        if include_items and len(items) < max_items:
            items.append(
                {
                    "binding_id": b.get("binding_id"),
                    "agent_id": b.get("agent_id"),
                    "definition_contract_version": bound_ver,
                    "impact": impact,
                    "message": message,
                }
            )

    status_value: Literal["safe", "risky"] = "safe"
    if breaking_count > 0 or invalid_count > 0:
        status_value = "risky"
    return {
        "definition_type": str(definition_type),
        "definition_id": loaded["definition_id"],
        "definition_key": loaded["definition_key"],
        "definition_name": loaded["definition_name"],
        "current_contract_version": current_ver,
        "target_contract_version": str(target_contract_version),
        "impacted_binding_count": len(bindings),
        "breaking_count": breaking_count,
        "warning_count": warning_count,
        "invalid_count": invalid_count,
        "unchanged_count": unchanged_count,
        "status": status_value,
        "items": items,
        "org_id": loaded["org_id"],
    }


def _drift_status_from_versions(*, bound_ver: str, current_ver: str) -> Dict[str, str]:
    parsed_bound = _parse_semver(bound_ver)
    parsed_current = _parse_semver(current_ver)
    if parsed_bound is None or parsed_current is None:
        return {
            "drift": "invalid",
            "severity": "error",
            "message": f"Invalid contract version format (bound={bound_ver}, current={current_ver}).",
        }
    if parsed_bound[0] != parsed_current[0]:
        return {
            "drift": "breaking",
            "severity": "error",
            "message": f"Major version mismatch (bound={bound_ver}, current={current_ver}).",
        }
    if parsed_bound != parsed_current:
        return {
            "drift": "warning",
            "severity": "warning",
            "message": f"Minor/patch drift (bound={bound_ver}, current={current_ver}).",
        }
    return {
        "drift": "none",
        "severity": "info",
        "message": "Binding contract version matches definition.",
    }


def _collect_agent_contract_drift_items(*, agent_id: UUID, include_healthy: bool = False) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for b in _get_agent_gate_bindings(agent_id):
        bound_ver = str(b.get("definition_contract_version", "1.0.0"))
        current_ver = str(b.get("contract_version", "1.0.0"))
        drift_data = _drift_status_from_versions(bound_ver=bound_ver, current_ver=current_ver)
        if not include_healthy and drift_data["drift"] == "none":
            continue
        items.append(
            {
                "agent_id": agent_id,
                "definition_type": "gate",
                "binding_id": b["id"],
                "definition_id": b["gate_definition_id"],
                "definition_key": str(b.get("gate_key", "")),
                "bound_contract_version": bound_ver,
                "current_contract_version": current_ver,
                "drift": drift_data["drift"],
                "severity": drift_data["severity"],
                "message": drift_data["message"],
            }
        )
    for b in _get_agent_evaluator_bindings(agent_id).values():
        bound_ver = str(b.get("definition_contract_version", "1.0.0"))
        current_ver = str(b.get("contract_version", "1.0.0"))
        drift_data = _drift_status_from_versions(bound_ver=bound_ver, current_ver=current_ver)
        if not include_healthy and drift_data["drift"] == "none":
            continue
        items.append(
            {
                "agent_id": agent_id,
                "definition_type": "evaluator",
                "binding_id": b["id"],
                "definition_id": b["evaluator_definition_id"],
                "definition_key": str(b.get("evaluator_key", "")),
                "bound_contract_version": bound_ver,
                "current_contract_version": current_ver,
                "drift": drift_data["drift"],
                "severity": drift_data["severity"],
                "message": drift_data["message"],
            }
        )
    for b in _get_agent_run_type_bindings(agent_id).values():
        bound_ver = str(b.get("definition_contract_version", "1.0.0"))
        current_ver = str(b.get("contract_version", "1.0.0"))
        drift_data = _drift_status_from_versions(bound_ver=bound_ver, current_ver=current_ver)
        if not include_healthy and drift_data["drift"] == "none":
            continue
        items.append(
            {
                "agent_id": agent_id,
                "definition_type": "run_type",
                "binding_id": b["id"],
                "definition_id": b["run_type_definition_id"],
                "definition_key": str(b.get("definition_key", "")),
                "bound_contract_version": bound_ver,
                "current_contract_version": current_ver,
                "drift": drift_data["drift"],
                "severity": drift_data["severity"],
                "message": drift_data["message"],
            }
        )
    return items


def _create_or_reuse_contract_drift_pattern(
    *,
    org_id: UUID,
    drift_item: Dict[str, Any],
) -> Dict[str, Any]:
    agent_id = UUID(str(drift_item["agent_id"]))
    definition_type = str(drift_item.get("definition_type", "unknown"))
    definition_key = str(drift_item.get("definition_key", "unknown"))
    binding_id = str(drift_item.get("binding_id"))
    definition_id = str(drift_item.get("definition_id"))
    bound_ver = str(drift_item.get("bound_contract_version", "1.0.0"))
    current_ver = str(drift_item.get("current_contract_version", "1.0.0"))
    drift = str(drift_item.get("drift", "warning"))
    open_statuses = ("detected", "diagnosed", "assigned", "in_progress", "regressed")
    now_iso = datetime.now(timezone.utc).isoformat()

    title = (
        f"Contract drift: {definition_type}:{definition_key} "
        f"{bound_ver} -> {current_ver} ({drift})"
    )
    severity_to_priority = {"invalid": "critical", "breaking": "high", "warning": "medium"}
    priority = severity_to_priority.get(drift, "medium")
    root_cause = (
        f"Binding contract version drift detected for {definition_type} definition '{definition_key}'."
    )
    suggested_fix = "Review definition upgrade rollout and sync affected bindings where appropriate."
    verification_result = {
        "source": "contract_drift_monitor",
        "definition_type": definition_type,
        "definition_id": definition_id,
        "binding_id": binding_id,
        "bound_contract_version": bound_ver,
        "current_contract_version": current_ver,
        "drift": drift,
    }

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id
                from public.issue_patterns
                where agent_id = %s
                  and primary_tag = 'contract_drift'
                  and status::text = any(%s)
                  and verification_result->>'binding_id' = %s
                  and verification_result->>'bound_contract_version' = %s
                  and verification_result->>'current_contract_version' = %s
                order by created_at desc
                limit 1
                """,
                (str(agent_id), list(open_statuses), binding_id, bound_ver, current_ver),
            )
            existing = cur.fetchone()
            if existing:
                return {"created": False, "pattern_id": str(existing[0])}

            cur.execute(
                """
                insert into public.issue_patterns (
                    org_id,
                    agent_id,
                    title,
                    primary_tag,
                    related_tags,
                    status,
                    priority,
                    root_cause,
                    root_cause_type,
                    suggested_fix,
                    linked_case_ids,
                    history,
                    status_history,
                    fix_notes,
                    verification_result
                )
                values (
                    %s, %s, %s, 'contract_drift', %s::text[],
                    'detected'::public.issue_status,
                    %s::public.issue_priority,
                    %s,
                    'config'::public.root_cause_type,
                    %s,
                    %s::uuid[],
                    %s::jsonb,
                    %s::jsonb,
                    '[]'::jsonb,
                    %s::jsonb
                )
                returning id
                """,
                (
                    str(org_id),
                    str(agent_id),
                    title,
                    ["contract", "drift", definition_type],
                    priority,
                    root_cause,
                    suggested_fix,
                    [],
                    json.dumps(
                        [
                            {
                                "detected_at": now_iso,
                                "definition_type": definition_type,
                                "definition_key": definition_key,
                                "bound_contract_version": bound_ver,
                                "current_contract_version": current_ver,
                                "drift": drift,
                            }
                        ]
                    ),
                    json.dumps([{"from": None, "to": "detected", "at": now_iso}]),
                    json.dumps(verification_result),
                ),
            )
            created = cur.fetchone()
            return {"created": True, "pattern_id": str(created[0])}


def _resolve_contract_drift_escalation_agent_id(
    *,
    org_id: UUID,
    preferred_agent_id: Optional[UUID],
) -> Optional[UUID]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            if preferred_agent_id is not None:
                cur.execute(
                    """
                    select id
                    from public.agents
                    where id = %s and org_id = %s
                    limit 1
                    """,
                    (str(preferred_agent_id), str(org_id)),
                )
                preferred = cur.fetchone()
                if preferred:
                    return UUID(str(preferred[0]))
            cur.execute(
                """
                select id
                from public.agents
                where org_id = %s
                  and status <> 'retired'::public.agent_status
                order by updated_at desc, created_at desc
                limit 1
                """,
                (str(org_id),),
            )
            fallback = cur.fetchone()
            if fallback:
                return UUID(str(fallback[0]))
    return None


def _create_or_reuse_contract_drift_notify_failure_pattern(
    *,
    org_id: UUID,
    agent_id: UUID,
    schedule_name: Optional[str],
    window_days: int,
    dedupe_hit_rate: float,
    execution_rate: float,
    error_message: str,
) -> Dict[str, Any]:
    open_statuses = ("detected", "diagnosed", "assigned", "in_progress", "regressed")
    schedule_key = (schedule_name or "_all").strip() or "_all"
    now_iso = datetime.now(timezone.utc).isoformat()
    verification_result = {
        "source": "contract_drift_alert_delivery",
        "schedule_name": schedule_key,
        "window_days": int(window_days),
    }
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id
                from public.issue_patterns
                where agent_id = %s
                  and primary_tag = 'contract_drift_alert_delivery'
                  and status::text = any(%s)
                  and verification_result->>'source' = 'contract_drift_alert_delivery'
                  and verification_result->>'schedule_name' = %s
                  and verification_result->>'window_days' = %s
                order by created_at desc
                limit 1
                """,
                (str(agent_id), list(open_statuses), schedule_key, str(int(window_days))),
            )
            existing = cur.fetchone()
            if existing:
                return {"created": False, "pattern_id": str(existing[0])}

            cur.execute(
                """
                insert into public.issue_patterns (
                    org_id,
                    agent_id,
                    title,
                    primary_tag,
                    related_tags,
                    status,
                    priority,
                    root_cause,
                    root_cause_type,
                    suggested_fix,
                    linked_case_ids,
                    history,
                    status_history,
                    fix_notes,
                    verification_result
                )
                values (
                    %s, %s, %s, 'contract_drift_alert_delivery', %s::text[],
                    'detected'::public.issue_status,
                    'high'::public.issue_priority,
                    %s,
                    'config'::public.root_cause_type,
                    %s,
                    %s::uuid[],
                    %s::jsonb,
                    %s::jsonb,
                    '[]'::jsonb,
                    %s::jsonb
                )
                returning id
                """,
                (
                    str(org_id),
                    str(agent_id),
                    f"Contract drift alert notify failed ({schedule_key})",
                    ["contract", "drift", "alert_delivery"],
                    "Drift trigger anomaly detected but notification delivery failed.",
                    "Review webhook configuration and outbox retry state before next scheduled run.",
                    [],
                    json.dumps(
                        [
                            {
                                "detected_at": now_iso,
                                "schedule_name": schedule_key,
                                "window_days": int(window_days),
                                "dedupe_hit_rate": round(float(dedupe_hit_rate), 6),
                                "execution_rate": round(float(execution_rate), 6),
                                "error_message": error_message[:1000],
                            }
                        ]
                    ),
                    json.dumps([{"from": None, "to": "detected", "at": now_iso}]),
                    json.dumps(verification_result),
                ),
            )
            created = cur.fetchone()
            return {"created": True, "pattern_id": str(created[0])}


def _compute_agent_contract_issues(
    *, agent_id: UUID, run_type: str, entrypoint: str, golden_set_id: Optional[UUID]
) -> Dict[str, Any]:
    issues: List[Dict[str, str]] = []
    run_handler = _resolve_run_type_handler(agent_id=agent_id, run_type=run_type, run_config={})
    handler_key = str(run_handler.get("handler_key", "default"))
    handler_config = dict(run_handler.get("handler_config") or {})
    run_type_bindings = _get_agent_run_type_bindings(agent_id)
    rt_binding = run_type_bindings.get(run_type)
    if rt_binding and bool(rt_binding.get("enabled", False)):
        bound_ver = str(rt_binding.get("definition_contract_version", "1.0.0"))
        current_ver = str(rt_binding.get("contract_version", "1.0.0"))
        parsed_bound = _parse_semver(bound_ver)
        parsed_current = _parse_semver(current_ver)
        if parsed_bound is None or parsed_current is None:
            issues.append(
                {
                    "severity": "error",
                    "code": "RUN_TYPE_CONTRACT_VERSION_INVALID",
                    "message": f"Invalid run type contract version format (bound={bound_ver}, current={current_ver}).",
                    "component": "run_type_binding",
                }
            )
        elif parsed_bound[0] != parsed_current[0]:
            issues.append(
                {
                    "severity": "error",
                    "code": "RUN_TYPE_CONTRACT_INCOMPATIBLE",
                    "message": f"Run type contract major mismatch (bound={bound_ver}, current={current_ver}).",
                    "component": "run_type_binding",
                }
            )
        elif bound_ver != current_ver:
            issues.append(
                {
                    "severity": "warning",
                    "code": "RUN_TYPE_CONTRACT_OUTDATED",
                    "message": f"Run type contract version changed (bound={bound_ver}, current={current_ver}).",
                    "component": "run_type_binding",
                }
            )

    try:
        _enforce_run_type_handler_mode(handler_key=handler_key, handler_config=handler_config, entrypoint=entrypoint)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        issues.append(
            {
                "severity": "error",
                "code": str(detail.get("code") or "EVAL_RUN_HANDLER_MODE_INVALID"),
                "message": str(detail.get("message") or "Run type handler mode invalid."),
                "component": "run_type_handler",
            }
        )

    gate_bindings = _get_agent_gate_bindings(agent_id)
    enabled_gate_count = 0
    for b in gate_bindings:
        if not bool(b.get("enabled", False)):
            continue
        enabled_gate_count += 1
        if not bool(b.get("gate_active", False)):
            issues.append(
                {
                    "severity": "warning",
                    "code": "GATE_DEFINITION_INACTIVE",
                    "message": f"Gate '{b.get('gate_key')}' is bound but definition is inactive.",
                    "component": "gate_binding",
                }
            )
        evaluator_key = str(b.get("evaluator_key", "")).strip()
        bound_ver = str(b.get("definition_contract_version", "1.0.0"))
        current_ver = str(b.get("contract_version", "1.0.0"))
        parsed_bound = _parse_semver(bound_ver)
        parsed_current = _parse_semver(current_ver)
        if parsed_bound is None or parsed_current is None:
            issues.append(
                {
                    "severity": "error",
                    "code": "GATE_CONTRACT_VERSION_INVALID",
                    "message": f"Invalid gate contract version format (bound={bound_ver}, current={current_ver}).",
                    "component": "gate_binding",
                }
            )
        elif parsed_bound[0] != parsed_current[0]:
            issues.append(
                {
                    "severity": "error",
                    "code": "GATE_CONTRACT_INCOMPATIBLE",
                    "message": f"Gate contract major mismatch (bound={bound_ver}, current={current_ver}).",
                    "component": "gate_binding",
                }
            )
        elif bound_ver != current_ver:
            issues.append(
                {
                    "severity": "warning",
                    "code": "GATE_CONTRACT_OUTDATED",
                    "message": f"Gate contract version changed (bound={bound_ver}, current={current_ver}).",
                    "component": "gate_binding",
                }
            )
        if evaluator_key not in SUPPORTED_GATE_EVALUATORS:
            issues.append(
                {
                    "severity": "error",
                    "code": "GATE_EVALUATOR_UNSUPPORTED",
                    "message": f"Gate '{b.get('gate_key')}' uses unsupported evaluator_key='{evaluator_key}'.",
                    "component": "gate_binding",
                }
            )
        applies_to = b.get("applies_to_run_types") or []
        if run_type in applies_to and evaluator_key == "golden_set_quality" and golden_set_id is None:
            issues.append(
                {
                    "severity": "error",
                    "code": "GOLDEN_SET_REQUIRED",
                    "message": f"Gate '{b.get('gate_key')}' requires golden_set_id for run_type='{run_type}'.",
                    "component": "gate_binding",
                }
            )

    evaluator_bindings = _get_agent_evaluator_bindings(agent_id)
    enabled_eval_count = 0
    for mode, b in evaluator_bindings.items():
        if not bool(b.get("enabled", False)):
            continue
        enabled_eval_count += 1
        if not bool(b.get("definition_active", False)):
            issues.append(
                {
                    "severity": "warning",
                    "code": "EVALUATOR_DEFINITION_INACTIVE",
                    "message": f"Evaluator binding for mode='{mode}' is bound but definition is inactive.",
                    "component": "evaluator_binding",
                }
            )
        evaluator_kind = str(b.get("evaluator_kind", "")).strip()
        if evaluator_kind not in SUPPORTED_EVALUATOR_KINDS:
            issues.append(
                {
                    "severity": "error",
                    "code": "EVALUATOR_KIND_UNSUPPORTED",
                    "message": f"Evaluator binding for mode='{mode}' uses unsupported evaluator_kind='{evaluator_kind}'.",
                    "component": "evaluator_binding",
                }
            )
        bound_ver = str(b.get("definition_contract_version", "1.0.0"))
        current_ver = str(b.get("contract_version", "1.0.0"))
        parsed_bound = _parse_semver(bound_ver)
        parsed_current = _parse_semver(current_ver)
        if parsed_bound is None or parsed_current is None:
            issues.append(
                {
                    "severity": "error",
                    "code": "EVALUATOR_CONTRACT_VERSION_INVALID",
                    "message": f"Invalid evaluator contract version format (bound={bound_ver}, current={current_ver}).",
                    "component": "evaluator_binding",
                }
            )
        elif parsed_bound[0] != parsed_current[0]:
            issues.append(
                {
                    "severity": "error",
                    "code": "EVALUATOR_CONTRACT_INCOMPATIBLE",
                    "message": f"Evaluator contract major mismatch (bound={bound_ver}, current={current_ver}).",
                    "component": "evaluator_binding",
                }
            )
        elif bound_ver != current_ver:
            issues.append(
                {
                    "severity": "warning",
                    "code": "EVALUATOR_CONTRACT_OUTDATED",
                    "message": f"Evaluator contract version changed (bound={bound_ver}, current={current_ver}).",
                    "component": "evaluator_binding",
                }
            )

    return {
        "status": "fail" if any(i["severity"] == "error" for i in issues) else "pass",
        "issues": issues,
        "resolved_handler_key": handler_key,
        "enabled_gate_binding_count": enabled_gate_count,
        "enabled_evaluator_binding_count": enabled_eval_count,
    }


def _enforce_agent_contract_issues(
    *, agent_id: UUID, run_type: str, entrypoint: str, golden_set_id: Optional[UUID]
) -> None:
    data = _compute_agent_contract_issues(
        agent_id=agent_id,
        run_type=run_type,
        entrypoint=entrypoint,
        golden_set_id=golden_set_id,
    )
    if data.get("status") == "pass":
        return
    errors = [x for x in (data.get("issues") or []) if str(x.get("severity")) == "error"]
    if not errors:
        return
    first = errors[0]
    _error(
        "AGENT_CONTRACT_VALIDATION_FAILED",
        "Agent contract validation failed: " + str(first.get("message", "unknown error")),
        status.HTTP_409_CONFLICT,
        {
            "issue_count": len(errors),
            "first_issue_code": first.get("code"),
            "resolved_handler_key": data.get("resolved_handler_key"),
        },
    )


def _enforce_configured_gates(
    *, agent_id: UUID, run_type: str, golden_set_id: Optional[UUID], run_config: Dict[str, Any]
) -> None:
    bindings = _get_agent_gate_bindings(agent_id)
    for binding in bindings:
        if not bool(binding.get("enabled", False)):
            continue
        if not bool(binding.get("gate_active", False)):
            continue
        applies_to = binding.get("applies_to_run_types") or []
        if applies_to and run_type not in applies_to:
            continue
        evaluator_key = str(binding.get("evaluator_key", "")).strip()
        gate_key = str(binding.get("gate_key", "unknown_gate"))
        effective_config = {}
        default_config = binding.get("default_config") or {}
        binding_config = binding.get("config") or {}
        if isinstance(default_config, dict):
            effective_config.update(default_config)
        if isinstance(binding_config, dict):
            effective_config.update(binding_config)
        if evaluator_key == "calibration_freshness":
            gate_status = _get_calibration_gate_status(
                agent_id=agent_id,
                policy={
                    "require_calibration_gate": True,
                    "min_calibration_overall_agreement": float(
                        effective_config.get("min_overall_agreement", 0.7)
                    ),
                    "max_calibration_age_days": int(effective_config.get("max_age_days", 14)),
                },
            )
        elif evaluator_key == "golden_set_quality":
            if golden_set_id is None:
                _error(
                    "EVAL_GATE_FAILED",
                    f"Gate '{gate_key}' blocked run execution: run has no golden_set_id.",
                    status.HTTP_409_CONFLICT,
                )
            gate_status = _get_golden_set_quality_gate_status(
                golden_set_id=UUID(str(golden_set_id)),
                policy={
                    "require_golden_set_quality_gate": True,
                    "min_verified_case_ratio": float(effective_config.get("min_verified_case_ratio", 0.7)),
                    "min_active_case_count": int(effective_config.get("min_active_case_count", 20)),
                },
            )
        elif evaluator_key in SUPPORTED_GATE_EVALUATORS:
            # Reserved evaluator registered but not yet wired.
            continue
        else:
            _error(
                "EVAL_GATE_CONFIG_ERROR",
                f"Gate '{gate_key}' has unsupported evaluator_key='{evaluator_key}'.",
                status.HTTP_400_BAD_REQUEST,
            )

        if str(gate_status.get("status", "fail")) != "pass":
            reasons = gate_status.get("reasons") or [f"Gate '{gate_key}' failed."]
            _error(
                "EVAL_GATE_FAILED",
                f"Gate '{gate_key}' blocked run execution: " + " ".join(str(x) for x in reasons),
                status.HTTP_409_CONFLICT,
            )


def _record_slo_violation(
    *,
    org_id: UUID,
    agent_id: UUID,
    policy_id: Optional[UUID],
    source: SloViolationSource,
    source_ref_id: Optional[UUID],
    metric: str,
    actual_value: float,
    expected_value: float,
    comparator: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.slo_violations (
                        org_id, agent_id, policy_id, source, source_ref_id,
                        metric, actual_value, expected_value, comparator, details
                    )
                    values (%s, %s, %s, %s::public.slo_violation_source, %s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        str(org_id),
                        str(agent_id),
                        str(policy_id) if policy_id else None,
                        source,
                        str(source_ref_id) if source_ref_id else None,
                        metric,
                        actual_value,
                        expected_value,
                        comparator,
                        json.dumps(details or {}),
                    ),
                )
    except Exception:
        return


def _emit_slo_violation(
    *,
    org_id: UUID,
    agent_id: UUID,
    policy_id: Optional[UUID],
    source: SloViolationSource,
    source_ref_id: Optional[UUID],
    metric: str,
    actual_value: float,
    expected_value: float,
    comparator: str,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    _record_slo_violation(
        org_id=org_id,
        agent_id=agent_id,
        policy_id=policy_id,
        source=source,
        source_ref_id=source_ref_id,
        metric=metric,
        actual_value=actual_value,
        expected_value=expected_value,
        comparator=comparator,
        details=details,
    )
    _record_activity_event(
        org_id=org_id,
        agent_id=agent_id,
        event_type="slo_violation",
        title="SLO violation detected",
        details=f"{metric}: actual={actual_value}, expected={expected_value}, comparator={comparator}",
        severity="error",
        metadata={
            "policy_id": str(policy_id) if policy_id else None,
            "source": source,
            "source_ref_id": str(source_ref_id) if source_ref_id else None,
            "metric": metric,
            "actual_value": actual_value,
            "expected_value": expected_value,
            "comparator": comparator,
            **(details or {}),
        },
    )
    notify = _dispatch_notification(
        org_id=org_id,
        agent_id=agent_id,
        event_type="slo_violation",
        payload={
            "org_id": str(org_id),
            "agent_id": str(agent_id),
            "policy_id": str(policy_id) if policy_id else None,
            "source": source,
            "source_ref_id": str(source_ref_id) if source_ref_id else None,
            "metric": metric,
            "actual_value": actual_value,
            "expected_value": expected_value,
            "comparator": comparator,
            **(details or {}),
        },
    )
    return notify


def _auto_close_remediation_on_clean_compare(
    *,
    org_id: UUID,
    agent_id: UUID,
    baseline_run_id: UUID,
    candidate_run_id: UUID,
) -> Dict[str, Any]:
    updated_patterns = 0
    resolved_slo_violations = 0

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id, status::text, status_history
                    from public.issue_patterns
                    where agent_id = %s
                      and primary_tag = 'regression_compare'
                      and status in (
                        'detected'::public.issue_status,
                        'diagnosed'::public.issue_status,
                        'assigned'::public.issue_status,
                        'in_progress'::public.issue_status,
                        'regressed'::public.issue_status
                      )
                      and verification_result->>'baseline_run_id' = %s
                      and verification_result->>'candidate_run_id' = %s
                    """,
                    (str(agent_id), str(baseline_run_id), str(candidate_run_id)),
                )
                pattern_rows = cur.fetchall()
                for row in pattern_rows:
                    pattern_id = row[0]
                    old_status = str(row[1])
                    history = row[2] or []
                    new_status = "verifying"
                    if _is_allowed_pattern_transition(old_status, new_status):
                        new_history = _append_status_history(
                            history,
                            old_status=old_status,
                            new_status=new_status,
                            note="Auto-transitioned after clean regression compare.",
                        )
                        cur.execute(
                            """
                            update public.issue_patterns
                            set status = 'verifying'::public.issue_status,
                                status_history = %s::jsonb,
                                updated_at = now()
                            where id = %s
                            """,
                            (json.dumps(new_history), str(pattern_id)),
                        )
                        updated_patterns += 1

                cur.execute(
                    """
                    update public.slo_violations
                    set status = 'resolved'::public.slo_violation_status,
                        resolved_at = now()
                    where agent_id = %s
                      and status = 'open'::public.slo_violation_status
                      and source = 'run_compare'::public.slo_violation_source
                      and metric = 'max_regression_count'
                      and (
                        source_ref_id = %s
                        or (
                          details->>'baseline_run_id' = %s
                          and details->>'candidate_run_id' = %s
                        )
                      )
                    """,
                    (str(agent_id), str(candidate_run_id), str(baseline_run_id), str(candidate_run_id)),
                )
                resolved_slo_violations = cur.rowcount or 0
    except Exception:
        return {"updated_patterns": 0, "resolved_slo_violations": 0}

    if updated_patterns > 0 or resolved_slo_violations > 0:
        _record_activity_event(
            org_id=org_id,
            agent_id=agent_id,
            event_type="remediation_verified",
            title="Remediation verified after clean compare",
            details=(
                f"baseline={str(baseline_run_id)[:8]}, candidate={str(candidate_run_id)[:8]}, "
                f"patterns_to_verifying={updated_patterns}, resolved_slo_violations={resolved_slo_violations}"
            ),
            severity="info",
            metadata={
                "baseline_run_id": str(baseline_run_id),
                "candidate_run_id": str(candidate_run_id),
                "updated_patterns": updated_patterns,
                "resolved_slo_violations": resolved_slo_violations,
            },
        )
        _dispatch_notification(
            org_id=org_id,
            agent_id=agent_id,
            event_type="remediation_verified",
            payload={
                "org_id": str(org_id),
                "agent_id": str(agent_id),
                "baseline_run_id": str(baseline_run_id),
                "candidate_run_id": str(candidate_run_id),
                "updated_patterns": updated_patterns,
                "resolved_slo_violations": resolved_slo_violations,
            },
        )

    return {"updated_patterns": updated_patterns, "resolved_slo_violations": resolved_slo_violations}


def _evaluate_launch_gate(agent_id: UUID) -> Dict[str, Any]:
    blockers: List[str] = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            org_id = agent_row[1]  # type: ignore[index]

            cur.execute(
                """
                select id, status::text
                from public.eval_runs
                where agent_id = %s
                order by created_at desc
                limit 1
                """,
                (str(agent_id),),
            )
            latest_run = cur.fetchone()
            latest_run_id = latest_run[0] if latest_run else None  # type: ignore[index]
            latest_run_status = latest_run[1] if latest_run else None  # type: ignore[index]
            if not latest_run:
                blockers.append("No eval run found.")
            elif latest_run_status != "completed":
                blockers.append("Latest eval run is not completed.")

            cur.execute(
                """
                select count(1)
                from public.issue_patterns
                where agent_id = %s
                  and priority = 'critical'::public.issue_priority
                  and status not in ('resolved'::public.issue_status, 'wont_fix'::public.issue_status)
                """,
                (str(agent_id),),
            )
            active_critical_issues = int(cur.fetchone()[0])  # type: ignore[index]
            if active_critical_issues > 0:
                blockers.append(f"{active_critical_issues} active critical issue(s).")

            cur.execute(
                """
                select count(1)
                from public.slo_violations
                where agent_id = %s
                  and status = 'open'::public.slo_violation_status
                """,
                (str(agent_id),),
            )
            open_slo_violations = int(cur.fetchone()[0])  # type: ignore[index]
            if open_slo_violations > 0:
                blockers.append(f"{open_slo_violations} open SLO violation(s).")

            cur.execute(
                """
                select items
                from public.launch_readiness
                where agent_id = %s
                limit 1
                """,
                (str(agent_id),),
            )
            readiness_row = cur.fetchone()
            readiness_pending_items = 0
            if not readiness_row:
                blockers.append("Launch readiness checklist not configured.")
            else:
                items = readiness_row[0] or []  # type: ignore[index]
                if isinstance(items, list):
                    readiness_pending_items = sum(1 for x in items if str((x or {}).get("status", "")).lower() != "done")
                if readiness_pending_items > 0:
                    blockers.append(f"{readiness_pending_items} readiness item(s) pending.")

    return {
        "org_id": org_id,
        "latest_run_id": latest_run_id,
        "latest_run_status": latest_run_status,
        "active_critical_issues": active_critical_issues,
        "open_slo_violations": open_slo_violations,
        "readiness_pending_items": readiness_pending_items,
        "can_launch": len(blockers) == 0,
        "blockers": blockers,
    }


def _create_or_reuse_regression_pattern(
    *,
    org_id: UUID,
    agent_id: UUID,
    baseline_run_id: UUID,
    candidate_run_id: UUID,
    regressions: List[EvalRunRegressionItem],
    answer_yes_rate_delta: float,
    source_yes_rate_delta: float,
    quality_good_rate_delta: float,
) -> Dict[str, Any]:
    open_statuses = ("detected", "diagnosed", "assigned", "in_progress", "regressed")
    case_ids = sorted({str(item.case_id) for item in regressions})
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id
                from public.issue_patterns
                where agent_id = %s
                  and primary_tag = 'regression_compare'
                  and status::text = any(%s)
                  and verification_result->>'baseline_run_id' = %s
                  and verification_result->>'candidate_run_id' = %s
                order by created_at desc
                limit 1
                """,
                (str(agent_id), list(open_statuses), str(baseline_run_id), str(candidate_run_id)),
            )
            existing = cur.fetchone()
            if existing:
                return {"enabled": True, "created": False, "pattern_id": str(existing[0])}

            title = f"Regression detected: {str(baseline_run_id)[:8]} -> {str(candidate_run_id)[:8]}"
            root_cause = "Candidate run quality regressed against baseline on shared golden set cases."
            suggested_fix = "Review model/prompt/retrieval changes and re-run compare after mitigation."
            history = [
                {
                    "detected_at": now_iso,
                    "regression_count": len(regressions),
                    "answer_yes_rate_delta": answer_yes_rate_delta,
                    "source_yes_rate_delta": source_yes_rate_delta,
                    "quality_good_rate_delta": quality_good_rate_delta,
                }
            ]
            status_history = [{"from": None, "to": "detected", "at": now_iso}]
            verification_result = {
                "baseline_run_id": str(baseline_run_id),
                "candidate_run_id": str(candidate_run_id),
                "regression_count": len(regressions),
            }

            cur.execute(
                """
                insert into public.issue_patterns (
                    org_id,
                    agent_id,
                    title,
                    primary_tag,
                    related_tags,
                    status,
                    priority,
                    root_cause,
                    root_cause_type,
                    suggested_fix,
                    linked_case_ids,
                    history,
                    status_history,
                    fix_notes,
                    verification_result
                )
                values (
                    %s, %s, %s, 'regression_compare', %s::text[],
                    'detected'::public.issue_status,
                    'high'::public.issue_priority,
                    %s,
                    'config'::public.root_cause_type,
                    %s,
                    %s::uuid[],
                    %s::jsonb,
                    %s::jsonb,
                    '[]'::jsonb,
                    %s::jsonb
                )
                returning id
                """,
                (
                    str(org_id),
                    str(agent_id),
                    title,
                    ["regression", "eval_compare"],
                    root_cause,
                    suggested_fix,
                    case_ids,
                    json.dumps(history),
                    json.dumps(status_history),
                    json.dumps(verification_result),
                ),
            )
            created_row = cur.fetchone()
            return {"enabled": True, "created": True, "pattern_id": str(created_row[0])}


@app.exception_handler(HTTPException)
async def http_exception_handler(_, exc: HTTPException):  # type: ignore[override]
    if isinstance(exc.detail, dict) and "ok" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"ok": False, "error": {"code": "HTTP_ERROR", "message": str(exc.detail)}},
    )


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(_, exc: RequestValidationError):  # type: ignore[override]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "ok": False,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed.",
                "details": exc.errors(),
            },
        },
    )


@app.get("/health", response_model=HealthResponse)
def health() -> Dict[str, Any]:
    return {"ok": True, "data": {"status": "healthy"}}


@app.post("/api/system/api-keys", status_code=status.HTTP_201_CREATED, response_model=ApiKeyCreateResponse)
def create_api_key(
    payload: ApiKeyCreateRequest = Body(
        ...,
        examples=[
            {
                "name": "create-key",
                "summary": "Create an org-scoped API key",
                "value": {"name": "ci-key", "org_id": None, "expires_at": None},
            }
        ],
    ),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    # Plaintext key is returned once at creation time.
    plaintext = f"sk_live_{secrets.token_urlsafe(24)}"
    key_hash = _api_key_hash(plaintext)
    key_prefix = plaintext[:10]

    caller_org = _caller_org_id(api_key_ctx)
    target_org_id = payload.org_id
    if caller_org:
        target_org_id = UUID(caller_org)
    _assert_org_access(api_key_ctx, str(target_org_id) if target_org_id else None, context="api_key_create")
    if target_org_id is None and payload.role != "admin":
        _error(
            "API_KEY_SCOPE_ROLE_INVALID",
            "Global API keys must use role=admin.",
            status.HTTP_400_BAD_REQUEST,
        )
    expires_at = payload.expires_at or (datetime.now(timezone.utc) + timedelta(days=API_KEY_DEFAULT_TTL_DAYS))

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.api_keys (org_id, name, role, key_prefix, key_hash, status, expires_at)
                    values (%s, %s, %s::public.api_key_role, %s, %s, 'active', %s)
                    returning id, org_id, name, role::text, key_prefix, status::text, expires_at, created_at
                    """,
                    (
                        str(target_org_id) if target_org_id else None,
                        payload.name,
                        payload.role,
                        key_prefix,
                        key_hash,
                        expires_at,
                    ),
                )
                row = cur.fetchone()
    except Exception as exc:
        _error("API_KEY_CREATE_FAILED", f"Failed to create API key: {exc}", status.HTTP_400_BAD_REQUEST)

    return {
        "ok": True,
        "data": {
            "id": str(row[0]),  # type: ignore[index]
            "org_id": str(row[1]) if row[1] else None,  # type: ignore[index]
            "name": row[2],  # type: ignore[index]
            "role": row[3],  # type: ignore[index]
            "key_prefix": row[4],  # type: ignore[index]
            "status": row[5],  # type: ignore[index]
            "expires_at": row[6].isoformat() if row[6] else None,  # type: ignore[index]
            "created_at": row[7].isoformat(),  # type: ignore[index]
            "api_key": plaintext,
        },
    }


@app.get("/api/system/api-keys", response_model=ApiKeyListResponse)
def list_api_keys(
    status_filter: Optional[Literal["active", "revoked"]] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            where = []
            params: List[Any] = []
            caller_org = _caller_org_id(api_key_ctx)
            if caller_org:
                where.append("org_id = %s")
                params.append(caller_org)
            if status_filter is not None:
                where.append("status::text = %s")
                params.append(status_filter)
            where_sql = f"where {' and '.join(where)}" if where else ""

            cur.execute(
                f"""
                select
                  id,
                  org_id,
                  name,
                  role::text,
                  key_prefix,
                  status::text,
                  expires_at,
                  last_used_at,
                  created_at
                from public.api_keys
                {where_sql}
                order by created_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.api_keys
                {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = [
        ApiKeyListItem(
            id=r[0],
            org_id=r[1],
            name=r[2],
            role=r[3],
            key_prefix=r[4],
            status=r[5],
            expires_at=r[6],
            last_used_at=r[7],
            created_at=r[8],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {
        "ok": True,
        "data": {
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/system/audit-logs", response_model=ApiAuditLogListResponse)
def list_api_audit_logs(
    request_id: Optional[str] = Query(default=None),
    path: Optional[str] = Query(default=None),
    method: Optional[Literal["POST", "PATCH", "PUT", "DELETE"]] = Query(default=None),
    status_code: Optional[int] = Query(default=None, ge=100, le=599),
    error_code: Optional[str] = Query(default=None),
    agent_id: Optional[UUID] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    where = []
    params: List[Any] = []
    caller_org = _caller_org_id(api_key_ctx)
    if caller_org:
        where.append("al.org_id = %s")
        params.append(caller_org)

    if request_id is not None:
        where.append("al.request_id = %s")
        params.append(request_id)
    if path is not None:
        where.append("al.path ilike %s")
        params.append(f"%{path}%")
    if method is not None:
        where.append("al.method = %s")
        params.append(method)
    if status_code is not None:
        where.append("al.status_code = %s")
        params.append(status_code)
    if error_code is not None:
        where.append("al.error_code = %s")
        params.append(error_code)
    if agent_id is not None:
        where.append(
            """
            exists (
              select 1
              from public.activity_events ae
              where ae.agent_id = %s
                and ae.metadata->>'request_id' = al.request_id
            )
            """
        )
        params.append(str(agent_id))

    where_sql = f"where {' and '.join(where)}" if where else ""

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select
                    al.id,
                    al.request_id,
                    al.api_key_id,
                    al.org_id,
                    al.method,
                    al.path,
                    al.status_code,
                    al.latency_ms,
                    al.error_code,
                    al.created_at
                from public.api_audit_logs al
                {where_sql}
                order by al.created_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.api_audit_logs al
                {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = [
        ApiAuditLogItem(
            id=r[0],
            request_id=r[1],
            api_key_id=r[2],
            org_id=r[3],
            method=r[4],
            path=r[5],
            status_code=int(r[6]),
            latency_ms=int(r[7]),
            error_code=r[8],
            created_at=r[9],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"items": items, "count": len(items), "total_count": total_count, "limit": limit, "offset": offset}}


@app.get("/api/system/queue/stats", response_model=QueueStatsResponse)
def get_queue_stats(
    org_id: Optional[UUID] = Query(default=None),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_stats")
    with get_conn() as conn:
        with conn.cursor() as cur:
            where_sql = ""
            params: List[Any] = []
            if scoped_org_id is not None:
                where_sql = "where org_id = %s"
                params.append(scoped_org_id)

            cur.execute(
                f"""
                select
                    count(*) filter (where status = 'queued') as queued_count,
                    count(*) filter (where status = 'running') as running_count,
                    count(*) filter (where status = 'succeeded') as succeeded_count,
                    count(*) filter (where status = 'failed') as failed_count,
                    count(*) filter (where status = 'cancelled') as cancelled_count,
                    count(*) filter (
                      where status = 'queued'
                        and attempt_count > 0
                        and attempt_count < max_attempts
                    ) as retry_backlog_count
                from public.eval_run_jobs
                {where_sql}
                """,
                tuple(params),
            )
            counts_row = cur.fetchone()

            cur.execute(
                f"""
                select extract(epoch from (now() - min(created_at)))::int
                from public.eval_run_jobs
                {where_sql}
                  {'and' if where_sql else 'where'} status = 'queued'
                """,
                tuple(params),
            )
            oldest_row = cur.fetchone()

    data = QueueStatsData(
        org_id=UUID(scoped_org_id) if scoped_org_id else None,
        queued_count=int(counts_row[0] or 0),  # type: ignore[index]
        running_count=int(counts_row[1] or 0),  # type: ignore[index]
        succeeded_count=int(counts_row[2] or 0),  # type: ignore[index]
        failed_count=int(counts_row[3] or 0),  # type: ignore[index]
        cancelled_count=int(counts_row[4] or 0),  # type: ignore[index]
        retry_backlog_count=int(counts_row[5] or 0),  # type: ignore[index]
        oldest_queued_age_seconds=int(oldest_row[0]) if oldest_row and oldest_row[0] is not None else None,  # type: ignore[index]
        checked_at=datetime.now(timezone.utc),
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/system/queue/jobs/failed", response_model=QueueJobListResponse)
def list_failed_queue_jobs(
    org_id: Optional[UUID] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_failed_jobs")
    where = ["j.status = 'failed'"]
    params: List[Any] = []
    if scoped_org_id:
        where.append("j.org_id = %s")
        params.append(scoped_org_id)
    where_sql = " and ".join(where)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select
                    j.id,
                    j.run_id,
                    j.org_id,
                    er.agent_id,
                    er.name,
                    er.status::text,
                    j.status,
                    j.attempt_count,
                    j.max_attempts,
                    j.error_message,
                    j.created_at,
                    j.updated_at,
                    j.completed_at
                from public.eval_run_jobs j
                left join public.eval_runs er on er.id = j.run_id
                where {where_sql}
                order by j.updated_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.eval_run_jobs j
                where {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = [
        QueueJobItem(
            job_id=r[0],
            run_id=r[1],
            org_id=r[2],
            agent_id=r[3],
            run_name=r[4],
            run_status=r[5],
            job_status=r[6],
            attempt_count=int(r[7] or 0),
            max_attempts=int(r[8] or 0),
            error_message=r[9],
            created_at=r[10],
            updated_at=r[11],
            completed_at=r[12],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"items": items, "count": len(items), "total_count": total_count, "limit": limit, "offset": offset}}


@app.post("/api/system/queue/jobs/{job_id}/retry", response_model=QueueJobRetryResponse)
def retry_queue_job(
    job_id: UUID = Path(...),
    delay_seconds: int = Query(default=0, ge=0, le=86400),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, run_id, org_id, status, attempt_count, max_attempts
                from public.eval_run_jobs
                where id = %s
                """,
                (str(job_id),),
            )
            job_row = cur.fetchone()
            if not job_row:
                _error("QUEUE_JOB_NOT_FOUND", f"Queue job {job_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(job_row[2]), context="system_queue_job_retry")  # type: ignore[index]
            if str(job_row[3]) != "failed":
                _error("QUEUE_JOB_NOT_RETRYABLE", "Only failed jobs can be retried.", status.HTTP_400_BAD_REQUEST)

            cur.execute(
                """
                update public.eval_run_jobs
                set
                    status = 'queued',
                    error_message = null,
                    not_before = case when %s > 0 then now() + (%s || ' seconds')::interval else null end,
                    locked_at = null,
                    locked_by = null,
                    completed_at = null,
                    updated_at = now()
                where id = %s
                returning id, run_id, status, attempt_count, max_attempts, not_before, org_id
                """,
                (delay_seconds, delay_seconds, str(job_id)),
            )
            row = cur.fetchone()

            cur.execute("select agent_id, status::text from public.eval_runs where id = %s", (str(row[1]),))
            run_row = cur.fetchone()
            agent_id = run_row[0] if run_row else None
            run_status = str(run_row[1]) if run_row and run_row[1] is not None else None
            if run_status in {"failed", "cancelled", "completed"}:
                try:
                    _assert_eval_run_transition_allowed(run_status, "pending")
                except EvalRunStateTransitionError as exc:
                    _error("EVAL_RUN_STATUS_TRANSITION_INVALID", str(exc), status.HTTP_409_CONFLICT)
                cur.execute(
                    """
                    update public.eval_runs
                    set status = 'pending',
                        started_at = null,
                        completed_at = null,
                        failure_reason = null
                    where id = %s
                    """,
                    (str(row[1]),),
                )

    if agent_id is not None:
        _record_activity_event(
            org_id=UUID(str(row[6])),  # type: ignore[index]
            agent_id=UUID(str(agent_id)),
            event_type="run_requeued",
            title="Eval run re-queued",
            details=f"run_id={str(row[1])[:8]}, delay={delay_seconds}s",
            severity="warning",
            metadata={"run_id": str(row[1]), "job_id": str(row[0]), "delay_seconds": delay_seconds},
        )

    data = QueueJobRetryData(
        job_id=row[0],  # type: ignore[index]
        run_id=row[1],  # type: ignore[index]
        status=row[2],  # type: ignore[index]
        attempt_count=int(row[3] or 0),  # type: ignore[index]
        max_attempts=int(row[4] or 0),  # type: ignore[index]
        not_before=row[5],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/queue/jobs/{job_id}/cancel", response_model=QueueJobCancelResponse)
def cancel_queue_job(
    job_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, run_id, org_id, status
                from public.eval_run_jobs
                where id = %s
                """,
                (str(job_id),),
            )
            row = cur.fetchone()
            if not row:
                _error("QUEUE_JOB_NOT_FOUND", f"Queue job {job_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(row[2]), context="system_queue_job_cancel")  # type: ignore[index]

            current_status = str(row[3])
            if current_status not in {"queued", "running"}:
                return {
                    "ok": True,
                    "data": {
                        "job_id": str(row[0]),
                        "run_id": str(row[1]),
                        "status": current_status,
                        "cancelled": False,
                    },
                }

            cur.execute(
                """
                update public.eval_run_jobs
                set status = 'cancelled',
                    cancelled_at = now(),
                    completed_at = now(),
                    locked_at = null,
                    locked_by = null,
                    updated_at = now()
                where id = %s
                returning id, run_id, status, org_id
                """,
                (str(job_id),),
            )
            updated = cur.fetchone()
            cur.execute("select agent_id from public.eval_runs where id = %s", (str(updated[1]),))
            run_row = cur.fetchone()
            agent_id = run_row[0] if run_row else None

    if agent_id is not None:
        _record_activity_event(
            org_id=UUID(str(updated[3])),  # type: ignore[index]
            agent_id=UUID(str(agent_id)),
            event_type="run_cancelled",
            title="Queue job cancelled",
            details=f"run_id={str(updated[1])[:8]}",
            severity="warning",
            metadata={"run_id": str(updated[1]), "job_id": str(updated[0])},
        )
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update public.eval_runs
                    set status = 'cancelled',
                        completed_at = coalesce(completed_at, now()),
                        failure_reason = coalesce(failure_reason, 'Cancelled by operator.')
                    where id = %s
                      and status in ('pending', 'running')
                    """,
                    (str(updated[1]),),
                )
    except Exception:
        pass
    return {
        "ok": True,
        "data": {
            "job_id": str(updated[0]),
            "run_id": str(updated[1]),
            "status": str(updated[2]),
            "cancelled": True,
        },
    }


@app.post("/api/system/queue/jobs/failed/replay", response_model=QueueJobsReplayResponse)
def replay_failed_queue_jobs(
    org_id: Optional[UUID] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    delay_seconds: int = Query(default=0, ge=0, le=3600),
    dry_run: bool = Query(default=False),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_failed_replay")
    selected_rows: List[Any]
    replayed_rows: List[Any] = []
    selected_agent_by_job_id: Dict[str, Any] = {}

    with get_conn() as conn:
        with conn.cursor() as cur:
            where = ["j.status = 'failed'"]
            params: List[Any] = []
            if scoped_org_id is not None:
                where.append("j.org_id = %s")
                params.append(scoped_org_id)
            where_sql = " and ".join(where)

            cur.execute(
                f"""
                select
                    j.id,
                    j.run_id,
                    j.org_id,
                    j.attempt_count,
                    j.max_attempts,
                    er.agent_id
                from public.eval_run_jobs j
                left join public.eval_runs er on er.id = j.run_id
                where {where_sql}
                order by j.updated_at asc, j.id asc
                limit %s
                """,
                (*params, limit),
            )
            selected_rows = cur.fetchall()
            selected_agent_by_job_id = {str(r[0]): r[5] for r in selected_rows}

            if not dry_run and selected_rows:
                selected_ids = [str(r[0]) for r in selected_rows]
                cur.execute(
                    """
                    update public.eval_run_jobs
                    set
                        status = 'queued',
                        error_message = null,
                        not_before = case when %s > 0 then now() + (%s || ' seconds')::interval else null end,
                        locked_at = null,
                        locked_by = null,
                        completed_at = null,
                        updated_at = now()
                    where id = any(%s::uuid[])
                      and status = 'failed'
                    returning id, run_id, org_id, attempt_count, max_attempts, not_before
                    """,
                    (delay_seconds, delay_seconds, selected_ids),
                )
                replayed_rows = cur.fetchall()
                replayed_run_ids = sorted({str(r[1]) for r in replayed_rows})
                if replayed_run_ids:
                    cur.execute(
                        """
                        select id, status::text
                        from public.eval_runs
                        where id = any(%s::uuid[])
                        """,
                        (replayed_run_ids,),
                    )
                    for run_row in cur.fetchall():
                        from_status = str(run_row[1])
                        if from_status in {"failed", "cancelled", "completed"}:
                            try:
                                _assert_eval_run_transition_allowed(from_status, "pending")
                            except EvalRunStateTransitionError as exc:
                                _error("EVAL_RUN_STATUS_TRANSITION_INVALID", str(exc), status.HTTP_409_CONFLICT)
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'pending',
                            started_at = null,
                            completed_at = null,
                            failure_reason = null
                        where id = any(%s::uuid[])
                          and status in ('failed', 'cancelled', 'completed')
                        """,
                        (replayed_run_ids,),
                    )

    if not dry_run:
        for row in replayed_rows:
            run_id = row[1]
            org_for_event = row[2]
            agent_id = selected_agent_by_job_id.get(str(row[0]))
            if agent_id is not None:
                _record_activity_event(
                    org_id=UUID(str(org_for_event)),
                    agent_id=UUID(str(agent_id)),
                    event_type="run_requeued_bulk",
                    title="Eval run re-queued by bulk replay",
                    details=f"run_id={str(run_id)[:8]}, delay={delay_seconds}s",
                    severity="warning",
                    metadata={"run_id": str(run_id), "job_id": str(row[0]), "delay_seconds": delay_seconds},
                )

    data = QueueJobsReplayData(
        org_id=UUID(str(scoped_org_id)) if scoped_org_id else None,
        dry_run=dry_run,
        requested_limit=limit,
        delay_seconds=delay_seconds,
        selected_count=len(selected_rows),
        replayed_count=len(replayed_rows) if not dry_run else 0,
        job_ids=[UUID(str(r[0])) for r in (selected_rows if dry_run else replayed_rows)],
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/queue/jobs/reap-stale", response_model=QueueJobsReapStaleResponse)
def reap_stale_queue_jobs(
    org_id: Optional[UUID] = Query(default=None),
    stale_heartbeat_seconds: Optional[int] = Query(default=None, ge=5, le=86400),
    max_runtime_seconds: Optional[int] = Query(default=None, ge=30, le=86400),
    limit: Optional[int] = Query(default=None, ge=1, le=500),
    dry_run: bool = Query(default=False),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_reap_stale")
    effective_stale_heartbeat_seconds = int(stale_heartbeat_seconds) if stale_heartbeat_seconds is not None else 60
    effective_max_runtime_seconds = int(max_runtime_seconds) if max_runtime_seconds is not None else 900
    effective_limit = int(limit) if limit is not None else 100
    if scoped_org_id is not None:
        policy = _get_queue_maintenance_policy(UUID(str(scoped_org_id)))
        if policy:
            if stale_heartbeat_seconds is None:
                effective_stale_heartbeat_seconds = int(policy["stale_heartbeat_seconds"])
            if max_runtime_seconds is None:
                effective_max_runtime_seconds = int(policy["max_runtime_seconds"])
            if limit is None:
                effective_limit = min(int(policy["reap_limit"]), 500)

    selected_rows: List[Any]
    reaped_rows: List[Any] = []
    selected_reason_by_job_id: Dict[str, str] = {}
    selected_agent_by_job_id: Dict[str, Any] = {}

    with get_conn() as conn:
        with conn.cursor() as cur:
            where = [
                "j.status = 'running'",
                "("
                " (j.heartbeat_at is not null and j.heartbeat_at < now() - (%s || ' seconds')::interval)"
                " or"
                " (j.run_started_at is not null and j.run_started_at < now() - (%s || ' seconds')::interval)"
                ")",
            ]
            params: List[Any] = [effective_stale_heartbeat_seconds, effective_max_runtime_seconds]
            if scoped_org_id is not None:
                where.append("j.org_id = %s")
                params.append(scoped_org_id)
            where_sql = " and ".join(where)

            cur.execute(
                f"""
                select
                    j.id,
                    j.run_id,
                    j.org_id,
                    er.agent_id,
                    case
                      when j.heartbeat_at is not null and j.heartbeat_at < now() - (%s || ' seconds')::interval
                        then 'stale_heartbeat'
                      when j.run_started_at is not null and j.run_started_at < now() - (%s || ' seconds')::interval
                        then 'runtime_exceeded'
                      else 'stale'
                    end as reason
                from public.eval_run_jobs j
                left join public.eval_runs er on er.id = j.run_id
                where {where_sql}
                order by j.run_started_at asc nulls first, j.id asc
                limit %s
                """,
                    (effective_stale_heartbeat_seconds, effective_max_runtime_seconds, *params, effective_limit),
            )
            selected_rows = cur.fetchall()
            selected_reason_by_job_id = {str(r[0]): str(r[4]) for r in selected_rows}
            selected_agent_by_job_id = {str(r[0]): r[3] for r in selected_rows}

            if not dry_run and selected_rows:
                selected_ids = [str(r[0]) for r in selected_rows]
                cur.execute(
                    """
                    update public.eval_run_jobs
                    set status = 'failed',
                        completed_at = now(),
                        error_message = coalesce(error_message, 'Job reaped by admin stale-job sweep.'),
                        locked_at = null,
                        locked_by = null,
                        heartbeat_at = null,
                        updated_at = now()
                    where id = any(%s::uuid[])
                      and status = 'running'
                    returning id, run_id, org_id, status
                    """,
                    (selected_ids,),
                )
                reaped_rows = cur.fetchall()

                reaped_run_ids = sorted({str(r[1]) for r in reaped_rows})
                if reaped_run_ids:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'failed',
                            completed_at = now(),
                            failure_reason = coalesce(failure_reason, 'Run reaped by admin stale-job sweep.')
                        where id = any(%s::uuid[])
                          and status = 'running'
                        """,
                        (reaped_run_ids,),
                    )

    if not dry_run:
        for row in reaped_rows:
            job_id = str(row[0])
            run_id = row[1]
            org_for_event = row[2]
            agent_id = selected_agent_by_job_id.get(job_id)
            reason = selected_reason_by_job_id.get(job_id, "stale")
            if agent_id is not None:
                _record_activity_event(
                    org_id=UUID(str(org_for_event)),
                    agent_id=UUID(str(agent_id)),
                    event_type="run_reaped",
                    title="Eval run reaped by admin sweep",
                    details=f"run_id={str(run_id)[:8]}, reason={reason}",
                    severity="error",
                    metadata={"run_id": str(run_id), "job_id": job_id, "reason": reason},
                )

    rows_for_items = selected_rows if dry_run else reaped_rows
    items = [
        QueueJobsReapItem(
            job_id=r[0],
            run_id=r[1],
            org_id=r[2],
            agent_id=selected_agent_by_job_id.get(str(r[0])),
            reason=selected_reason_by_job_id.get(str(r[0]), "stale"),
        )
        for r in rows_for_items
    ]
    data = QueueJobsReapStaleData(
        org_id=UUID(str(scoped_org_id)) if scoped_org_id else None,
        dry_run=dry_run,
        stale_heartbeat_seconds=effective_stale_heartbeat_seconds,
        max_runtime_seconds=effective_max_runtime_seconds,
        requested_limit=effective_limit,
        selected_count=len(selected_rows),
        reaped_count=0 if dry_run else len(reaped_rows),
        items=items,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/queue/jobs/prune", response_model=QueueJobsPruneResponse)
def prune_terminal_queue_jobs(
    org_id: Optional[UUID] = Query(default=None),
    retention_days: Optional[int] = Query(default=None, ge=1, le=3650),
    limit: Optional[int] = Query(default=None, ge=1, le=5000),
    dry_run: bool = Query(default=False),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_prune")
    effective_retention_days = int(retention_days) if retention_days is not None else 14
    effective_limit = int(limit) if limit is not None else 500
    if scoped_org_id is not None:
        policy = _get_queue_maintenance_policy(UUID(str(scoped_org_id)))
        if policy:
            if retention_days is None:
                effective_retention_days = int(policy["retention_days"])
            if limit is None:
                effective_limit = min(int(policy["prune_limit"]), 5000)
    selected_rows: List[Any]
    deleted_rows: List[Any] = []

    with get_conn() as conn:
        with conn.cursor() as cur:
            where = [
                "status in ('succeeded', 'failed', 'cancelled')",
                "updated_at < now() - (%s || ' days')::interval",
            ]
            params: List[Any] = [effective_retention_days]
            if scoped_org_id is not None:
                where.append("org_id = %s")
                params.append(scoped_org_id)
            where_sql = " and ".join(where)

            cur.execute(
                f"""
                select id
                from public.eval_run_jobs
                where {where_sql}
                order by updated_at asc, id asc
                limit %s
                """,
                (*params, effective_limit),
            )
            selected_rows = cur.fetchall()

            if not dry_run and selected_rows:
                selected_ids = [str(r[0]) for r in selected_rows]
                cur.execute(
                    """
                    delete from public.eval_run_jobs
                    where id = any(%s::uuid[])
                    returning id
                    """,
                    (selected_ids,),
                )
                deleted_rows = cur.fetchall()

    data = QueueJobsPruneData(
        org_id=UUID(str(scoped_org_id)) if scoped_org_id else None,
        dry_run=dry_run,
        retention_days=effective_retention_days,
        requested_limit=effective_limit,
        selected_count=len(selected_rows),
        deleted_count=0 if dry_run else len(deleted_rows),
        job_ids=[UUID(str(r[0])) for r in (selected_rows if dry_run else deleted_rows)],
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/system/contracts/drift-policy", response_model=ContractDriftPolicyResponse, tags=["System"])
def get_contract_drift_policy(
    org_id: UUID = Query(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_contract_drift_policy_get")
    org_uuid = UUID(str(scoped_org_id))
    policy = _get_contract_drift_policy(org_uuid)
    if not policy:
        data = ContractDriftPolicyData(
            org_id=org_uuid,
            enabled=False,
            min_drift="breaking",
            promote_to_patterns=True,
            scan_limit=200,
            schedule_name="daily",
            schedule_window_minutes=1440,
            alert_enabled=False,
            alert_max_dedupe_hit_rate=0.7,
            alert_min_execution_rate=0.5,
            alert_cooldown_minutes=60,
            updated_by_api_key_id=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        return {"ok": True, "data": data.model_dump(mode="json")}
    data = ContractDriftPolicyData(**policy)
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/contracts/drift-policy", response_model=ContractDriftPolicyResponse, tags=["System"])
def upsert_contract_drift_policy(
    payload: ContractDriftPolicyUpsertRequest = Body(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="system_contract_drift_policy_upsert")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.orgs where id = %s", (str(payload.org_id),))
            if not cur.fetchone():
                _error("ORG_NOT_FOUND", f"Org {payload.org_id} was not found.", status.HTTP_404_NOT_FOUND)
            cur.execute(
                """
                insert into public.contract_drift_policies (
                    org_id, enabled, min_drift, promote_to_patterns, scan_limit,
                    schedule_name, schedule_window_minutes,
                    alert_enabled, alert_max_dedupe_hit_rate, alert_min_execution_rate, alert_cooldown_minutes,
                    updated_by_api_key_id
                )
                values (%s, %s, %s::text, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                on conflict (org_id) do update
                set enabled = excluded.enabled,
                    min_drift = excluded.min_drift,
                    promote_to_patterns = excluded.promote_to_patterns,
                    scan_limit = excluded.scan_limit,
                    schedule_name = excluded.schedule_name,
                    schedule_window_minutes = excluded.schedule_window_minutes,
                    alert_enabled = excluded.alert_enabled,
                    alert_max_dedupe_hit_rate = excluded.alert_max_dedupe_hit_rate,
                    alert_min_execution_rate = excluded.alert_min_execution_rate,
                    alert_cooldown_minutes = excluded.alert_cooldown_minutes,
                    updated_by_api_key_id = excluded.updated_by_api_key_id,
                    updated_at = now()
                returning
                    org_id,
                    enabled,
                    min_drift::text,
                    promote_to_patterns,
                    scan_limit,
                    schedule_name,
                    schedule_window_minutes,
                    alert_enabled,
                    alert_max_dedupe_hit_rate,
                    alert_min_execution_rate,
                    alert_cooldown_minutes,
                    updated_by_api_key_id,
                    created_at,
                    updated_at
                """,
                (
                    str(payload.org_id),
                    bool(payload.enabled),
                    payload.min_drift,
                    bool(payload.promote_to_patterns),
                    int(payload.scan_limit),
                    payload.schedule_name,
                    int(payload.schedule_window_minutes),
                    bool(payload.alert_enabled),
                    float(payload.alert_max_dedupe_hit_rate),
                    float(payload.alert_min_execution_rate),
                    int(payload.alert_cooldown_minutes),
                    _coerce_uuid_str(api_key_ctx.get("key_id")),
                ),
            )
            row = cur.fetchone()
    data = ContractDriftPolicyData(
        org_id=row[0],  # type: ignore[index]
        enabled=bool(row[1]),  # type: ignore[index]
        min_drift=row[2],  # type: ignore[index]
        promote_to_patterns=bool(row[3]),  # type: ignore[index]
        scan_limit=int(row[4]),  # type: ignore[index]
        schedule_name=str(row[5]),  # type: ignore[index]
        schedule_window_minutes=int(row[6]),  # type: ignore[index]
        alert_enabled=bool(row[7]),  # type: ignore[index]
        alert_max_dedupe_hit_rate=float(row[8]),  # type: ignore[index]
        alert_min_execution_rate=float(row[9]),  # type: ignore[index]
        alert_cooldown_minutes=int(row[10]),  # type: ignore[index]
        updated_by_api_key_id=row[11],  # type: ignore[index]
        created_at=row[12],  # type: ignore[index]
        updated_at=row[13],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/contracts/drift/trigger", response_model=ContractDriftTriggerResponse, tags=["System"])
def trigger_contract_drift_policy(
    payload: ContractDriftTriggerRequest = Body(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    scoped_org_id = _effective_org_for_scope(api_key_ctx, payload.org_id, context="system_contract_drift_trigger")
    org_uuid = UUID(str(scoped_org_id))
    policy = _get_contract_drift_policy(org_uuid)
    policy_enabled = bool((policy or {}).get("enabled", False))
    promote_to_patterns = bool((policy or {}).get("promote_to_patterns", True))
    min_drift = str(payload.min_drift or (policy or {}).get("min_drift", "breaking"))
    scan_limit = int(payload.limit if payload.limit is not None else (policy or {}).get("scan_limit", 200))
    if min_drift not in {"warning", "breaking", "invalid"}:
        _error("VALIDATION_ERROR", "min_drift must be warning|breaking|invalid.", status.HTTP_422_UNPROCESSABLE_ENTITY)

    schedule_name = payload.schedule_name.strip() or str((policy or {}).get("schedule_name", "manual"))
    window_minutes = int(payload.window_minutes)
    now = datetime.now(timezone.utc)
    window_seconds = window_minutes * 60
    bucket_epoch = int(now.timestamp()) // window_seconds * window_seconds
    window_started_at = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
    window_ends_at = window_started_at + timedelta(seconds=window_seconds)
    dedupe_key = f"{schedule_name}:{window_started_at.isoformat()}"
    audit_path = (
        "/api/system/contracts/drift/trigger?schedule_name="
        + quote(schedule_name, safe="")
        + "&dedupe_key="
        + quote(dedupe_key, safe="")
    )

    if not policy_enabled and not payload.force:
        _record_api_audit_log(
            request_id=f"{_current_request_id() or str(uuid4())}:contract-drift-policy-disabled",
            api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
            org_id=str(org_uuid),
            method="POST",
            path=audit_path,
            status_code=200,
            latency_ms=0,
            error_code="CONTRACT_DRIFT_TRIGGER_POLICY_DISABLED",
        )
        data = ContractDriftTriggerData(
            org_id=org_uuid,
            schedule_name=schedule_name,
            window_minutes=window_minutes,
            window_started_at=window_started_at,
            dedupe_key=dedupe_key,
            executed=False,
            deduped=False,
            policy_enabled=False,
            min_drift=min_drift,  # type: ignore[arg-type]
            scan_limit=scan_limit,
            dry_run=bool(payload.dry_run),
            reason="policy_disabled",
            promote_result=None,
        )
        return {"ok": True, "data": data.model_dump(mode="json")}

    if not promote_to_patterns and not payload.force:
        _record_api_audit_log(
            request_id=f"{_current_request_id() or str(uuid4())}:contract-drift-promotion-disabled",
            api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
            org_id=str(org_uuid),
            method="POST",
            path=audit_path,
            status_code=200,
            latency_ms=0,
            error_code="CONTRACT_DRIFT_TRIGGER_PROMOTION_DISABLED",
        )
        data = ContractDriftTriggerData(
            org_id=org_uuid,
            schedule_name=schedule_name,
            window_minutes=window_minutes,
            window_started_at=window_started_at,
            dedupe_key=dedupe_key,
            executed=False,
            deduped=False,
            policy_enabled=policy_enabled,
            min_drift=min_drift,  # type: ignore[arg-type]
            scan_limit=scan_limit,
            dry_run=bool(payload.dry_run),
            reason="promotion_disabled",
            promote_result=None,
        )
        return {"ok": True, "data": data.model_dump(mode="json")}

    if not payload.force:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id
                    from public.api_audit_logs
                    where org_id = %s
                      and path = %s
                      and error_code = 'CONTRACT_DRIFT_TRIGGER_EXECUTED'
                      and created_at >= %s
                      and created_at < %s
                    order by created_at desc
                    limit 1
                    """,
                    (str(org_uuid), audit_path, window_started_at, window_ends_at),
                )
                if cur.fetchone():
                    _record_api_audit_log(
                        request_id=f"{_current_request_id() or str(uuid4())}:contract-drift-deduped",
                        api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
                        org_id=str(org_uuid),
                        method="POST",
                        path=audit_path,
                        status_code=200,
                        latency_ms=0,
                        error_code="CONTRACT_DRIFT_TRIGGER_DEDUPED",
                    )
                    data = ContractDriftTriggerData(
                        org_id=org_uuid,
                        schedule_name=schedule_name,
                        window_minutes=window_minutes,
                        window_started_at=window_started_at,
                        dedupe_key=dedupe_key,
                        executed=False,
                        deduped=True,
                        policy_enabled=policy_enabled,
                        min_drift=min_drift,  # type: ignore[arg-type]
                        scan_limit=scan_limit,
                        dry_run=bool(payload.dry_run),
                        reason="deduped",
                        promote_result=None,
                    )
                    return {"ok": True, "data": data.model_dump(mode="json")}

    promote_resp = promote_contract_drift_patterns(
        ContractDriftPromotePatternsRequest(
            org_id=org_uuid,
            agent_id=payload.agent_id,
            min_drift=min_drift,  # type: ignore[arg-type]
            dry_run=bool(payload.dry_run),
            limit=scan_limit,
        ),
        api_key_ctx=api_key_ctx,
    )
    promote_data = ContractDriftPromotePatternsData(**promote_resp["data"])
    _record_api_audit_log(
        request_id=f"{_current_request_id() or str(uuid4())}:contract-drift-executed",
        api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
        org_id=str(org_uuid),
        method="POST",
        path=audit_path,
        status_code=200,
        latency_ms=0,
        error_code="CONTRACT_DRIFT_TRIGGER_EXECUTED",
    )
    data = ContractDriftTriggerData(
        org_id=org_uuid,
        schedule_name=schedule_name,
        window_minutes=window_minutes,
        window_started_at=window_started_at,
        dedupe_key=dedupe_key,
        executed=True,
        deduped=False,
        policy_enabled=policy_enabled,
        min_drift=min_drift,  # type: ignore[arg-type]
        scan_limit=scan_limit,
        dry_run=bool(payload.dry_run),
        reason=None,
        promote_result=promote_data,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


def _compute_contract_drift_trigger_summary_data(
    *,
    org_id: UUID,
    schedule_name: Optional[str],
    window_days: int,
    limit: int,
) -> "ContractDriftTriggerSummaryData":
    schedule_prefix = (
        f"/api/system/contracts/drift/trigger?schedule_name={quote(schedule_name, safe='')}"
        if schedule_name
        else "/api/system/contracts/drift/trigger?schedule_name="
    )
    path_pattern = f"{schedule_prefix}%"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    count(*)::bigint as trigger_count,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_TRIGGER_EXECUTED')::bigint as executed_count,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_TRIGGER_DEDUPED')::bigint as deduped_count,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_TRIGGER_POLICY_DISABLED')::bigint as policy_disabled_count,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_TRIGGER_PROMOTION_DISABLED')::bigint as promotion_disabled_count,
                    max(created_at) as last_triggered_at
                from public.api_audit_logs
                where org_id = %s
                  and path like %s
                  and created_at >= (now() - (%s::int * interval '1 day'))
                """,
                (str(org_id), path_pattern, int(window_days)),
            )
            stats = cur.fetchone()
            cur.execute(
                """
                select request_id, status_code, error_code, created_at, path
                from public.api_audit_logs
                where org_id = %s
                  and path like %s
                  and created_at >= (now() - (%s::int * interval '1 day'))
                order by created_at desc
                limit %s
                """,
                (str(org_id), path_pattern, int(window_days), int(limit)),
            )
            rows = cur.fetchall()

    trigger_count = int(stats[0] or 0)  # type: ignore[index]
    executed_count = int(stats[1] or 0)  # type: ignore[index]
    deduped_count = int(stats[2] or 0)  # type: ignore[index]
    policy_disabled_count = int(stats[3] or 0)  # type: ignore[index]
    promotion_disabled_count = int(stats[4] or 0)  # type: ignore[index]
    execution_rate = float(executed_count / trigger_count) if trigger_count > 0 else 0.0
    dedupe_hit_rate = float(deduped_count / trigger_count) if trigger_count > 0 else 0.0
    items = [
        ContractDriftTriggerEventItem(
            request_id=str(r[0]),
            status_code=int(r[1]),
            error_code=str(r[2]),
            created_at=r[3],
            path=str(r[4]),
        )
        for r in rows
    ]
    return ContractDriftTriggerSummaryData(
        org_id=org_id,
        schedule_name=schedule_name,
        window_days=int(window_days),
        trigger_count=trigger_count,
        executed_count=executed_count,
        deduped_count=deduped_count,
        policy_disabled_count=policy_disabled_count,
        promotion_disabled_count=promotion_disabled_count,
        execution_rate=execution_rate,
        dedupe_hit_rate=dedupe_hit_rate,
        last_triggered_at=stats[5],  # type: ignore[index]
        items=items,
        count=len(items),
        limit=int(limit),
    )


@app.get("/api/system/contracts/drift/trigger-summary", response_model=ContractDriftTriggerSummaryResponse, tags=["System"])
def get_contract_drift_trigger_summary(
    org_id: UUID = Query(...),
    schedule_name: Optional[str] = Query(default=None),
    window_days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=50, ge=1, le=200),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_contract_drift_trigger_summary")
    org_uuid = UUID(str(scoped_org_id))
    data = _compute_contract_drift_trigger_summary_data(
        org_id=org_uuid,
        schedule_name=schedule_name,
        window_days=int(window_days),
        limit=int(limit),
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/contracts/drift/trigger-summary/notify", response_model=ContractDriftTriggerNotifyResponse, tags=["System"])
def notify_contract_drift_trigger_summary(
    payload: ContractDriftTriggerNotifyRequest = Body(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    scoped_org_id = _effective_org_for_scope(api_key_ctx, payload.org_id, context="system_contract_drift_trigger_summary_notify")
    org_uuid = UUID(str(scoped_org_id))
    summary = _compute_contract_drift_trigger_summary_data(
        org_id=org_uuid,
        schedule_name=payload.schedule_name,
        window_days=int(payload.window_days),
        limit=50,
    )
    policy = _get_contract_drift_policy(org_uuid) or {}
    alert_enabled = bool(policy.get("alert_enabled", False))
    threshold_max_dedupe = float(policy.get("alert_max_dedupe_hit_rate", 0.7))
    threshold_min_execution = float(policy.get("alert_min_execution_rate", 0.5))
    cooldown_minutes = int(policy.get("alert_cooldown_minutes", 60))

    alerts: List[str] = []
    if summary.dedupe_hit_rate >= threshold_max_dedupe:
        alerts.append(
            f"dedupe_hit_rate {summary.dedupe_hit_rate:.3f} >= threshold {threshold_max_dedupe:.3f}"
        )
    if summary.execution_rate < threshold_min_execution:
        alerts.append(
            f"execution_rate {summary.execution_rate:.3f} < threshold {threshold_min_execution:.3f}"
        )
    anomaly_detected = len(alerts) > 0

    should_notify = (alert_enabled and anomaly_detected) or bool(payload.force_notify)
    escalation_pattern: Optional[Dict[str, Any]] = None
    notification_result: Dict[str, Any] = {
        "event_type": "contract_drift_trigger_anomaly",
        "queued": False,
        "sent": False,
        "skipped": True,
    }
    suppressed = False
    notify_audit_path = "/api/system/contracts/drift/trigger-summary/notify?schedule_name=" + quote(
        payload.schedule_name or "_all", safe=""
    )
    notify_audit_code = "CONTRACT_DRIFT_ANOMALY_NOTIFY_SKIPPED"

    if should_notify and not payload.dry_run and not payload.force_notify:
        alert_fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "schedule_name": payload.schedule_name,
                    "alerts": alerts,
                    "dedupe_hit_rate": round(summary.dedupe_hit_rate, 6),
                    "execution_rate": round(summary.execution_rate, 6),
                    "window_days": int(payload.window_days),
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        cooldown_state = _check_and_mark_contract_drift_alert_cooldown(
            org_id=org_uuid,
            schedule_name=payload.schedule_name,
            alert_fingerprint=alert_fingerprint,
            cooldown_minutes=cooldown_minutes,
        )
        suppressed = bool(cooldown_state.get("suppressed"))
        if suppressed:
            notification_result = {
                "event_type": "contract_drift_trigger_anomaly",
                "queued": False,
                "sent": False,
                "skipped": True,
                "suppressed": True,
                "suppression_reason": str(cooldown_state.get("reason") or "cooldown"),
                "cooldown_minutes": int(cooldown_state.get("cooldown_minutes") or cooldown_minutes),
                "last_notified_at": cooldown_state.get("last_notified_at"),
            }
            notify_audit_code = "CONTRACT_DRIFT_ANOMALY_NOTIFY_SUPPRESSED"

    if should_notify and not payload.dry_run and not suppressed:
        notification_result = _dispatch_notification(
            org_id=org_uuid,
            agent_id=payload.agent_id,
            event_type="contract_drift_trigger_anomaly",
            payload={
                "org_id": str(org_uuid),
                "agent_id": str(payload.agent_id) if payload.agent_id else None,
                "schedule_name": payload.schedule_name,
                "window_days": int(payload.window_days),
                "anomaly_detected": anomaly_detected,
                "alerts": alerts,
                "thresholds": {
                    "max_dedupe_hit_rate": threshold_max_dedupe,
                    "min_execution_rate": threshold_min_execution,
                },
                "summary": summary.model_dump(mode="json"),
                "cooldown_minutes": cooldown_minutes,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        notify_audit_code = (
            "CONTRACT_DRIFT_ANOMALY_NOTIFY_SENT"
            if notification_result.get("sent")
            else "CONTRACT_DRIFT_ANOMALY_NOTIFY_FAILED"
        )
    elif bool(payload.dry_run):
        notify_audit_code = "CONTRACT_DRIFT_ANOMALY_NOTIFY_DRY_RUN"

    if should_notify and not payload.dry_run and not suppressed and not bool(notification_result.get("sent")):
        escalation_agent_id = _resolve_contract_drift_escalation_agent_id(
            org_id=org_uuid,
            preferred_agent_id=payload.agent_id,
        )
        if escalation_agent_id is None:
            escalation_pattern = {"created": False, "pattern_id": None, "reason": "no_agent_found"}
        else:
            escalation_pattern = _create_or_reuse_contract_drift_notify_failure_pattern(
                org_id=org_uuid,
                agent_id=escalation_agent_id,
                schedule_name=payload.schedule_name,
                window_days=int(payload.window_days),
                dedupe_hit_rate=summary.dedupe_hit_rate,
                execution_rate=summary.execution_rate,
                error_message=str(notification_result.get("error") or "notification_send_failed"),
            )

    _record_api_audit_log(
        request_id=f"{_current_request_id() or str(uuid4())}:contract-drift-notify",
        api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
        org_id=str(org_uuid),
        method="POST",
        path=notify_audit_path,
        status_code=200,
        latency_ms=0,
        error_code=notify_audit_code,
    )

    data = ContractDriftTriggerNotifyData(
        org_id=org_uuid,
        schedule_name=payload.schedule_name,
        agent_id=payload.agent_id,
        window_days=int(payload.window_days),
        anomaly_detected=anomaly_detected,
        dedupe_hit_rate=summary.dedupe_hit_rate,
        execution_rate=summary.execution_rate,
        threshold_max_dedupe_hit_rate=threshold_max_dedupe,
        threshold_min_execution_rate=threshold_min_execution,
        alerts=alerts,
        dry_run=bool(payload.dry_run),
        notified=bool(should_notify and not payload.dry_run and not suppressed and notification_result.get("sent")),
        notification=notification_result,
        escalation_pattern=escalation_pattern,
        summary=summary,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/contracts/drift/schedule-run", response_model=ContractDriftScheduleRunResponse, tags=["System"])
def run_contract_drift_schedule(
    payload: ContractDriftScheduleRunRequest = Body(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    try:
        scoped_org_id = _effective_org_for_scope(api_key_ctx, payload.org_id, context="system_contract_drift_schedule_run")
        org_uuid = UUID(str(scoped_org_id))
        policy = _get_contract_drift_policy(org_uuid) or {}
        effective_schedule_name = (payload.schedule_name or str(policy.get("schedule_name", "daily"))).strip() or "daily"
        effective_window_minutes = int(
            payload.window_minutes if payload.window_minutes is not None else int(policy.get("schedule_window_minutes", 1440))
        )

        trigger_resp = trigger_contract_drift_policy(
            payload=ContractDriftTriggerRequest(
                org_id=org_uuid,
                schedule_name=effective_schedule_name,
                window_minutes=effective_window_minutes,
                dry_run=bool(payload.dry_run),
                force=bool(payload.force),
                agent_id=payload.agent_id,
                min_drift=payload.min_drift,
                limit=payload.limit,
            ),
            api_key_ctx=api_key_ctx,
            idem_key=f"{idem_key}:trigger",
        )
        trigger_data = ContractDriftTriggerData(**trigger_resp["data"])

        notify_resp = notify_contract_drift_trigger_summary(
            payload=ContractDriftTriggerNotifyRequest(
                org_id=org_uuid,
                schedule_name=effective_schedule_name,
                agent_id=payload.agent_id,
                window_days=int(payload.summary_window_days),
                dry_run=bool(payload.dry_run),
                force_notify=bool(payload.force_notify),
            ),
            api_key_ctx=api_key_ctx,
            idem_key=f"{idem_key}:notify",
        )
        notify_data = ContractDriftTriggerNotifyData(**notify_resp["data"])

        _record_api_audit_log(
            request_id=f"{_current_request_id() or str(uuid4())}:contract-drift-schedule-run",
            api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
            org_id=str(org_uuid),
            method="POST",
            path="/api/system/contracts/drift/schedule-run?schedule_name=" + quote(effective_schedule_name, safe=""),
            status_code=200,
            latency_ms=0,
            error_code="CONTRACT_DRIFT_SCHEDULE_RUN_EXECUTED",
        )

        data = ContractDriftScheduleRunData(
            org_id=org_uuid,
            schedule_name=effective_schedule_name,
            window_minutes=effective_window_minutes,
            summary_window_days=int(payload.summary_window_days),
            dry_run=bool(payload.dry_run),
            force=bool(payload.force),
            force_notify=bool(payload.force_notify),
            trigger=trigger_data,
            notify=notify_data,
        )
        return {"ok": True, "data": data.model_dump(mode="json")}
    except HTTPException:
        raise
    except Exception as exc:
        _error(
            "CONTRACT_DRIFT_SCHEDULE_RUN_FAILED",
            f"Failed to run contract drift schedule: {exc}",
            status.HTTP_400_BAD_REQUEST,
        )


@app.get(
    "/api/system/contracts/drift/trigger-alert-delivery",
    response_model=ContractDriftTriggerAlertDeliveryResponse,
    tags=["System"],
)
def get_contract_drift_trigger_alert_delivery(
    org_id: UUID = Query(...),
    schedule_name: Optional[str] = Query(default=None),
    window_days: int = Query(default=30, ge=1, le=365),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_contract_drift_trigger_alert_delivery")
    org_uuid = UUID(str(scoped_org_id))
    notify_base_path = "/api/system/contracts/drift/trigger-summary/notify"
    encoded_schedule = quote(schedule_name or "_all", safe="")
    notify_path = f"{notify_base_path}?schedule_name={encoded_schedule}"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    count(*)::bigint as total_notify_events,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_ANOMALY_NOTIFY_SENT')::bigint as sent_count,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_ANOMALY_NOTIFY_FAILED')::bigint as failed_count,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_ANOMALY_NOTIFY_SUPPRESSED')::bigint as suppressed_count,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_ANOMALY_NOTIFY_SKIPPED')::bigint as skipped_count,
                    count(*) filter (where error_code = 'CONTRACT_DRIFT_ANOMALY_NOTIFY_DRY_RUN')::bigint as dry_run_count,
                    max(created_at) as last_event_at,
                    max(created_at) filter (where error_code = 'CONTRACT_DRIFT_ANOMALY_NOTIFY_SENT') as last_sent_at,
                    max(created_at) filter (where error_code = 'CONTRACT_DRIFT_ANOMALY_NOTIFY_FAILED') as last_failed_at,
                    max(created_at) filter (where error_code = 'CONTRACT_DRIFT_ANOMALY_NOTIFY_SUPPRESSED') as last_suppressed_at
                from public.api_audit_logs
                where org_id = %s
                  and path = %s
                  and created_at >= (now() - (%s::int * interval '1 day'))
                """,
                (str(org_uuid), notify_path, int(window_days)),
            )
            stats = cur.fetchone()
            cur.execute(
                """
                select last_notified_at
                from public.contract_drift_trigger_alert_state
                where org_id = %s and schedule_name = %s
                limit 1
                """,
                (str(org_uuid), schedule_name or "_all"),
            )
            state_row = cur.fetchone()

    data = ContractDriftTriggerAlertDeliveryData(
        org_id=org_uuid,
        schedule_name=schedule_name,
        window_days=int(window_days),
        total_notify_events=int(stats[0] or 0),  # type: ignore[index]
        sent_count=int(stats[1] or 0),  # type: ignore[index]
        failed_count=int(stats[2] or 0),  # type: ignore[index]
        suppressed_count=int(stats[3] or 0),  # type: ignore[index]
        skipped_count=int(stats[4] or 0),  # type: ignore[index]
        dry_run_count=int(stats[5] or 0),  # type: ignore[index]
        last_event_at=stats[6],  # type: ignore[index]
        last_sent_at=stats[7],  # type: ignore[index]
        last_failed_at=stats[8],  # type: ignore[index]
        last_suppressed_at=stats[9],  # type: ignore[index]
        last_notified_at=state_row[0] if state_row else None,  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/system/queue/maintenance-policy", response_model=QueueMaintenancePolicyResponse)
def get_queue_maintenance_policy(
    org_id: UUID = Query(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_maintenance_policy_get")
    policy = _get_queue_maintenance_policy(UUID(str(scoped_org_id)))
    if not policy:
        data = QueueMaintenancePolicyData(
            org_id=UUID(str(scoped_org_id)),
            stale_heartbeat_seconds=60,
            max_runtime_seconds=900,
            retention_days=14,
            reap_limit=100,
            prune_limit=500,
            schedule_alert_enabled=False,
            schedule_alert_dedupe_hit_rate_threshold=0.7,
            schedule_alert_min_execution_success_rate=0.9,
            schedule_alert_cooldown_minutes=60,
            updated_by_api_key_id=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        return {"ok": True, "data": data.model_dump(mode="json")}

    data = QueueMaintenancePolicyData(**policy)
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/queue/maintenance-policy", response_model=QueueMaintenancePolicyResponse)
def upsert_queue_maintenance_policy(
    payload: QueueMaintenancePolicyUpsertRequest = Body(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="system_queue_maintenance_policy_upsert")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.orgs where id = %s", (str(payload.org_id),))
            if not cur.fetchone():
                _error("ORG_NOT_FOUND", f"Org {payload.org_id} was not found.", status.HTTP_404_NOT_FOUND)
            cur.execute(
                """
                insert into public.queue_maintenance_policies (
                    org_id,
                    stale_heartbeat_seconds,
                    max_runtime_seconds,
                    retention_days,
                    reap_limit,
                    prune_limit,
                    schedule_alert_enabled,
                    schedule_alert_dedupe_hit_rate_threshold,
                    schedule_alert_min_execution_success_rate,
                    schedule_alert_cooldown_minutes,
                    updated_by_api_key_id
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                on conflict (org_id) do update
                set
                    stale_heartbeat_seconds = excluded.stale_heartbeat_seconds,
                    max_runtime_seconds = excluded.max_runtime_seconds,
                    retention_days = excluded.retention_days,
                    reap_limit = excluded.reap_limit,
                    prune_limit = excluded.prune_limit,
                    schedule_alert_enabled = excluded.schedule_alert_enabled,
                    schedule_alert_dedupe_hit_rate_threshold = excluded.schedule_alert_dedupe_hit_rate_threshold,
                    schedule_alert_min_execution_success_rate = excluded.schedule_alert_min_execution_success_rate,
                    schedule_alert_cooldown_minutes = excluded.schedule_alert_cooldown_minutes,
                    updated_by_api_key_id = excluded.updated_by_api_key_id,
                    updated_at = now()
                returning
                    org_id,
                    stale_heartbeat_seconds,
                    max_runtime_seconds,
                    retention_days,
                    reap_limit,
                    prune_limit,
                    schedule_alert_enabled,
                    schedule_alert_dedupe_hit_rate_threshold,
                    schedule_alert_min_execution_success_rate,
                    schedule_alert_cooldown_minutes,
                    updated_by_api_key_id,
                    created_at,
                    updated_at
                """,
                (
                    str(payload.org_id),
                    int(payload.stale_heartbeat_seconds),
                    int(payload.max_runtime_seconds),
                    int(payload.retention_days),
                    int(payload.reap_limit),
                    int(payload.prune_limit),
                    bool(payload.schedule_alert_enabled),
                    float(payload.schedule_alert_dedupe_hit_rate_threshold),
                    float(payload.schedule_alert_min_execution_success_rate),
                    int(payload.schedule_alert_cooldown_minutes),
                    str(api_key_ctx.get("key_id")) if api_key_ctx.get("key_id") else None,
                ),
            )
            row = cur.fetchone()

    data = QueueMaintenancePolicyData(
        org_id=row[0],  # type: ignore[index]
        stale_heartbeat_seconds=int(row[1]),  # type: ignore[index]
        max_runtime_seconds=int(row[2]),  # type: ignore[index]
        retention_days=int(row[3]),  # type: ignore[index]
        reap_limit=int(row[4]),  # type: ignore[index]
        prune_limit=int(row[5]),  # type: ignore[index]
        schedule_alert_enabled=bool(row[6]),  # type: ignore[index]
        schedule_alert_dedupe_hit_rate_threshold=float(row[7]),  # type: ignore[index]
        schedule_alert_min_execution_success_rate=float(row[8]),  # type: ignore[index]
        schedule_alert_cooldown_minutes=int(row[9]),  # type: ignore[index]
        updated_by_api_key_id=row[10],  # type: ignore[index]
        created_at=row[11],  # type: ignore[index]
        updated_at=row[12],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/queue/maintenance/run", response_model=QueueMaintenanceRunResponse)
def run_queue_maintenance(
    org_id: UUID = Query(...),
    dry_run: bool = Query(default=True),
    stale_heartbeat_seconds: Optional[int] = Query(default=None, ge=5, le=86400),
    max_runtime_seconds: Optional[int] = Query(default=None, ge=30, le=86400),
    retention_days: Optional[int] = Query(default=None, ge=1, le=3650),
    reap_limit: Optional[int] = Query(default=None, ge=1, le=500),
    prune_limit: Optional[int] = Query(default=None, ge=1, le=5000),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_maintenance_run")
    org_uuid = UUID(str(scoped_org_id))
    run_id: Optional[UUID] = None
    started_at = datetime.now(timezone.utc)

    policy_row = _get_queue_maintenance_policy(org_uuid)
    effective_stale_heartbeat_seconds = int(stale_heartbeat_seconds) if stale_heartbeat_seconds is not None else 60
    effective_max_runtime_seconds = int(max_runtime_seconds) if max_runtime_seconds is not None else 900
    effective_retention_days = int(retention_days) if retention_days is not None else 14
    effective_reap_limit = int(reap_limit) if reap_limit is not None else 100
    effective_prune_limit = int(prune_limit) if prune_limit is not None else 500
    if policy_row is not None:
        if stale_heartbeat_seconds is None:
            effective_stale_heartbeat_seconds = int(policy_row["stale_heartbeat_seconds"])
        if max_runtime_seconds is None:
            effective_max_runtime_seconds = int(policy_row["max_runtime_seconds"])
        if retention_days is None:
            effective_retention_days = int(policy_row["retention_days"])
        if reap_limit is None:
            effective_reap_limit = min(int(policy_row["reap_limit"]), 500)
        if prune_limit is None:
            effective_prune_limit = min(int(policy_row["prune_limit"]), 5000)

    policy_snapshot = {
        "stale_heartbeat_seconds": effective_stale_heartbeat_seconds,
        "max_runtime_seconds": effective_max_runtime_seconds,
        "retention_days": effective_retention_days,
        "reap_limit": effective_reap_limit,
        "prune_limit": effective_prune_limit,
    }
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.queue_maintenance_runs (
                        org_id, dry_run, status, policy_snapshot, triggered_by_api_key_id
                    )
                    values (%s, %s, 'running', %s::jsonb, %s)
                    returning id, started_at
                    """,
                    (
                        str(org_uuid),
                        bool(dry_run),
                        json.dumps(policy_snapshot),
                        str(api_key_ctx.get("key_id")) if api_key_ctx.get("key_id") else None,
                    ),
                )
                inserted = cur.fetchone()
                run_id = inserted[0]  # type: ignore[index]
                started_at_raw = inserted[1]  # type: ignore[index]
                if isinstance(started_at_raw, datetime):
                    started_at = started_at_raw if started_at_raw.tzinfo else started_at_raw.replace(tzinfo=timezone.utc)
                elif isinstance(started_at_raw, str):
                    started_at = datetime.fromisoformat(started_at_raw.replace("Z", "+00:00"))
                else:
                    started_at = datetime.now(timezone.utc)
    except Exception as exc:
        msg = str(exc)
        if (
            "idx_queue_maintenance_runs_one_running_per_org" in msg
            or ("duplicate key value violates unique constraint" in msg and "queue_maintenance_runs" in msg)
        ):
            _error(
                "QUEUE_MAINTENANCE_ALREADY_RUNNING",
                "A maintenance run is already active for this org.",
                409,
            )
        raise

    try:
        reap_resp = reap_stale_queue_jobs(
            org_id=org_uuid,
            stale_heartbeat_seconds=effective_stale_heartbeat_seconds,
            max_runtime_seconds=effective_max_runtime_seconds,
            limit=effective_reap_limit,
            dry_run=dry_run,
            api_key_ctx=api_key_ctx,
            idem_key=f"{idem_key}:reap",
        )
        prune_resp = prune_terminal_queue_jobs(
            org_id=org_uuid,
            retention_days=effective_retention_days,
            limit=effective_prune_limit,
            dry_run=dry_run,
            api_key_ctx=api_key_ctx,
            idem_key=f"{idem_key}:prune",
        )

        completed_at = datetime.now(timezone.utc)
        duration_ms = int(round((completed_at - started_at).total_seconds() * 1000))
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update public.queue_maintenance_runs
                    set
                        status = 'completed',
                        reap_summary = %s::jsonb,
                        prune_summary = %s::jsonb,
                        duration_ms = %s,
                        completed_at = %s
                    where id = %s
                    """,
                    (
                        json.dumps(reap_resp["data"]),
                        json.dumps(prune_resp["data"]),
                        duration_ms,
                        completed_at,
                        str(run_id),
                    ),
                )

        data = QueueMaintenanceRunData(
            run_id=run_id,
            org_id=org_uuid,
            dry_run=dry_run,
            status="completed",
            error_message=None,
            duration_ms=duration_ms,
            triggered_by_api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
            policy=QueueMaintenanceRunPolicy(**policy_snapshot),
            reap=QueueJobsReapStaleData(**reap_resp["data"]),
            prune=QueueJobsPruneData(**prune_resp["data"]),
            started_at=started_at,
            completed_at=completed_at,
        )
        return {"ok": True, "data": data.model_dump(mode="json")}
    except Exception as exc:
        completed_at = datetime.now(timezone.utc)
        duration_ms = int(round((completed_at - started_at).total_seconds() * 1000))
        if run_id is not None:
            try:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            update public.queue_maintenance_runs
                            set
                                status = 'failed',
                                error_message = %s,
                                duration_ms = %s,
                                completed_at = %s
                            where id = %s
                            """,
                            (str(exc)[:4000], duration_ms, completed_at, str(run_id)),
                        )
            except Exception:
                pass
        raise


@app.post("/api/system/queue/maintenance/schedule-trigger", response_model=QueueMaintenanceScheduleTriggerResponse)
def trigger_queue_maintenance_schedule(
    payload: QueueMaintenanceScheduleTriggerRequest = Body(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, payload.org_id, context="system_queue_maintenance_schedule_trigger")
    org_uuid = UUID(str(scoped_org_id))
    now = datetime.now(timezone.utc)
    window_seconds = int(payload.window_minutes) * 60
    bucket_epoch = int(now.timestamp()) // window_seconds * window_seconds
    window_started_at = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
    window_ends_at = window_started_at + timedelta(seconds=window_seconds)
    dedupe_key = f"{payload.schedule_name}:{window_started_at.isoformat()}"
    audit_path = "/api/system/queue/maintenance/schedule-trigger?schedule_name=" + quote(payload.schedule_name, safe="")

    if not payload.force:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select
                        id, org_id, dry_run, status, error_message, duration_ms, triggered_by_api_key_id,
                        policy_snapshot, reap_summary, prune_summary, started_at, completed_at
                    from public.queue_maintenance_runs
                    where org_id = %s
                      and triggered_by_api_key_id = %s
                      and status = 'completed'
                      and started_at >= %s
                      and started_at < %s
                      and coalesce(policy_snapshot->>'_schedule_dedupe_key', '') = %s
                    order by started_at desc, id desc
                    limit 1
                    """,
                    (
                        str(org_uuid),
                        str(api_key_ctx.get("key_id")) if api_key_ctx.get("key_id") else None,
                        window_started_at,
                        window_ends_at,
                        dedupe_key,
                    ),
                )
                row = cur.fetchone()
        if row is not None:
            policy_snapshot = row[7] or {}
            run_data = QueueMaintenanceRunData(
                run_id=row[0],
                org_id=row[1],
                dry_run=bool(row[2]),
                status=str(row[3]),
                error_message=row[4],
                duration_ms=int(row[5]) if row[5] is not None else None,
                triggered_by_api_key_id=row[6],
                policy=QueueMaintenanceRunPolicy(
                    stale_heartbeat_seconds=int(policy_snapshot.get("stale_heartbeat_seconds", 60)),
                    max_runtime_seconds=int(policy_snapshot.get("max_runtime_seconds", 900)),
                    retention_days=int(policy_snapshot.get("retention_days", 14)),
                    reap_limit=int(policy_snapshot.get("reap_limit", 100)),
                    prune_limit=int(policy_snapshot.get("prune_limit", 500)),
                ),
                reap=QueueJobsReapStaleData(**(row[8] or {})),
                prune=QueueJobsPruneData(**(row[9] or {})),
                started_at=row[10],
                completed_at=row[11],
            )
            data = QueueMaintenanceScheduleTriggerData(
                org_id=org_uuid,
                schedule_name=payload.schedule_name,
                window_minutes=int(payload.window_minutes),
                window_started_at=window_started_at,
                dedupe_key=dedupe_key,
                executed=False,
                deduped=True,
                run=run_data,
            )
            _record_api_audit_log(
                request_id=f"{_current_request_id() or str(uuid4())}:schedule-deduped",
                api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
                org_id=str(org_uuid),
                method="POST",
                path=audit_path,
                status_code=200,
                latency_ms=0,
                error_code="SCHEDULE_TRIGGER_DEDUPED",
            )
            return {"ok": True, "data": data.model_dump(mode="json")}

    trigger_idem_key = f"schedule-trigger:{dedupe_key}"
    run_response = run_queue_maintenance(
        org_id=org_uuid,
        dry_run=bool(payload.dry_run),
        stale_heartbeat_seconds=payload.stale_heartbeat_seconds,
        max_runtime_seconds=payload.max_runtime_seconds,
        retention_days=payload.retention_days,
        reap_limit=payload.reap_limit,
        prune_limit=payload.prune_limit,
        api_key_ctx=api_key_ctx,
        idem_key=trigger_idem_key,
    )
    run_data = QueueMaintenanceRunData(**run_response["data"])
    if run_data.run_id is not None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update public.queue_maintenance_runs
                    set policy_snapshot = policy_snapshot
                      || jsonb_build_object('_schedule_name', %s, '_schedule_dedupe_key', %s)
                    where id = %s
                    """,
                    (payload.schedule_name, dedupe_key, str(run_data.run_id)),
                )
    data = QueueMaintenanceScheduleTriggerData(
        org_id=org_uuid,
        schedule_name=payload.schedule_name,
        window_minutes=int(payload.window_minutes),
        window_started_at=window_started_at,
        dedupe_key=dedupe_key,
        executed=True,
        deduped=False,
        run=run_data,
    )
    _record_api_audit_log(
        request_id=f"{_current_request_id() or str(uuid4())}:schedule-executed",
        api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
        org_id=str(org_uuid),
        method="POST",
        path=audit_path,
        status_code=200,
        latency_ms=0,
        error_code="SCHEDULE_TRIGGER_EXECUTED",
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/system/queue/maintenance/runs", response_model=QueueMaintenanceRunListResponse)
def list_queue_maintenance_runs(
    org_id: Optional[UUID] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    if status_filter is not None and status_filter not in {"running", "completed", "failed"}:
        _error("VALIDATION_ERROR", "status must be one of: running, completed, failed.", status.HTTP_422_UNPROCESSABLE_ENTITY)
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_maintenance_runs_list")
    where: List[str] = []
    params: List[Any] = []
    if scoped_org_id is not None:
        where.append("org_id = %s")
        params.append(scoped_org_id)
    if status_filter is not None:
        where.append("status = %s")
        params.append(status_filter)
    where_sql = f"where {' and '.join(where)}" if where else ""

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select
                    id, org_id, dry_run, status, error_message, duration_ms,
                    triggered_by_api_key_id, started_at, completed_at
                from public.queue_maintenance_runs
                {where_sql}
                order by started_at desc, id desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()
            cur.execute(f"select count(*) from public.queue_maintenance_runs {where_sql}", tuple(params))
            total_count = int(cur.fetchone()[0] or 0)  # type: ignore[index]

    items = [
        QueueMaintenanceRunListItem(
            id=r[0],
            org_id=r[1],
            dry_run=bool(r[2]),
            status=str(r[3]),
            error_message=r[4],
            duration_ms=int(r[5]) if r[5] is not None else None,
            triggered_by_api_key_id=r[6],
            started_at=r[7],
            completed_at=r[8],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"items": items, "count": len(items), "total_count": total_count, "limit": limit, "offset": offset}}


@app.get("/api/system/queue/maintenance/runs/{run_id}", response_model=QueueMaintenanceRunDetailResponse)
def get_queue_maintenance_run(
    run_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    id, org_id, dry_run, status, policy_snapshot, reap_summary, prune_summary,
                    error_message, duration_ms, triggered_by_api_key_id,
                    started_at, completed_at, created_at, updated_at
                from public.queue_maintenance_runs
                where id = %s
                """,
                (str(run_id),),
            )
            row = cur.fetchone()
            if not row:
                _error("QUEUE_MAINTENANCE_RUN_NOT_FOUND", f"Queue maintenance run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(row[1]), context="system_queue_maintenance_run_detail")  # type: ignore[index]

    data = QueueMaintenanceRunDetailData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        dry_run=bool(row[2]),  # type: ignore[index]
        status=str(row[3]),  # type: ignore[index]
        policy_snapshot=row[4] or {},  # type: ignore[index]
        reap_summary=row[5],  # type: ignore[index]
        prune_summary=row[6],  # type: ignore[index]
        error_message=row[7],  # type: ignore[index]
        duration_ms=int(row[8]) if row[8] is not None else None,  # type: ignore[index]
        triggered_by_api_key_id=row[9],  # type: ignore[index]
        started_at=row[10],  # type: ignore[index]
        completed_at=row[11],  # type: ignore[index]
        created_at=row[12],  # type: ignore[index]
        updated_at=row[13],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/queue/maintenance/reap-stale-runs", response_model=QueueMaintenanceReapStaleResponse)
def reap_stale_queue_maintenance_runs(
    org_id: Optional[UUID] = Query(default=None),
    max_runtime_seconds: Optional[int] = Query(default=None, ge=30, le=86400),
    limit: int = Query(default=100, ge=1, le=500),
    dry_run: bool = Query(default=False),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_maintenance_reap_stale")
    effective_max_runtime_seconds = int(max_runtime_seconds) if max_runtime_seconds is not None else 900
    if scoped_org_id is not None and max_runtime_seconds is None:
        policy = _get_queue_maintenance_policy(UUID(str(scoped_org_id)))
        if policy:
            effective_max_runtime_seconds = int(policy["max_runtime_seconds"])

    selected_rows: List[Any]
    reaped_rows: List[Any] = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            where = [
                "status = 'running'",
                "started_at < now() - (%s || ' seconds')::interval",
            ]
            params: List[Any] = [effective_max_runtime_seconds]
            if scoped_org_id is not None:
                where.append("org_id = %s")
                params.append(scoped_org_id)
            where_sql = " and ".join(where)
            cur.execute(
                f"""
                select id, org_id, dry_run, started_at, duration_ms, status
                from public.queue_maintenance_runs
                where {where_sql}
                order by started_at asc, id asc
                limit %s
                """,
                (*params, int(limit)),
            )
            selected_rows = cur.fetchall()
            if not dry_run and selected_rows:
                selected_ids = [str(r[0]) for r in selected_rows]
                cur.execute(
                    """
                    update public.queue_maintenance_runs
                    set
                        status = 'failed',
                        error_message = coalesce(error_message, 'Maintenance run reaped by admin stale-run sweep.'),
                        duration_ms = coalesce(
                            duration_ms,
                            greatest(0, round(extract(epoch from (now() - started_at)) * 1000)::integer)
                        ),
                        completed_at = coalesce(completed_at, now()),
                        updated_at = now()
                    where id = any(%s::uuid[])
                      and status = 'running'
                    returning id, org_id, dry_run, started_at, duration_ms, status
                    """,
                    (selected_ids,),
                )
                reaped_rows = cur.fetchall()

    rows_for_items = selected_rows if dry_run else reaped_rows
    items = [
        QueueMaintenanceReapItem(
            run_id=r[0],
            org_id=r[1],
            dry_run=bool(r[2]),
            reason="runtime_exceeded",
            started_at=r[3],
            duration_ms=int(r[4]) if r[4] is not None else None,
            status=str(r[5]),
        )
        for r in rows_for_items
    ]
    if not dry_run and reaped_rows:
        base_req = _current_request_id() or str(uuid4())
        for idx, row in enumerate(reaped_rows, start=1):
            _record_api_audit_log(
                request_id=f"{base_req}:maintenance-reap:{idx}",
                api_key_id=str(api_key_ctx.get("key_id")) if api_key_ctx.get("key_id") else None,
                org_id=str(row[1]),
                method="POST",
                path="/api/system/queue/maintenance/reap-stale-runs",
                status_code=200,
                latency_ms=0,
                error_code="MAINTENANCE_RUN_REAPED",
            )

    data = QueueMaintenanceReapStaleData(
        org_id=UUID(str(scoped_org_id)) if scoped_org_id else None,
        dry_run=dry_run,
        max_runtime_seconds=effective_max_runtime_seconds,
        requested_limit=int(limit),
        selected_count=len(selected_rows),
        reaped_count=0 if dry_run else len(reaped_rows),
        items=items,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/system/queue/maintenance/metrics", response_model=QueueMaintenanceMetricsResponse)
def get_queue_maintenance_metrics(
    org_id: UUID = Query(...),
    window_days: int = Query(default=30, ge=1, le=365),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_maintenance_metrics")
    org_uuid = UUID(str(scoped_org_id))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    count(*)::bigint as total_runs,
                    count(*) filter (where status = 'running')::bigint as running_count,
                    count(*) filter (where status = 'completed')::bigint as completed_count,
                    count(*) filter (where status = 'failed')::bigint as failed_count,
                    count(*) filter (where dry_run = true)::bigint as dry_run_count,
                    avg(duration_ms) filter (where status = 'completed' and duration_ms is not null) as avg_duration_ms,
                    percentile_cont(0.5) within group (order by duration_ms)
                        filter (where status = 'completed' and duration_ms is not null) as p50_duration_ms,
                    percentile_cont(0.95) within group (order by duration_ms)
                        filter (where status = 'completed' and duration_ms is not null) as p95_duration_ms
                from public.queue_maintenance_runs
                where org_id = %s
                  and started_at >= (now() - (%s::int * interval '1 day'))
                """,
                (str(org_uuid), int(window_days)),
            )
            stats = cur.fetchone()
            cur.execute(
                """
                select started_at, status
                from public.queue_maintenance_runs
                where org_id = %s
                order by started_at desc, id desc
                limit 1
                """,
                (str(org_uuid),),
            )
            last_row = cur.fetchone()

    total_runs = int(stats[0] or 0)  # type: ignore[index]
    failed_count = int(stats[3] or 0)  # type: ignore[index]
    failure_rate = float(failed_count / total_runs) if total_runs > 0 else 0.0
    p50_raw = stats[6]  # type: ignore[index]
    p95_raw = stats[7]  # type: ignore[index]
    data = QueueMaintenanceMetricsData(
        org_id=org_uuid,
        window_days=int(window_days),
        total_runs=total_runs,
        running_count=int(stats[1] or 0),  # type: ignore[index]
        completed_count=int(stats[2] or 0),  # type: ignore[index]
        failed_count=failed_count,
        dry_run_count=int(stats[4] or 0),  # type: ignore[index]
        failure_rate=failure_rate,
        avg_duration_ms=float(stats[5]) if stats[5] is not None else None,  # type: ignore[index]
        p50_duration_ms=int(round(float(p50_raw))) if p50_raw is not None else None,
        p95_duration_ms=int(round(float(p95_raw))) if p95_raw is not None else None,
        last_run_started_at=last_row[0] if last_row else None,
        last_run_status=str(last_row[1]) if last_row else None,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/system/queue/maintenance/schedule-summary", response_model=QueueMaintenanceScheduleSummaryResponse)
def get_queue_maintenance_schedule_summary(
    org_id: UUID = Query(...),
    schedule_name: Optional[str] = Query(default=None),
    window_days: int = Query(default=30, ge=1, le=365),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_maintenance_schedule_summary")
    org_uuid = UUID(str(scoped_org_id))
    data = _compute_queue_maintenance_schedule_summary_data(
        org_id=org_uuid,
        schedule_name=schedule_name,
        window_days=int(window_days),
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/queue/maintenance/schedule-summary/notify", response_model=QueueMaintenanceScheduleNotifyResponse)
def notify_queue_maintenance_schedule_summary(
    payload: QueueMaintenanceScheduleNotifyRequest = Body(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
    idem_key: str = Depends(require_idempotency_key),
) -> Dict[str, Any]:
    _ = idem_key
    scoped_org_id = _effective_org_for_scope(api_key_ctx, payload.org_id, context="system_queue_maintenance_schedule_summary_notify")
    org_uuid = UUID(str(scoped_org_id))
    summary = _compute_queue_maintenance_schedule_summary_data(
        org_id=org_uuid,
        schedule_name=payload.schedule_name,
        window_days=int(payload.window_days),
    )
    policy = _get_queue_maintenance_policy(org_uuid) or {}
    alert_enabled = bool(policy.get("schedule_alert_enabled", False))
    threshold_dedupe = float(policy.get("schedule_alert_dedupe_hit_rate_threshold", 0.7))
    threshold_success = float(policy.get("schedule_alert_min_execution_success_rate", 0.9))
    cooldown_minutes = int(policy.get("schedule_alert_cooldown_minutes", 60))

    alerts: List[str] = []
    if summary.dedupe_hit_rate >= threshold_dedupe:
        alerts.append(
            f"dedupe_hit_rate {summary.dedupe_hit_rate:.3f} >= threshold {threshold_dedupe:.3f}"
        )
    if summary.execution_success_rate < threshold_success:
        alerts.append(
            f"execution_success_rate {summary.execution_success_rate:.3f} < threshold {threshold_success:.3f}"
        )
    anomaly_detected = len(alerts) > 0

    should_notify = (alert_enabled and anomaly_detected) or bool(payload.force_notify)
    notification_result: Dict[str, Any] = {"event_type": "maintenance_schedule_anomaly", "queued": False, "sent": False, "skipped": True}
    suppressed = False
    notify_audit_path = "/api/system/queue/maintenance/schedule-summary/notify?schedule_name=" + quote(
        payload.schedule_name or "_all", safe=""
    )
    notify_audit_code = "SCHEDULE_ANOMALY_NOTIFY_SKIPPED"
    if should_notify and not payload.dry_run and not payload.force_notify:
        alert_fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "schedule_name": payload.schedule_name,
                    "alerts": alerts,
                    "dedupe_hit_rate": round(summary.dedupe_hit_rate, 6),
                    "execution_success_rate": round(summary.execution_success_rate, 6),
                    "window_days": int(payload.window_days),
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        cooldown_state = _check_and_mark_schedule_alert_cooldown(
            org_id=org_uuid,
            schedule_name=payload.schedule_name,
            alert_fingerprint=alert_fingerprint,
            cooldown_minutes=cooldown_minutes,
        )
        suppressed = bool(cooldown_state.get("suppressed"))
        if suppressed:
            notification_result = {
                "event_type": "maintenance_schedule_anomaly",
                "queued": False,
                "sent": False,
                "skipped": True,
                "suppressed": True,
                "suppression_reason": str(cooldown_state.get("reason") or "cooldown"),
                "cooldown_minutes": int(cooldown_state.get("cooldown_minutes") or cooldown_minutes),
                "last_notified_at": cooldown_state.get("last_notified_at"),
            }
            notify_audit_code = "SCHEDULE_ANOMALY_NOTIFY_SUPPRESSED"

    if should_notify and not payload.dry_run and not suppressed:
        notification_result = _dispatch_notification(
            org_id=org_uuid,
            agent_id=None,
            event_type="maintenance_schedule_anomaly",
            payload={
                "org_id": str(org_uuid),
                "schedule_name": payload.schedule_name,
                "window_days": int(payload.window_days),
                "anomaly_detected": anomaly_detected,
                "alerts": alerts,
                "thresholds": {
                    "dedupe_hit_rate_threshold": threshold_dedupe,
                    "min_execution_success_rate": threshold_success,
                },
                "summary": summary.model_dump(mode="json"),
                "cooldown_minutes": cooldown_minutes,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        notify_audit_code = (
            "SCHEDULE_ANOMALY_NOTIFY_SENT" if notification_result.get("sent") else "SCHEDULE_ANOMALY_NOTIFY_FAILED"
        )
    elif bool(payload.dry_run):
        notify_audit_code = "SCHEDULE_ANOMALY_NOTIFY_DRY_RUN"

    _record_api_audit_log(
        request_id=f"{_current_request_id() or str(uuid4())}:schedule-notify",
        api_key_id=_coerce_uuid_str(api_key_ctx.get("key_id")),
        org_id=str(org_uuid),
        method="POST",
        path=notify_audit_path,
        status_code=200,
        latency_ms=0,
        error_code=notify_audit_code,
    )

    data = QueueMaintenanceScheduleNotifyData(
        org_id=org_uuid,
        schedule_name=payload.schedule_name,
        window_days=int(payload.window_days),
        anomaly_detected=anomaly_detected,
        dedupe_hit_rate=summary.dedupe_hit_rate,
        execution_success_rate=summary.execution_success_rate,
        threshold_dedupe_hit_rate=threshold_dedupe,
        threshold_min_execution_success_rate=threshold_success,
        alerts=alerts,
        dry_run=bool(payload.dry_run),
        notified=bool(should_notify and not payload.dry_run and not suppressed and notification_result.get("sent")),
        notification=notification_result,
        summary=summary,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get(
    "/api/system/queue/maintenance/schedule-alert-delivery",
    response_model=QueueMaintenanceScheduleAlertDeliveryResponse,
)
def get_queue_maintenance_schedule_alert_delivery(
    org_id: UUID = Query(...),
    schedule_name: Optional[str] = Query(default=None),
    window_days: int = Query(default=30, ge=1, le=365),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_queue_maintenance_schedule_alert_delivery")
    org_uuid = UUID(str(scoped_org_id))
    notify_base_path = "/api/system/queue/maintenance/schedule-summary/notify"
    encoded_schedule = quote(schedule_name or "_all", safe="")
    notify_path = f"{notify_base_path}?schedule_name={encoded_schedule}"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    count(*)::bigint as total_notify_events,
                    count(*) filter (where error_code = 'SCHEDULE_ANOMALY_NOTIFY_SENT')::bigint as sent_count,
                    count(*) filter (where error_code = 'SCHEDULE_ANOMALY_NOTIFY_FAILED')::bigint as failed_count,
                    count(*) filter (where error_code = 'SCHEDULE_ANOMALY_NOTIFY_SUPPRESSED')::bigint as suppressed_count,
                    count(*) filter (where error_code = 'SCHEDULE_ANOMALY_NOTIFY_SKIPPED')::bigint as skipped_count,
                    count(*) filter (where error_code = 'SCHEDULE_ANOMALY_NOTIFY_DRY_RUN')::bigint as dry_run_count,
                    max(created_at) as last_event_at,
                    max(created_at) filter (where error_code = 'SCHEDULE_ANOMALY_NOTIFY_SENT') as last_sent_at,
                    max(created_at) filter (where error_code = 'SCHEDULE_ANOMALY_NOTIFY_FAILED') as last_failed_at,
                    max(created_at) filter (where error_code = 'SCHEDULE_ANOMALY_NOTIFY_SUPPRESSED') as last_suppressed_at
                from public.api_audit_logs
                where org_id = %s
                  and path = %s
                  and created_at >= (now() - (%s::int * interval '1 day'))
                """,
                (str(org_uuid), notify_path, int(window_days)),
            )
            stats = cur.fetchone()
            cur.execute(
                """
                select last_notified_at
                from public.queue_maintenance_schedule_alert_state
                where org_id = %s and schedule_name = %s
                limit 1
                """,
                (str(org_uuid), schedule_name or "_all"),
            )
            state_row = cur.fetchone()

    data = QueueMaintenanceScheduleAlertDeliveryData(
        org_id=org_uuid,
        schedule_name=schedule_name,
        window_days=int(window_days),
        total_notify_events=int(stats[0] or 0),  # type: ignore[index]
        sent_count=int(stats[1] or 0),  # type: ignore[index]
        failed_count=int(stats[2] or 0),  # type: ignore[index]
        suppressed_count=int(stats[3] or 0),  # type: ignore[index]
        skipped_count=int(stats[4] or 0),  # type: ignore[index]
        dry_run_count=int(stats[5] or 0),  # type: ignore[index]
        last_event_at=stats[6],  # type: ignore[index]
        last_sent_at=stats[7],  # type: ignore[index]
        last_failed_at=stats[8],  # type: ignore[index]
        last_suppressed_at=stats[9],  # type: ignore[index]
        last_notified_at=state_row[0] if state_row else None,  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/notifications/outbox/drain", response_model=NotificationOutboxDrainResponse)
def drain_notification_outbox(
    limit: int = Query(default=20, ge=1, le=200),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    _ = api_key_ctx
    data = NotificationOutboxDrainData(**_drain_notification_outbox_batch(limit=limit))
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/system/notifications/outbox", response_model=NotificationOutboxListResponse)
def list_notification_outbox(
    org_id: Optional[UUID] = Query(default=None),
    status_filter: Optional[NotificationOutboxStatus] = Query(default=None, alias="status"),
    event_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_notification_outbox_list")
    where: List[str] = []
    params: List[Any] = []
    if scoped_org_id is not None:
        where.append("org_id = %s")
        params.append(scoped_org_id)
    if status_filter is not None:
        where.append("status = %s")
        params.append(status_filter)
    if event_type:
        where.append("event_type = %s")
        params.append(event_type)
    where_sql = f"where {' and '.join(where)}" if where else ""

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select count(*) from public.notification_outbox {where_sql}", tuple(params))
            total_count = int(cur.fetchone()[0] or 0)  # type: ignore[index]
            cur.execute(
                f"""
                select
                    id, org_id, agent_id, event_type, status,
                    attempt_count, max_attempts, next_attempt_at, sent_at,
                    last_error, source_request_id, created_at, updated_at
                from public.notification_outbox
                {where_sql}
                order by created_at desc, id desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

    items = [
        NotificationOutboxItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            event_type=r[3],
            status=r[4],
            attempt_count=int(r[5] or 0),
            max_attempts=int(r[6] or 0),
            next_attempt_at=r[7],
            sent_at=r[8],
            last_error=r[9],
            source_request_id=r[10],
            created_at=r[11],
            updated_at=r[12],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"items": items, "count": len(items), "total_count": total_count, "limit": limit, "offset": offset}}


@app.get(
    "/api/system/notifications/outbox/dead-letter-summary",
    response_model=NotificationOutboxDeadLetterSummaryResponse,
)
def notification_outbox_dead_letter_summary(
    org_id: Optional[UUID] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="system_notification_outbox_dead_letter_summary")
    where = ["status = 'dead'"]
    params: List[Any] = []
    if scoped_org_id is not None:
        where.append("org_id = %s")
        params.append(scoped_org_id)
    if event_type:
        where.append("event_type = %s")
        params.append(event_type)
    where_sql = " and ".join(where)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select count(*) as total_dead,
                       extract(epoch from (now() - min(created_at)))::int as oldest_dead_age_seconds
                from public.notification_outbox
                where {where_sql}
                """,
                tuple(params),
            )
            head = cur.fetchone()

            cur.execute(
                f"""
                select
                  coalesce(nullif(trim(last_error), ''), '(unknown)') as reason,
                  count(*) as c
                from public.notification_outbox
                where {where_sql}
                group by 1
                order by c desc, reason asc
                limit 10
                """,
                tuple(params),
            )
            reason_rows = cur.fetchall()

            cur.execute(
                f"""
                select bucket, count(*) as c
                from (
                  select case
                    when created_at >= now() - interval '1 hour' then 'lt_1h'
                    when created_at >= now() - interval '24 hours' then 'h_1_to_24'
                    when created_at >= now() - interval '7 days' then 'd_1_to_7'
                    else 'gte_7d'
                  end as bucket
                  from public.notification_outbox
                  where {where_sql}
                ) t
                group by bucket
                order by
                  case bucket
                    when 'lt_1h' then 1
                    when 'h_1_to_24' then 2
                    when 'd_1_to_7' then 3
                    else 4
                  end
                """,
                tuple(params),
            )
            age_rows = cur.fetchall()

    data = NotificationOutboxDeadLetterSummaryData(
        org_id=UUID(scoped_org_id) if scoped_org_id else None,
        event_type=event_type,
        total_dead=int(head[0] or 0),  # type: ignore[index]
        oldest_dead_age_seconds=int(head[1]) if head and head[1] is not None else None,  # type: ignore[index]
        reason_groups=[
            NotificationOutboxReasonGroup(reason=str(r[0]), count=int(r[1] or 0))
            for r in reason_rows
        ],
        age_buckets=[
            NotificationOutboxAgeBucket(bucket=str(r[0]), count=int(r[1] or 0))
            for r in age_rows
        ],
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/notifications/outbox/{outbox_id}/retry", response_model=NotificationOutboxRetryResponse)
def retry_notification_outbox_item(
    outbox_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, org_id, status, attempt_count, max_attempts, next_attempt_at
                from public.notification_outbox
                where id = %s
                """,
                (str(outbox_id),),
            )
            row = cur.fetchone()
            if not row:
                _error("NOTIFICATION_OUTBOX_NOT_FOUND", f"Outbox item {outbox_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(row[1]), context="system_notification_outbox_retry")  # type: ignore[index]
            if str(row[2]) == "sending":
                _error("NOTIFICATION_OUTBOX_IN_PROGRESS", "Outbox item is currently sending.", status.HTTP_409_CONFLICT)

            cur.execute(
                """
                update public.notification_outbox
                set status = 'pending',
                    attempt_count = case when status = 'dead' then 0 else attempt_count end,
                    next_attempt_at = now(),
                    last_error = null,
                    updated_at = now()
                where id = %s
                returning id, org_id, status, attempt_count, max_attempts, next_attempt_at
                """,
                (str(outbox_id),),
            )
            updated = cur.fetchone()

    data = NotificationOutboxRetryData(
        id=updated[0],  # type: ignore[index]
        org_id=updated[1],  # type: ignore[index]
        status=updated[2],  # type: ignore[index]
        attempt_count=int(updated[3] or 0),  # type: ignore[index]
        max_attempts=int(updated[4] or 0),  # type: ignore[index]
        next_attempt_at=updated[5],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/system/api-keys/{key_id}/revoke", response_model=ApiKeyRevokeResponse)
def revoke_api_key(
    key_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.api_keys where id = %s", (str(key_id),))
            key_row = cur.fetchone()
            if not key_row:
                _error("API_KEY_NOT_FOUND", f"API key {key_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(key_row[1]) if key_row[1] else None, context="api_key_revoke")
            cur.execute(
                """
                update public.api_keys
                set status = 'revoked'
                where id = %s
                returning id, status::text
                """,
                (str(key_id),),
            )
            row = cur.fetchone()

    return {"ok": True, "data": {"id": str(row[0]), "status": row[1]}}  # type: ignore[index]


@app.post("/api/eval/templates", status_code=status.HTTP_201_CREATED, response_model=EvalTemplateCreateResponse)
def create_eval_template(
    payload: EvalTemplateCreateRequest,
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="eval_template_create")
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                if payload.default_golden_set_id is not None:
                    cur.execute(
                        "select id from public.golden_sets where id = %s and org_id = %s",
                        (str(payload.default_golden_set_id), str(payload.org_id)),
                    )
                    if not cur.fetchone():
                        _error(
                            "GOLDEN_SET_NOT_FOUND",
                            f"Golden set {payload.default_golden_set_id} was not found for this org.",
                            status.HTTP_404_NOT_FOUND,
                        )
                cur.execute(
                    """
                    insert into public.eval_templates (
                        org_id, name, description, run_type, agent_type, default_golden_set_id, config, design_context, is_active
                    )
                    values (%s, %s, %s, %s::public.eval_run_type, %s::public.agent_type, %s, %s::jsonb, %s::jsonb, %s)
                    returning id, org_id, name, description, run_type::text, agent_type::text,
                              default_golden_set_id, config, design_context, is_active, created_at, updated_at
                    """,
                    (
                        str(payload.org_id),
                        payload.name.strip(),
                        payload.description,
                        payload.run_type,
                        payload.agent_type,
                        str(payload.default_golden_set_id) if payload.default_golden_set_id else None,
                        json.dumps(payload.config),
                        json.dumps(payload.design_context),
                        bool(payload.is_active),
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("EVAL_TEMPLATE_CREATE_FAILED", f"Failed to create eval template: {exc}", status.HTTP_400_BAD_REQUEST)

    item = EvalTemplateItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        name=row[2],  # type: ignore[index]
        description=row[3],  # type: ignore[index]
        run_type=row[4],  # type: ignore[index]
        agent_type=row[5],  # type: ignore[index]
        default_golden_set_id=row[6],  # type: ignore[index]
        config=row[7] or {},  # type: ignore[index]
        design_context=row[8] or {},  # type: ignore[index]
        is_active=bool(row[9]),  # type: ignore[index]
        created_at=row[10],  # type: ignore[index]
        updated_at=row[11],  # type: ignore[index]
    )
    return {"ok": True, "data": item.model_dump(mode="json")}


@app.get("/api/eval/templates", response_model=EvalTemplateListResponse)
def list_eval_templates(
    org_id: UUID = Query(...),
    run_type: Optional[RunType] = Query(default=None),
    agent_type: Optional[AgentType] = Query(default=None),
    include_inactive: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(org_id), context="eval_template_list")
    where = ["org_id = %s"]
    params: List[Any] = [str(org_id)]
    if run_type is not None:
        where.append("run_type::text = %s")
        params.append(run_type)
    if agent_type is not None:
        where.append("(agent_type is null or agent_type::text = %s)")
        params.append(agent_type)
    if not include_inactive:
        where.append("is_active = true")
    where_sql = " and ".join(where)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select id, org_id, name, description, run_type::text, agent_type::text,
                       default_golden_set_id, config, design_context, is_active, created_at, updated_at
                from public.eval_templates
                where {where_sql}
                order by updated_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

    items = [
        EvalTemplateItem(
            id=r[0],
            org_id=r[1],
            name=r[2],
            description=r[3],
            run_type=r[4],
            agent_type=r[5],
            default_golden_set_id=r[6],
            config=r[7] or {},
            design_context=r[8] or {},
            is_active=bool(r[9]),
            created_at=r[10],
            updated_at=r[11],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"items": items, "count": len(items), "limit": limit, "offset": offset}}


@app.get("/api/eval/templates/{template_id}", response_model=EvalTemplateDetailResponse)
def get_eval_template(
    template_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, org_id, name, description, run_type::text, agent_type::text,
                       default_golden_set_id, config, design_context, is_active, created_at, updated_at
                from public.eval_templates
                where id = %s
                """,
                (str(template_id),),
            )
            row = cur.fetchone()
            if not row:
                _error("EVAL_TEMPLATE_NOT_FOUND", f"Eval template {template_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(row[1]), context="eval_template_read")  # type: ignore[index]

    item = EvalTemplateItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        name=row[2],  # type: ignore[index]
        description=row[3],  # type: ignore[index]
        run_type=row[4],  # type: ignore[index]
        agent_type=row[5],  # type: ignore[index]
        default_golden_set_id=row[6],  # type: ignore[index]
        config=row[7] or {},  # type: ignore[index]
        design_context=row[8] or {},  # type: ignore[index]
        is_active=bool(row[9]),  # type: ignore[index]
        created_at=row[10],  # type: ignore[index]
        updated_at=row[11],  # type: ignore[index]
    )
    return {"ok": True, "data": item.model_dump(mode="json")}


@app.post("/api/eval/runs", status_code=status.HTTP_202_ACCEPTED, response_model=EvalRunCreateResponse)
def create_eval_run(
    payload: EvalRunCreateRequest = Body(
        ...,
        examples=[
            {
                "name": "create-run",
                "summary": "Create pending eval run",
                "value": {
                    "org_id": "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb",
                    "agent_id": "e3660b25-47cf-47f3-ab53-c080fb7ffdcc",
                    "template_id": "11111111-1111-1111-1111-111111111111",
                    "golden_set_id": "6755aac9-2d1e-46bd-8962-5731dbe4b6b5",
                    "name": "acme-gs-exec-001",
                    "type": "eval",
                    "config": {"sample_size": "all"},
                    "design_context": {"reason": "execute endpoint test"},
                },
            }
        ],
    ),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="eval_run_create")
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id, agent_type::text from public.agents where id = %s", (str(payload.agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {payload.agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                if str(agent_row[1]) != str(payload.org_id):  # type: ignore[index]
                    _error("EVAL_RUN_ORG_MISMATCH", "agent_id does not belong to org_id.", status.HTTP_400_BAD_REQUEST)
                agent_type = str(agent_row[2])  # type: ignore[index]

                effective_golden_set_id = payload.golden_set_id
                effective_config = dict(payload.config)
                effective_design_context = dict(payload.design_context)

                if payload.template_id is not None:
                    cur.execute(
                        """
                        select
                            id,
                            org_id,
                            name,
                            run_type::text,
                            agent_type::text,
                            default_golden_set_id,
                            config,
                            design_context,
                            is_active
                        from public.eval_templates
                        where id = %s
                        """,
                        (str(payload.template_id),),
                    )
                    template_row = cur.fetchone()
                    if not template_row:
                        _error(
                            "EVAL_TEMPLATE_NOT_FOUND",
                            f"Eval template {payload.template_id} was not found.",
                            status.HTTP_404_NOT_FOUND,
                        )
                    if str(template_row[1]) != str(payload.org_id):  # type: ignore[index]
                        _error(
                            "EVAL_TEMPLATE_MISMATCH",
                            "template_id does not belong to org_id.",
                            status.HTTP_400_BAD_REQUEST,
                        )
                    if not bool(template_row[8]):  # type: ignore[index]
                        _error(
                            "EVAL_TEMPLATE_INACTIVE",
                            f"Eval template {payload.template_id} is inactive.",
                            status.HTTP_400_BAD_REQUEST,
                        )
                    template_run_type = str(template_row[3])  # type: ignore[index]
                    template_agent_type = template_row[4]  # type: ignore[index]
                    if payload.type != template_run_type:
                        _error(
                            "EVAL_TEMPLATE_MISMATCH",
                            "payload.type must match template run_type.",
                            status.HTTP_400_BAD_REQUEST,
                        )
                    if template_agent_type and str(template_agent_type) != agent_type:
                        _error(
                            "EVAL_TEMPLATE_MISMATCH",
                            "template agent_type does not match selected agent.",
                            status.HTTP_400_BAD_REQUEST,
                        )
                    template_default_golden_set_id = template_row[5]  # type: ignore[index]
                    template_config = template_row[6] or {}  # type: ignore[index]
                    template_design_context = template_row[7] or {}  # type: ignore[index]
                    if not isinstance(template_config, dict) or not isinstance(template_design_context, dict):
                        _error(
                            "EVAL_TEMPLATE_INVALID",
                            "template config/design_context must be JSON objects.",
                            status.HTTP_400_BAD_REQUEST,
                        )
                    if effective_golden_set_id is None and template_default_golden_set_id is not None:
                        effective_golden_set_id = template_default_golden_set_id
                    effective_config = {**template_config, **effective_config}
                    effective_design_context = {**template_design_context, **effective_design_context}
                    effective_design_context["template_id"] = str(template_row[0])  # type: ignore[index]
                    effective_design_context["template_name"] = str(template_row[2])  # type: ignore[index]

                if effective_golden_set_id is not None:
                    cur.execute(
                        "select id from public.golden_sets where id = %s and org_id = %s and agent_id = %s",
                        (str(effective_golden_set_id), str(payload.org_id), str(payload.agent_id)),
                    )
                    if not cur.fetchone():
                        _error(
                            "GOLDEN_SET_NOT_FOUND",
                            f"Golden set {effective_golden_set_id} was not found for this org/agent.",
                            status.HTTP_404_NOT_FOUND,
                        )
                cur.execute(
                    """
                    insert into public.eval_runs (
                        org_id, agent_id, golden_set_id, name, type, status, config, design_context
                    )
                    values (%s, %s, %s, %s, %s::public.eval_run_type, 'pending', %s::jsonb, %s::jsonb)
                    returning id, status, created_at
                    """,
                    (
                        str(payload.org_id),
                        str(payload.agent_id),
                        str(effective_golden_set_id) if effective_golden_set_id else None,
                        payload.name,
                        payload.type,
                        json.dumps(effective_config),
                        json.dumps(effective_design_context),
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("EVAL_RUN_CREATE_FAILED", f"Failed to create eval run: {exc}", status.HTTP_400_BAD_REQUEST)

    _record_activity_event(
        org_id=payload.org_id,
        agent_id=payload.agent_id,
        event_type="run_created",
        title="Eval run created",
        details=f"run_id={str(row[0])[:8]}, type={payload.type}",
        severity="info",
        metadata={"run_id": str(row[0]), "run_type": payload.type},
    )

    data = EvalRunCreateData(run_id=row[0], status=row[1], created_at=row[2])  # type: ignore[index]
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/eval/runs/{run_id}/start", status_code=status.HTTP_202_ACCEPTED, response_model=EvalRunQueueStartResponse)
def start_eval_run(
    run_id: UUID = Path(...),
    max_attempts: int = Query(default=3, ge=1, le=10),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select id, org_id, agent_id, golden_set_id, type::text, status::text, config from public.eval_runs where id = %s",
                (str(run_id),),
            )
            run_row = cur.fetchone()
            if not run_row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(run_row[1]), context="eval_run_start")  # type: ignore[index]
            run_type = str(run_row[4])
            run_status = str(run_row[5])
            run_config = run_row[6] or {}  # type: ignore[index]
            if not isinstance(run_config, dict):
                run_config = {}
            run_handler = _resolve_run_type_handler(
                agent_id=UUID(str(run_row[2])),
                run_type=run_type,
                run_config=run_config,
            )
            _enforce_run_type_handler_mode(
                handler_key=str(run_handler.get("handler_key", "default")),
                handler_config=dict(run_handler.get("handler_config") or {}),
                entrypoint="start",
            )
            if run_status == "running":
                _error("EVAL_RUN_ALREADY_RUNNING", f"Eval run {run_id} is already running.", status.HTTP_409_CONFLICT)
            org_id = UUID(str(run_row[1]))  # type: ignore[index]
            agent_id = UUID(str(run_row[2]))  # type: ignore[index]
            _enforce_calibration_gate(agent_id=agent_id, run_type=run_type, run_config=run_config)
            _enforce_golden_set_quality_gate(
                agent_id=agent_id,
                golden_set_id=UUID(str(run_row[3])) if run_row[3] is not None else None,
                run_config=run_config,
            )
            _enforce_configured_gates(
                agent_id=agent_id,
                run_type=run_type,
                golden_set_id=UUID(str(run_row[3])) if run_row[3] is not None else None,
                run_config=run_config,
            )
            _enforce_agent_contract_issues(
                agent_id=agent_id,
                run_type=run_type,
                entrypoint="start",
                golden_set_id=UUID(str(run_row[3])) if run_row[3] is not None else None,
            )
            if run_status in {"failed", "cancelled", "completed"}:
                try:
                    _assert_eval_run_transition_allowed(run_status, "pending")
                except EvalRunStateTransitionError as exc:
                    _error("EVAL_RUN_STATUS_TRANSITION_INVALID", str(exc), status.HTTP_409_CONFLICT)
                cur.execute(
                    """
                    update public.eval_runs
                    set status = 'pending',
                        started_at = null,
                        completed_at = null,
                        failure_reason = null
                    where id = %s
                    """,
                    (str(run_id),),
                )

    queued = _enqueue_eval_run_job(run_id=run_id, org_id=org_id, max_attempts=max_attempts)
    if bool(queued.get("enqueued", False)):
        _record_activity_event(
            org_id=org_id,
            agent_id=agent_id,
            event_type="run_queued",
            title="Eval run queued",
            details=f"run_id={str(run_id)[:8]}",
            severity="info",
            metadata={"run_id": str(run_id), "job_id": str(queued["job_id"]), "status": queued["status"]},
        )
    else:
        _record_activity_event(
            org_id=org_id,
            agent_id=agent_id,
            event_type="run_queue_deduplicated",
            title="Eval run already queued",
            details=f"run_id={str(run_id)[:8]} reused existing queued/running job",
            severity="warning",
            metadata={"run_id": str(run_id), "job_id": str(queued["job_id"]), "status": queued["status"]},
        )
    data = EvalRunQueueStartData(
        job_id=queued["job_id"],
        run_id=queued["run_id"],
        status=queued["status"],
        enqueued=bool(queued.get("enqueued", False)),
        attempt_count=queued["attempt_count"],
        max_attempts=queued["max_attempts"],
        created_at=queued["created_at"],
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/eval/runs/{run_id}/cancel", response_model=EvalRunQueueCancelResponse)
def cancel_eval_run(
    run_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id, agent_id from public.eval_runs where id = %s", (str(run_id),))
            run_row = cur.fetchone()
            if not run_row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(run_row[1]), context="eval_run_cancel")  # type: ignore[index]
            org_id = UUID(str(run_row[1]))  # type: ignore[index]
            agent_id = UUID(str(run_row[2]))  # type: ignore[index]

    cancelled = _cancel_eval_run_job(run_id)
    if cancelled["cancelled"]:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'cancelled',
                            completed_at = coalesce(completed_at, now()),
                            failure_reason = coalesce(failure_reason, 'Cancelled by user.')
                        where id = %s
                          and status in ('pending', 'running')
                        """,
                        (str(run_id),),
                    )
        except Exception:
            pass
        _record_activity_event(
            org_id=org_id,
            agent_id=agent_id,
            event_type="run_cancelled",
            title="Eval run cancelled",
            details=f"run_id={str(run_id)[:8]}",
            severity="warning",
            metadata={"run_id": str(run_id), "job_id": str(cancelled["job_id"])},
        )
    data = EvalRunQueueCancelData(
        run_id=run_id,
        cancelled=bool(cancelled["cancelled"]),
        job_id=cancelled["job_id"],
        status=cancelled["status"],
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/calibration/runs", status_code=status.HTTP_201_CREATED, response_model=CalibrationRunResponse)
def create_calibration_run(
    payload: CalibrationRunCreateRequest = Body(
        ...,
        examples=[
            {
                "name": "create-calibration",
                "summary": "Create calibration run from human vs judge comparisons",
                "value": {
                    "org_id": "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb",
                    "agent_id": "e3660b25-47cf-47f3-ab53-c080fb7ffdcc",
                    "prompt_version": "judge_prompt_v1",
                    "judge_model": "gpt-4.1-mini",
                    "per_case_comparison": [
                        {"case_id": None, "human_label": "yes", "judge_label": "yes", "is_clean": True},
                        {"case_id": None, "human_label": "partially", "judge_label": "no", "is_clean": False},
                    ],
                },
            }
        ],
    ),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="calibration_create")
    cases_json = [c.model_dump(mode="json") for c in payload.per_case_comparison]
    overall_agreement, clean_agreement = compute_agreement(cases_json)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(payload.agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {payload.agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                if str(agent_row[1]) != str(payload.org_id):  # type: ignore[index]
                    _error("CALIBRATION_ORG_MISMATCH", "agent_id does not belong to org_id.", status.HTTP_400_BAD_REQUEST)
                cur.execute(
                    """
                    insert into public.calibration_runs (
                        org_id,
                        agent_id,
                        prompt_version,
                        judge_model,
                        overall_agreement,
                        clean_agreement,
                        per_case_comparison
                    )
                    values (%s, %s, %s, %s, %s, %s, %s::jsonb)
                    returning
                        id, org_id, agent_id, prompt_version, judge_model,
                        overall_agreement, clean_agreement, per_case_comparison, created_at
                    """,
                    (
                        str(payload.org_id),
                        str(payload.agent_id),
                        payload.prompt_version,
                        payload.judge_model,
                        overall_agreement,
                        clean_agreement,
                        json.dumps(cases_json),
                    ),
                )
                row = cur.fetchone()
    except Exception as exc:
        _error("CALIBRATION_CREATE_FAILED", f"Failed to create calibration run: {exc}", status.HTTP_400_BAD_REQUEST)

    data = CalibrationRunData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        prompt_version=row[3],  # type: ignore[index]
        judge_model=row[4],  # type: ignore[index]
        overall_agreement=float(row[5]),  # type: ignore[index]
        clean_agreement=float(row[6]) if row[6] is not None else None,  # type: ignore[index]
        per_case_comparison=row[7] or [],  # type: ignore[index]
        created_at=row[8],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/calibration/runs/{calibration_id}", response_model=CalibrationRunResponse)
def get_calibration_run(
    calibration_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    id, org_id, agent_id, prompt_version, judge_model,
                    overall_agreement, clean_agreement, per_case_comparison, created_at
                from public.calibration_runs
                where id = %s
                """,
                (str(calibration_id),),
            )
            row = cur.fetchone()
            if not row:
                _error(
                    "CALIBRATION_NOT_FOUND",
                    f"Calibration run {calibration_id} was not found.",
                    status.HTTP_404_NOT_FOUND,
                )
    _assert_org_access(api_key_ctx, str(row[1]), context="calibration_read")  # type: ignore[index]

    data = CalibrationRunData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        prompt_version=row[3],  # type: ignore[index]
        judge_model=row[4],  # type: ignore[index]
        overall_agreement=float(row[5]),  # type: ignore[index]
        clean_agreement=float(row[6]) if row[6] is not None else None,  # type: ignore[index]
        per_case_comparison=row[7] or [],  # type: ignore[index]
        created_at=row[8],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/calibration/latest", response_model=AgentLatestCalibrationResponse)
def get_agent_latest_calibration(
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_calibration_latest")  # type: ignore[index]

            cur.execute(
                """
                select
                    id, org_id, agent_id, prompt_version, judge_model,
                    overall_agreement, clean_agreement, per_case_comparison, created_at
                from public.calibration_runs
                where agent_id = %s
                order by created_at desc
                limit 1
                """,
                (str(agent_id),),
            )
            row = cur.fetchone()

    if not row:
        return {"ok": True, "data": {"agent_id": str(agent_id), "latest_calibration": None}}

    latest = CalibrationRunData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        prompt_version=row[3],  # type: ignore[index]
        judge_model=row[4],  # type: ignore[index]
        overall_agreement=float(row[5]),  # type: ignore[index]
        clean_agreement=float(row[6]) if row[6] is not None else None,  # type: ignore[index]
        per_case_comparison=row[7] or [],  # type: ignore[index]
        created_at=row[8],  # type: ignore[index]
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "latest_calibration": latest.model_dump(mode="json")}}


@app.get("/api/agents/{agent_id}/calibration-gate-status", response_model=CalibrationGateStatusResponse)
def get_agent_calibration_gate_status(
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_calibration_gate_status")  # type: ignore[index]

    gate = _get_calibration_gate_status(agent_id=agent_id)
    data = CalibrationGateStatusData(
        agent_id=agent_id,
        enabled=bool(gate.get("enabled", False)),
        status=str(gate.get("status", "disabled")),
        reasons=[str(x) for x in (gate.get("reasons") or [])],
        min_overall_agreement=float(gate.get("min_overall_agreement", 0.7)),
        max_age_days=int(gate.get("max_age_days", 14)),
        latest_calibration_id=gate.get("latest_calibration_id"),
        latest_calibration_created_at=gate.get("latest_calibration_created_at"),
        latest_overall_agreement=gate.get("latest_overall_agreement"),
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/golden-sets/{golden_set_id}/quality-gate-status", response_model=GoldenSetQualityGateStatusResponse)
def get_golden_set_quality_gate_status(
    golden_set_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id, agent_id from public.golden_sets where id = %s", (str(golden_set_id),))
            gs_row = cur.fetchone()
            if not gs_row:
                _error("GOLDEN_SET_NOT_FOUND", f"Golden set {golden_set_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(gs_row[1]), context="golden_set_quality_gate_status")  # type: ignore[index]
            agent_id = UUID(str(gs_row[2]))  # type: ignore[index]

    policy = _get_slo_policy(agent_id)
    gate = _get_golden_set_quality_gate_status(golden_set_id=golden_set_id, policy=policy)
    data = GoldenSetQualityGateStatusData(
        golden_set_id=golden_set_id,
        enabled=bool(gate.get("enabled", False)),
        status=str(gate.get("status", "disabled")),
        reasons=[str(x) for x in (gate.get("reasons") or [])],
        min_verified_case_ratio=float(gate.get("min_verified_case_ratio", 0.7)),
        min_active_case_count=int(gate.get("min_active_case_count", 20)),
        total_case_count=int(gate.get("total_case_count", 0)),
        active_case_count=int(gate.get("active_case_count", 0)),
        verified_case_count=int(gate.get("verified_case_count", 0)),
        verified_case_ratio=float(gate.get("verified_case_ratio", 0.0)),
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/gate-definitions", response_model=GateDefinitionListResponse)
def list_gate_definitions(
    org_id: Optional[UUID] = Query(default=None),
    include_builtin: bool = Query(default=True),
    active_only: bool = Query(default=True),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    where: List[str] = []
    params: List[Any] = []
    if active_only:
        where.append("gd.active = true")
    if org_id is not None:
        _assert_org_access(api_key_ctx, str(org_id), context="gate_definitions_list")
        if include_builtin:
            where.append("(gd.org_id is null or gd.org_id = %s)")
            params.append(str(org_id))
        else:
            where.append("gd.org_id = %s")
            params.append(str(org_id))
    else:
        if api_key_ctx.get("org_id"):
            scoped_org = str(api_key_ctx.get("org_id"))
            if include_builtin:
                where.append("(gd.org_id is null or gd.org_id = %s)")
                params.append(scoped_org)
            else:
                where.append("gd.org_id = %s")
                params.append(scoped_org)
        else:
            if include_builtin:
                where.append("gd.org_id is null")
            else:
                where.append("1=0")

    where_sql = ("where " + " and ".join(where)) if where else ""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select count(*) from public.gate_definitions gd {where_sql}", tuple(params))
            total_count = int(cur.fetchone()[0])  # type: ignore[index]
            cur.execute(
                f"""
                select
                  gd.id, gd.org_id, gd.key, gd.name, gd.description, gd.evaluator_key,
                  gd.contract_version, gd.config_schema, gd.default_config, gd.applies_to_run_types,
                  gd.is_builtin, gd.active, gd.created_at, gd.updated_at
                from public.gate_definitions gd
                {where_sql}
                order by gd.is_builtin desc, gd.created_at asc
                limit %s offset %s
                """,
                tuple([*params, limit, offset]),
            )
            rows = cur.fetchall()
    items: List[GateDefinitionItem] = []
    for r in rows:
        if len(r) >= 14:
            contract_version = str(r[6] or "1.0.0")
            config_schema = r[7] or {}
            default_config = r[8] or {}
            applies_to = [str(x) for x in (r[9] or [])]
            is_builtin = bool(r[10])
            active = bool(r[11])
            created_at = r[12]
            updated_at = r[13]
        else:
            contract_version = "1.0.0"
            config_schema = r[6] or {}
            default_config = r[7] or {}
            applies_to = [str(x) for x in (r[8] or [])]
            is_builtin = bool(r[9])
            active = bool(r[10])
            created_at = r[11]
            updated_at = r[12]
        items.append(
            GateDefinitionItem(
                id=r[0],
                org_id=r[1],
                key=r[2],
                name=r[3],
                description=r[4],
                evaluator_key=r[5],
                contract_version=contract_version,
                config_schema=config_schema,
                default_config=default_config,
                applies_to_run_types=applies_to,
                is_builtin=is_builtin,
                active=active,
                created_at=created_at,
                updated_at=updated_at,
            )
        )
    data = GateDefinitionListData(items=items, count=len(items), total_count=total_count, limit=limit, offset=offset)
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/gate-definitions", status_code=status.HTTP_201_CREATED, response_model=GateDefinitionCreateResponse)
def create_gate_definition(
    payload: GateDefinitionCreateRequest,
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="gate_definition_create")
    evaluator_key = payload.evaluator_key.strip()
    if evaluator_key not in SUPPORTED_GATE_EVALUATORS:
        _error(
            "GATE_EVALUATOR_UNSUPPORTED",
            f"Unsupported evaluator_key '{evaluator_key}'.",
            status.HTTP_400_BAD_REQUEST,
        )
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.gate_definitions (
                      org_id, key, name, description, evaluator_key,
                      contract_version, config_schema, default_config, applies_to_run_types,
                      is_builtin, active
                    )
                    values (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::text[], false, %s)
                    returning
                      id, org_id, key, name, description, evaluator_key,
                      contract_version, config_schema, default_config, applies_to_run_types,
                      is_builtin, active, created_at, updated_at
                    """,
                    (
                        str(payload.org_id),
                        payload.key.strip(),
                        payload.name.strip(),
                        payload.description,
                        evaluator_key,
                        payload.contract_version,
                        json.dumps(payload.config_schema),
                        json.dumps(payload.default_config),
                        [str(x) for x in payload.applies_to_run_types],
                        payload.active,
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("GATE_DEFINITION_CREATE_FAILED", f"Failed to create gate definition: {exc}", status.HTTP_400_BAD_REQUEST)

    data = GateDefinitionItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        key=row[2],  # type: ignore[index]
        name=row[3],  # type: ignore[index]
        description=row[4],  # type: ignore[index]
        evaluator_key=row[5],  # type: ignore[index]
        contract_version=str(row[6] or "1.0.0"),  # type: ignore[index]
        config_schema=row[7] or {},  # type: ignore[index]
        default_config=row[8] or {},  # type: ignore[index]
        applies_to_run_types=[str(x) for x in (row[9] or [])],  # type: ignore[index]
        is_builtin=bool(row[10]),  # type: ignore[index]
        active=bool(row[11]),  # type: ignore[index]
        created_at=row[12],  # type: ignore[index]
        updated_at=row[13],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/gate-bindings", response_model=AgentGateBindingListResponse)
def list_agent_gate_bindings(
    agent_id: UUID = Path(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_gate_bindings_list")  # type: ignore[index]
            cur.execute("select count(*) from public.agent_gate_bindings where agent_id = %s", (str(agent_id),))
            total_count = int(cur.fetchone()[0])  # type: ignore[index]
            cur.execute(
                """
                select
                  b.id, b.org_id, b.agent_id, b.gate_definition_id, b.definition_contract_version,
                  b.enabled, b.config, b.created_at, b.updated_at, d.key, d.name, d.evaluator_key
                from public.agent_gate_bindings b
                join public.gate_definitions d on d.id = b.gate_definition_id
                where b.agent_id = %s
                order by b.updated_at desc
                limit %s offset %s
                """,
                (str(agent_id), limit, offset),
            )
            rows = cur.fetchall()
    items = [
        AgentGateBindingItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            gate_definition_id=r[3],
            definition_contract_version=str(r[4] or "1.0.0"),
            enabled=bool(r[5]),
            config=r[6] or {},
            created_at=r[7],
            updated_at=r[8],
            gate_key=r[9],
            gate_name=r[10],
            evaluator_key=r[11],
        )
        for r in rows
    ]
    data = AgentGateBindingListData(
        agent_id=agent_id,
        items=items,
        count=len(items),
        total_count=total_count,
        limit=limit,
        offset=offset,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/agents/{agent_id}/gate-bindings", status_code=status.HTTP_201_CREATED, response_model=AgentGateBindingUpsertResponse)
def upsert_agent_gate_binding(
    payload: AgentGateBindingUpsertRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    if not isinstance(payload.config, dict):
        _error("GATE_BINDING_CONFIG_INVALID", "config must be a JSON object.", status.HTTP_400_BAD_REQUEST)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_gate_binding_upsert")  # type: ignore[index]
                org_id = str(agent_row[1])  # type: ignore[index]

                cur.execute(
                    """
                    select id, org_id, key, name, evaluator_key, contract_version
                    from public.gate_definitions
                    where id = %s and active = true
                    """,
                    (str(payload.gate_definition_id),),
                )
                gate_row = cur.fetchone()
                if not gate_row:
                    _error(
                        "GATE_DEFINITION_NOT_FOUND",
                        f"Gate definition {payload.gate_definition_id} was not found.",
                        status.HTTP_404_NOT_FOUND,
                    )
                gate_org_id = gate_row[1]
                gate_key = str(gate_row[2])
                gate_name = str(gate_row[3])
                gate_evaluator_key = str(gate_row[4])
                gate_contract_version = str(gate_row[5] or "1.0.0") if len(gate_row) > 5 else "1.0.0"
                if gate_org_id is not None and str(gate_org_id) != org_id:
                    _error(
                        "GATE_DEFINITION_SCOPE_MISMATCH",
                        "Gate definition is not available for this agent org.",
                        status.HTTP_403_FORBIDDEN,
                    )

                cur.execute(
                    """
                    insert into public.agent_gate_bindings (
                      org_id, agent_id, gate_definition_id, definition_contract_version, enabled, config
                    )
                    values (%s, %s, %s, %s, %s, %s::jsonb)
                    on conflict (agent_id, gate_definition_id) do update
                    set definition_contract_version = excluded.definition_contract_version,
                        enabled = excluded.enabled,
                        config = excluded.config,
                        updated_at = now()
                    returning id, org_id, agent_id, gate_definition_id, definition_contract_version, enabled, config, created_at, updated_at
                    """,
                    (
                        org_id,
                        str(agent_id),
                        str(payload.gate_definition_id),
                        gate_contract_version,
                        payload.enabled,
                        json.dumps(payload.config),
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("GATE_BINDING_UPSERT_FAILED", f"Failed to upsert gate binding: {exc}", status.HTTP_400_BAD_REQUEST)

    if len(row) >= 9:
        def_contract_version = str(row[4] or "1.0.0")  # type: ignore[index]
        enabled = bool(row[5])  # type: ignore[index]
        config = row[6] or {}  # type: ignore[index]
        created_at = row[7]  # type: ignore[index]
        updated_at = row[8]  # type: ignore[index]
    else:
        def_contract_version = "1.0.0"
        enabled = bool(row[4])  # type: ignore[index]
        config = row[5] or {}  # type: ignore[index]
        created_at = row[6]  # type: ignore[index]
        updated_at = row[7]  # type: ignore[index]
    binding = AgentGateBindingItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        gate_definition_id=row[3],  # type: ignore[index]
        definition_contract_version=def_contract_version,
        enabled=enabled,
        config=config,
        created_at=created_at,
        updated_at=updated_at,
        gate_key=gate_key,
        gate_name=gate_name,
        evaluator_key=gate_evaluator_key,
    )

    return {
        "ok": True,
        "data": AgentGateBindingUpsertData(agent_id=agent_id, binding=binding).model_dump(mode="json"),
    }


@app.get("/api/evaluator-definitions", response_model=EvaluatorDefinitionListResponse)
def list_evaluator_definitions(
    org_id: Optional[UUID] = Query(default=None),
    include_builtin: bool = Query(default=True),
    active_only: bool = Query(default=True),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    where: List[str] = []
    params: List[Any] = []
    if active_only:
        where.append("ed.active = true")
    if org_id is not None:
        _assert_org_access(api_key_ctx, str(org_id), context="evaluator_definitions_list")
        if include_builtin:
            where.append("(ed.org_id is null or ed.org_id = %s)")
            params.append(str(org_id))
        else:
            where.append("ed.org_id = %s")
            params.append(str(org_id))
    else:
        if api_key_ctx.get("org_id"):
            scoped_org = str(api_key_ctx.get("org_id"))
            if include_builtin:
                where.append("(ed.org_id is null or ed.org_id = %s)")
                params.append(scoped_org)
            else:
                where.append("ed.org_id = %s")
                params.append(scoped_org)
        else:
            if include_builtin:
                where.append("ed.org_id is null")
            else:
                where.append("1=0")
    where_sql = ("where " + " and ".join(where)) if where else ""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select count(*) from public.evaluator_definitions ed {where_sql}", tuple(params))
            count_row = cur.fetchone()
            total_count = int(count_row[0]) if isinstance(count_row, (tuple, list)) else int(count_row or 0)
            cur.execute(
                f"""
                select
                  ed.id, ed.org_id, ed.key, ed.name, ed.description, ed.evaluation_mode::text,
                  ed.evaluator_kind, ed.contract_version, ed.default_config, ed.is_builtin, ed.active, ed.created_at, ed.updated_at
                from public.evaluator_definitions ed
                {where_sql}
                order by ed.is_builtin desc, ed.created_at asc
                limit %s offset %s
                """,
                tuple([*params, limit, offset]),
            )
            rows = cur.fetchall()
    items: List[EvaluatorDefinitionItem] = []
    for r in rows:
        if len(r) >= 13:
            contract_version = str(r[7] or "1.0.0")
            default_config = r[8] or {}
            is_builtin = bool(r[9])
            active = bool(r[10])
            created_at = r[11]
            updated_at = r[12]
        else:
            contract_version = "1.0.0"
            default_config = r[7] or {}
            is_builtin = bool(r[8])
            active = bool(r[9])
            created_at = r[10]
            updated_at = r[11]
        items.append(
            EvaluatorDefinitionItem(
                id=r[0],
                org_id=r[1],
                key=r[2],
                name=r[3],
                description=r[4],
                evaluation_mode=r[5],
                evaluator_kind=r[6],
                contract_version=contract_version,
                default_config=default_config,
                is_builtin=is_builtin,
                active=active,
                created_at=created_at,
                updated_at=updated_at,
            )
        )
    data = EvaluatorDefinitionListData(items=items, count=len(items), total_count=total_count, limit=limit, offset=offset)
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/evaluator-definitions", status_code=status.HTTP_201_CREATED, response_model=EvaluatorDefinitionCreateResponse)
def create_evaluator_definition(
    payload: EvaluatorDefinitionCreateRequest,
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="evaluator_definition_create")
    evaluator_kind = payload.evaluator_kind.strip()
    if evaluator_kind not in SUPPORTED_EVALUATOR_KINDS:
        _error(
            "EVALUATOR_KIND_UNSUPPORTED",
            f"Unsupported evaluator_kind '{evaluator_kind}'.",
            status.HTTP_400_BAD_REQUEST,
        )
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.evaluator_definitions (
                      org_id, key, name, description, evaluation_mode, evaluator_kind, contract_version, default_config, is_builtin, active
                    )
                    values (%s, %s, %s, %s, %s::public.eval_mode, %s, %s, %s::jsonb, false, %s)
                    returning
                      id, org_id, key, name, description, evaluation_mode::text,
                      evaluator_kind, contract_version, default_config, is_builtin, active, created_at, updated_at
                    """,
                    (
                        str(payload.org_id),
                        payload.key.strip(),
                        payload.name.strip(),
                        payload.description,
                        payload.evaluation_mode,
                        evaluator_kind,
                        payload.contract_version,
                        json.dumps(payload.default_config),
                        payload.active,
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error(
            "EVALUATOR_DEFINITION_CREATE_FAILED",
            f"Failed to create evaluator definition: {exc}",
            status.HTTP_400_BAD_REQUEST,
        )
    data = EvaluatorDefinitionItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        key=row[2],  # type: ignore[index]
        name=row[3],  # type: ignore[index]
        description=row[4],  # type: ignore[index]
        evaluation_mode=row[5],  # type: ignore[index]
        evaluator_kind=row[6],  # type: ignore[index]
        contract_version=str(row[7] or "1.0.0"),  # type: ignore[index]
        default_config=row[8] or {},  # type: ignore[index]
        is_builtin=bool(row[9]),  # type: ignore[index]
        active=bool(row[10]),  # type: ignore[index]
        created_at=row[11],  # type: ignore[index]
        updated_at=row[12],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/evaluator-bindings", response_model=AgentEvaluatorBindingListResponse)
def list_agent_evaluator_bindings(
    agent_id: UUID = Path(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_evaluator_bindings_list")  # type: ignore[index]
            cur.execute("select count(*) from public.agent_evaluator_bindings where agent_id = %s", (str(agent_id),))
            count_row = cur.fetchone()
            total_count = int(count_row[0]) if isinstance(count_row, (tuple, list)) else int(count_row or 0)
            cur.execute(
                """
                select
                  b.id, b.org_id, b.agent_id, b.evaluator_definition_id, b.evaluation_mode::text,
                  b.definition_contract_version, b.enabled, b.config, b.created_at, b.updated_at,
                  d.key, d.name, d.evaluator_kind
                from public.agent_evaluator_bindings b
                join public.evaluator_definitions d on d.id = b.evaluator_definition_id
                where b.agent_id = %s
                order by b.updated_at desc
                limit %s offset %s
                """,
                (str(agent_id), limit, offset),
            )
            rows = cur.fetchall()
    items = [
        AgentEvaluatorBindingItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            evaluator_definition_id=r[3],
            evaluation_mode=r[4],
            definition_contract_version=str(r[5] or "1.0.0"),
            enabled=bool(r[6]),
            config=r[7] or {},
            created_at=r[8],
            updated_at=r[9],
            evaluator_key=r[10],
            evaluator_name=r[11],
            evaluator_kind=r[12],
        )
        for r in rows
    ]
    data = AgentEvaluatorBindingListData(
        agent_id=agent_id,
        items=items,
        count=len(items),
        total_count=total_count,
        limit=limit,
        offset=offset,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post(
    "/api/agents/{agent_id}/evaluator-bindings",
    status_code=status.HTTP_201_CREATED,
    response_model=AgentEvaluatorBindingUpsertResponse,
)
def upsert_agent_evaluator_binding(
    payload: AgentEvaluatorBindingUpsertRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    if not isinstance(payload.config, dict):
        _error("EVALUATOR_BINDING_CONFIG_INVALID", "config must be a JSON object.", status.HTTP_400_BAD_REQUEST)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_evaluator_binding_upsert")  # type: ignore[index]
                org_id = str(agent_row[1])  # type: ignore[index]
                cur.execute(
                    """
                    select id, org_id, key, name, evaluation_mode::text, evaluator_kind, contract_version
                    from public.evaluator_definitions
                    where id = %s and active = true
                    """,
                    (str(payload.evaluator_definition_id),),
                )
                def_row = cur.fetchone()
                if not def_row:
                    _error(
                        "EVALUATOR_DEFINITION_NOT_FOUND",
                        f"Evaluator definition {payload.evaluator_definition_id} was not found.",
                        status.HTTP_404_NOT_FOUND,
                    )
                def_org_id = def_row[1]
                def_key = str(def_row[2])
                def_name = str(def_row[3])
                def_eval_mode = str(def_row[4])
                def_kind = str(def_row[5])
                def_contract_version = str(def_row[6] or "1.0.0") if len(def_row) > 6 else "1.0.0"
                if def_org_id is not None and str(def_org_id) != org_id:
                    _error(
                        "EVALUATOR_DEFINITION_SCOPE_MISMATCH",
                        "Evaluator definition is not available for this agent org.",
                        status.HTTP_403_FORBIDDEN,
                    )
                if def_eval_mode != payload.evaluation_mode:
                    _error(
                        "EVALUATOR_MODE_MISMATCH",
                        "Binding evaluation_mode must match evaluator definition mode.",
                        status.HTTP_400_BAD_REQUEST,
                    )
                cur.execute(
                    """
                    insert into public.agent_evaluator_bindings (
                      org_id, agent_id, evaluator_definition_id, evaluation_mode, definition_contract_version, enabled, config
                    )
                    values (%s, %s, %s, %s::public.eval_mode, %s, %s, %s::jsonb)
                    on conflict (agent_id, evaluation_mode) do update
                    set evaluator_definition_id = excluded.evaluator_definition_id,
                        definition_contract_version = excluded.definition_contract_version,
                        enabled = excluded.enabled,
                        config = excluded.config,
                        updated_at = now()
                    returning id, org_id, agent_id, evaluator_definition_id, evaluation_mode::text, definition_contract_version, enabled, config, created_at, updated_at
                    """,
                    (
                        org_id,
                        str(agent_id),
                        str(payload.evaluator_definition_id),
                        payload.evaluation_mode,
                        def_contract_version,
                        payload.enabled,
                        json.dumps(payload.config),
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("EVALUATOR_BINDING_UPSERT_FAILED", f"Failed to upsert evaluator binding: {exc}", status.HTTP_400_BAD_REQUEST)

    if len(row) >= 10:
        def_contract_version = str(row[5] or "1.0.0")  # type: ignore[index]
        enabled = bool(row[6])  # type: ignore[index]
        config = row[7] or {}  # type: ignore[index]
        created_at = row[8]  # type: ignore[index]
        updated_at = row[9]  # type: ignore[index]
    else:
        def_contract_version = "1.0.0"
        enabled = bool(row[5])  # type: ignore[index]
        config = row[6] or {}  # type: ignore[index]
        created_at = row[7]  # type: ignore[index]
        updated_at = row[8]  # type: ignore[index]
    binding = AgentEvaluatorBindingItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        evaluator_definition_id=row[3],  # type: ignore[index]
        evaluation_mode=row[4],  # type: ignore[index]
        definition_contract_version=def_contract_version,
        enabled=enabled,
        config=config,
        created_at=created_at,
        updated_at=updated_at,
        evaluator_key=def_key,
        evaluator_name=def_name,
        evaluator_kind=def_kind,
    )
    return {
        "ok": True,
        "data": AgentEvaluatorBindingUpsertData(agent_id=agent_id, binding=binding).model_dump(mode="json"),
    }


@app.get("/api/run-type-definitions", response_model=RunTypeDefinitionListResponse)
def list_run_type_definitions(
    org_id: Optional[UUID] = Query(default=None),
    include_builtin: bool = Query(default=True),
    active_only: bool = Query(default=True),
    run_type: Optional[RunType] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    where: List[str] = []
    params: List[Any] = []
    if active_only:
        where.append("rt.active = true")
    if run_type is not None:
        where.append("rt.run_type::text = %s")
        params.append(str(run_type))
    if org_id is not None:
        _assert_org_access(api_key_ctx, str(org_id), context="run_type_definitions_list")
        if include_builtin:
            where.append("(rt.org_id is null or rt.org_id = %s)")
            params.append(str(org_id))
        else:
            where.append("rt.org_id = %s")
            params.append(str(org_id))
    else:
        if api_key_ctx.get("org_id"):
            scoped_org = str(api_key_ctx.get("org_id"))
            if include_builtin:
                where.append("(rt.org_id is null or rt.org_id = %s)")
                params.append(scoped_org)
            else:
                where.append("rt.org_id = %s")
                params.append(scoped_org)
        else:
            if include_builtin:
                where.append("rt.org_id is null")
            else:
                where.append("1=0")
    where_sql = ("where " + " and ".join(where)) if where else ""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select count(*) from public.run_type_definitions rt {where_sql}", tuple(params))
            count_row = cur.fetchone()
            total_count = int(count_row[0]) if isinstance(count_row, (tuple, list)) else int(count_row or 0)
            cur.execute(
                f"""
                select
                  rt.id, rt.org_id, rt.run_type::text, rt.key, rt.name, rt.description,
                  rt.handler_key, rt.contract_version, rt.default_config, rt.is_builtin, rt.active, rt.created_at, rt.updated_at
                from public.run_type_definitions rt
                {where_sql}
                order by rt.is_builtin desc, rt.created_at asc
                limit %s offset %s
                """,
                tuple([*params, limit, offset]),
            )
            rows = cur.fetchall()
    items: List[RunTypeDefinitionItem] = []
    for r in rows:
        if len(r) >= 13:
            contract_version = str(r[7] or "1.0.0")
            default_config = r[8] or {}
            is_builtin = bool(r[9])
            active = bool(r[10])
            created_at = r[11]
            updated_at = r[12]
        else:
            contract_version = "1.0.0"
            default_config = r[7] or {}
            is_builtin = bool(r[8])
            active = bool(r[9])
            created_at = r[10]
            updated_at = r[11]
        items.append(
            RunTypeDefinitionItem(
                id=r[0],
                org_id=r[1],
                run_type=r[2],
                key=r[3],
                name=r[4],
                description=r[5],
                handler_key=r[6],
                contract_version=contract_version,
                default_config=default_config,
                is_builtin=is_builtin,
                active=active,
                created_at=created_at,
                updated_at=updated_at,
            )
        )
    data = RunTypeDefinitionListData(items=items, count=len(items), total_count=total_count, limit=limit, offset=offset)
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/run-type-definitions", status_code=status.HTTP_201_CREATED, response_model=RunTypeDefinitionCreateResponse)
def create_run_type_definition(
    payload: RunTypeDefinitionCreateRequest,
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="run_type_definition_create")
    handler_key = payload.handler_key.strip()
    if handler_key not in SUPPORTED_RUN_TYPE_HANDLERS:
        _error(
            "RUN_TYPE_HANDLER_UNSUPPORTED",
            f"Unsupported handler_key '{handler_key}'.",
            status.HTTP_400_BAD_REQUEST,
        )
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.run_type_definitions (
                      org_id, run_type, key, name, description, handler_key, contract_version, default_config, is_builtin, active
                    )
                    values (%s, %s::public.eval_run_type, %s, %s, %s, %s, %s, %s::jsonb, false, %s)
                    returning
                      id, org_id, run_type::text, key, name, description, handler_key, contract_version, default_config, is_builtin, active, created_at, updated_at
                    """,
                    (
                        str(payload.org_id),
                        payload.run_type,
                        payload.key.strip(),
                        payload.name.strip(),
                        payload.description,
                        handler_key,
                        payload.contract_version,
                        json.dumps(payload.default_config),
                        payload.active,
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("RUN_TYPE_DEFINITION_CREATE_FAILED", f"Failed to create run type definition: {exc}", status.HTTP_400_BAD_REQUEST)

    data = RunTypeDefinitionItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        run_type=row[2],  # type: ignore[index]
        key=row[3],  # type: ignore[index]
        name=row[4],  # type: ignore[index]
        description=row[5],  # type: ignore[index]
        handler_key=row[6],  # type: ignore[index]
        contract_version=str(row[7] or "1.0.0"),  # type: ignore[index]
        default_config=row[8] or {},  # type: ignore[index]
        is_builtin=bool(row[9]),  # type: ignore[index]
        active=bool(row[10]),  # type: ignore[index]
        created_at=row[11],  # type: ignore[index]
        updated_at=row[12],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/run-type-bindings", response_model=AgentRunTypeBindingListResponse)
def list_agent_run_type_bindings(
    agent_id: UUID = Path(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_run_type_bindings_list")  # type: ignore[index]
            cur.execute("select count(*) from public.agent_run_type_bindings where agent_id = %s", (str(agent_id),))
            count_row = cur.fetchone()
            total_count = int(count_row[0]) if isinstance(count_row, (tuple, list)) else int(count_row or 0)
            cur.execute(
                """
                select
                  b.id, b.org_id, b.agent_id, b.run_type::text, b.run_type_definition_id,
                  b.definition_contract_version, b.enabled, b.config, b.created_at, b.updated_at,
                  d.key, d.name, d.handler_key
                from public.agent_run_type_bindings b
                join public.run_type_definitions d on d.id = b.run_type_definition_id
                where b.agent_id = %s
                order by b.updated_at desc
                limit %s offset %s
                """,
                (str(agent_id), limit, offset),
            )
            rows = cur.fetchall()
    items = [
        AgentRunTypeBindingItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            run_type=r[3],
            run_type_definition_id=r[4],
            definition_contract_version=str(r[5] or "1.0.0"),
            enabled=bool(r[6]),
            config=r[7] or {},
            created_at=r[8],
            updated_at=r[9],
            definition_key=r[10],
            definition_name=r[11],
            handler_key=r[12],
        )
        for r in rows
    ]
    data = AgentRunTypeBindingListData(
        agent_id=agent_id,
        items=items,
        count=len(items),
        total_count=total_count,
        limit=limit,
        offset=offset,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/agents/{agent_id}/run-type-bindings", status_code=status.HTTP_201_CREATED, response_model=AgentRunTypeBindingUpsertResponse)
def upsert_agent_run_type_binding(
    payload: AgentRunTypeBindingUpsertRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    if not isinstance(payload.config, dict):
        _error("RUN_TYPE_BINDING_CONFIG_INVALID", "config must be a JSON object.", status.HTTP_400_BAD_REQUEST)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_run_type_binding_upsert")  # type: ignore[index]
                org_id = str(agent_row[1])  # type: ignore[index]
                cur.execute(
                    """
                    select id, org_id, run_type::text, key, name, handler_key, contract_version
                    from public.run_type_definitions
                    where id = %s and active = true
                    """,
                    (str(payload.run_type_definition_id),),
                )
                def_row = cur.fetchone()
                if not def_row:
                    _error(
                        "RUN_TYPE_DEFINITION_NOT_FOUND",
                        f"Run type definition {payload.run_type_definition_id} was not found.",
                        status.HTTP_404_NOT_FOUND,
                    )
                def_org_id = def_row[1]
                def_run_type = str(def_row[2])
                def_key = str(def_row[3])
                def_name = str(def_row[4])
                def_handler_key = str(def_row[5])
                def_contract_version = str(def_row[6] or "1.0.0") if len(def_row) > 6 else "1.0.0"
                if def_org_id is not None and str(def_org_id) != org_id:
                    _error(
                        "RUN_TYPE_DEFINITION_SCOPE_MISMATCH",
                        "Run type definition is not available for this agent org.",
                        status.HTTP_403_FORBIDDEN,
                    )
                if def_run_type != payload.run_type:
                    _error(
                        "RUN_TYPE_BINDING_MISMATCH",
                        "Binding run_type must match run type definition.",
                        status.HTTP_400_BAD_REQUEST,
                    )
                cur.execute(
                    """
                    insert into public.agent_run_type_bindings (
                      org_id, agent_id, run_type, run_type_definition_id, definition_contract_version, enabled, config
                    )
                    values (%s, %s, %s::public.eval_run_type, %s, %s, %s, %s::jsonb)
                    on conflict (agent_id, run_type) do update
                    set run_type_definition_id = excluded.run_type_definition_id,
                        definition_contract_version = excluded.definition_contract_version,
                        enabled = excluded.enabled,
                        config = excluded.config,
                        updated_at = now()
                    returning id, org_id, agent_id, run_type::text, run_type_definition_id, definition_contract_version, enabled, config, created_at, updated_at
                    """,
                    (
                        org_id,
                        str(agent_id),
                        payload.run_type,
                        str(payload.run_type_definition_id),
                        def_contract_version,
                        payload.enabled,
                        json.dumps(payload.config),
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("RUN_TYPE_BINDING_UPSERT_FAILED", f"Failed to upsert run type binding: {exc}", status.HTTP_400_BAD_REQUEST)

    if len(row) >= 10:
        def_contract_version = str(row[5] or "1.0.0")  # type: ignore[index]
        enabled = bool(row[6])  # type: ignore[index]
        config = row[7] or {}  # type: ignore[index]
        created_at = row[8]  # type: ignore[index]
        updated_at = row[9]  # type: ignore[index]
    else:
        def_contract_version = "1.0.0"
        enabled = bool(row[5])  # type: ignore[index]
        config = row[6] or {}  # type: ignore[index]
        created_at = row[7]  # type: ignore[index]
        updated_at = row[8]  # type: ignore[index]
    binding = AgentRunTypeBindingItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        run_type=row[3],  # type: ignore[index]
        run_type_definition_id=row[4],  # type: ignore[index]
        definition_contract_version=def_contract_version,
        enabled=enabled,
        config=config,
        created_at=created_at,
        updated_at=updated_at,
        definition_key=def_key,
        definition_name=def_name,
        handler_key=def_handler_key,
    )
    return {
        "ok": True,
        "data": AgentRunTypeBindingUpsertData(agent_id=agent_id, binding=binding).model_dump(mode="json"),
    }


@app.get("/api/agents/{agent_id}/contract-status", response_model=AgentContractStatusResponse)
def get_agent_contract_status(
    agent_id: UUID = Path(...),
    run_type: RunType = Query(default="eval"),
    entrypoint: Literal["start", "execute"] = Query(default="start"),
    golden_set_id: Optional[UUID] = Query(default=None),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_contract_status")  # type: ignore[index]
            if golden_set_id is not None:
                cur.execute(
                    "select id from public.golden_sets where id = %s and org_id = %s and agent_id = %s",
                    (str(golden_set_id), str(agent_row[1]), str(agent_id)),
                )
                if not cur.fetchone():
                    _error(
                        "GOLDEN_SET_NOT_FOUND",
                        f"Golden set {golden_set_id} was not found for this org/agent.",
                        status.HTTP_404_NOT_FOUND,
                    )

    validation = _compute_agent_contract_issues(
        agent_id=agent_id,
        run_type=str(run_type),
        entrypoint=str(entrypoint),
        golden_set_id=golden_set_id,
    )
    issues = [
        ContractValidationIssue(
            severity=str(i.get("severity", "error")),  # type: ignore[arg-type]
            code=str(i.get("code", "UNKNOWN")),
            message=str(i.get("message", "")),
            component=str(i.get("component", "unknown")),
        )
        for i in (validation.get("issues") or [])
    ]
    data = AgentContractStatusData(
        agent_id=agent_id,
        run_type=run_type,
        entrypoint=entrypoint,
        golden_set_id=golden_set_id,
        status=str(validation.get("status", "fail")),  # type: ignore[arg-type]
        issues=issues,
        resolved_handler_key=str(validation.get("resolved_handler_key", "default")),
        enabled_gate_binding_count=int(validation.get("enabled_gate_binding_count", 0)),
        enabled_evaluator_binding_count=int(validation.get("enabled_evaluator_binding_count", 0)),
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/contracts/upgrade-preview", response_model=ContractUpgradePreviewResponse, tags=["Guardrails"])
def preview_contract_upgrade(
    payload: ContractUpgradePreviewRequest,
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    preview = _compute_contract_upgrade_preview(
        definition_type=str(payload.definition_type),
        definition_id=payload.definition_id,
        target_contract_version=payload.target_contract_version,
        include_items=payload.include_items,
        max_items=payload.max_items,
    )
    definition_org_id = preview.get("org_id")
    if definition_org_id is not None:
        _assert_org_access(api_key_ctx, str(definition_org_id), context="contract_upgrade_preview")
    items = [
        ContractUpgradeImpactItem(
            binding_id=i["binding_id"],
            agent_id=i["agent_id"],
            definition_contract_version=i["definition_contract_version"],
            impact=i["impact"],
            message=i["message"],
        )
        for i in (preview.get("items") or [])
    ]
    data = ContractUpgradePreviewData(
        definition_type=payload.definition_type,
        definition_id=payload.definition_id,
        definition_key=str(preview.get("definition_key", "")),
        definition_name=str(preview.get("definition_name", "")),
        current_contract_version=str(preview.get("current_contract_version", "1.0.0")),
        target_contract_version=str(preview.get("target_contract_version", payload.target_contract_version)),
        impacted_binding_count=int(preview.get("impacted_binding_count", 0)),
        breaking_count=int(preview.get("breaking_count", 0)),
        warning_count=int(preview.get("warning_count", 0)),
        invalid_count=int(preview.get("invalid_count", 0)),
        unchanged_count=int(preview.get("unchanged_count", 0)),
        status=str(preview.get("status", "safe")),  # type: ignore[arg-type]
        items=items,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/contracts/apply-upgrade", response_model=ContractUpgradeApplyResponse, tags=["Guardrails"])
def apply_contract_upgrade(
    payload: ContractUpgradeApplyRequest,
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    preview = _compute_contract_upgrade_preview(
        definition_type=str(payload.definition_type),
        definition_id=payload.definition_id,
        target_contract_version=payload.target_contract_version,
        include_items=True,
        max_items=200,
    )
    definition_org_id = preview.get("org_id")
    if definition_org_id is None:
        _error(
            "CONTRACT_DEFINITION_IMMUTABLE",
            "Builtin definition contracts cannot be updated.",
            status.HTTP_403_FORBIDDEN,
        )
    _assert_org_access(api_key_ctx, str(definition_org_id), context="contract_upgrade_apply")

    meta = _CONTRACT_DEFINITION_META.get(str(payload.definition_type))
    if not meta:
        _error("CONTRACT_DEFINITION_TYPE_INVALID", "Unsupported definition type.", status.HTTP_400_BAD_REQUEST)

    bindings_updated = 0
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    update {meta["definition_table"]}
                    set contract_version = %s,
                        updated_at = now()
                    where {meta["definition_id_col"]} = %s
                    """,
                    (payload.target_contract_version, str(payload.definition_id)),
                )
                if payload.rollout_mode == "sync_bindings":
                    cur.execute(
                        f"""
                        update {meta["binding_table"]}
                        set definition_contract_version = %s,
                            updated_at = now()
                        where {meta["binding_definition_fk_col"]} = %s
                        """,
                        (payload.target_contract_version, str(payload.definition_id)),
                    )
                    bindings_updated = max(int(getattr(cur, "rowcount", 0) or 0), 0)
    except HTTPException:
        raise
    except Exception as exc:
        _error("CONTRACT_UPGRADE_APPLY_FAILED", f"Failed to apply contract upgrade: {exc}", status.HTTP_400_BAD_REQUEST)

    refreshed = _compute_contract_upgrade_preview(
        definition_type=str(payload.definition_type),
        definition_id=payload.definition_id,
        target_contract_version=payload.target_contract_version,
        include_items=True,
        max_items=200,
    )
    items = [
        ContractUpgradeImpactItem(
            binding_id=i["binding_id"],
            agent_id=i["agent_id"],
            definition_contract_version=i["definition_contract_version"],
            impact=i["impact"],
            message=i["message"],
        )
        for i in (refreshed.get("items") or [])
    ]
    preview_data = ContractUpgradePreviewData(
        definition_type=payload.definition_type,
        definition_id=payload.definition_id,
        definition_key=str(refreshed.get("definition_key", "")),
        definition_name=str(refreshed.get("definition_name", "")),
        current_contract_version=str(refreshed.get("current_contract_version", payload.target_contract_version)),
        target_contract_version=str(refreshed.get("target_contract_version", payload.target_contract_version)),
        impacted_binding_count=int(refreshed.get("impacted_binding_count", 0)),
        breaking_count=int(refreshed.get("breaking_count", 0)),
        warning_count=int(refreshed.get("warning_count", 0)),
        invalid_count=int(refreshed.get("invalid_count", 0)),
        unchanged_count=int(refreshed.get("unchanged_count", 0)),
        status=str(refreshed.get("status", "safe")),  # type: ignore[arg-type]
        items=items,
    )
    data = ContractUpgradeApplyData(
        definition_type=payload.definition_type,
        definition_id=payload.definition_id,
        target_contract_version=payload.target_contract_version,
        rollout_mode=payload.rollout_mode,
        bindings_updated=bindings_updated,
        preview=preview_data,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/contracts/drift", response_model=ContractDriftResponse, tags=["Guardrails"])
def get_contract_drift(
    org_id: Optional[UUID] = Query(default=None),
    agent_id: Optional[UUID] = Query(default=None),
    include_healthy: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1000),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    scoped_org = api_key_ctx.get("org_id")
    if org_id is None:
        if scoped_org:
            org_id = UUID(str(scoped_org))
        else:
            _error("ORG_ID_REQUIRED", "org_id is required for global API keys.", status.HTTP_400_BAD_REQUEST)
    _assert_org_access(api_key_ctx, str(org_id), context="contract_drift")

    with get_conn() as conn:
        with conn.cursor() as cur:
            if agent_id is not None:
                cur.execute(
                    "select id from public.agents where id = %s and org_id = %s",
                    (str(agent_id), str(org_id)),
                )
                row = cur.fetchone()
                if not row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                agent_ids: List[UUID] = [UUID(str(row[0]))]  # type: ignore[index]
            else:
                cur.execute(
                    """
                    select id
                    from public.agents
                    where org_id = %s
                    order by updated_at desc nulls last, created_at desc
                    limit %s
                    """,
                    (str(org_id), limit),
                )
                rows = cur.fetchall()
                agent_ids = [UUID(str(r[0])) for r in rows]

    collected: List[Dict[str, Any]] = []
    for a_id in agent_ids:
        collected.extend(_collect_agent_contract_drift_items(agent_id=a_id, include_healthy=include_healthy))

    breaking_count = sum(1 for x in collected if x.get("drift") == "breaking")
    warning_count = sum(1 for x in collected if x.get("drift") == "warning")
    invalid_count = sum(1 for x in collected if x.get("drift") == "invalid")

    items = [
        ContractDriftItem(
            agent_id=i["agent_id"],
            definition_type=i["definition_type"],
            binding_id=i["binding_id"],
            definition_id=i["definition_id"],
            definition_key=i["definition_key"],
            bound_contract_version=i["bound_contract_version"],
            current_contract_version=i["current_contract_version"],
            drift=i["drift"],
            severity=i["severity"],
            message=i["message"],
        )
        for i in collected
    ]
    data = ContractDriftData(
        org_id=org_id,
        agent_id=agent_id,
        item_count=len(items),
        breaking_count=breaking_count,
        warning_count=warning_count,
        invalid_count=invalid_count,
        checked_agent_count=len(agent_ids),
        items=items,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/contracts/drift/promote-patterns", response_model=ContractDriftPromotePatternsResponse, tags=["Guardrails"])
def promote_contract_drift_patterns(
    payload: ContractDriftPromotePatternsRequest,
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="contract_drift_promote_patterns")

    drift_resp = get_contract_drift(
        org_id=payload.org_id,
        agent_id=payload.agent_id,
        include_healthy=False,
        limit=payload.limit,
        api_key_ctx=api_key_ctx,
    )
    drift_data = drift_resp["data"]
    items = drift_data.get("items") or []
    threshold_order = {"warning": 1, "breaking": 2, "invalid": 3}
    min_level = threshold_order[str(payload.min_drift)]

    eligible_items: List[Dict[str, Any]] = []
    for i in items:
        drift = str(i.get("drift", "warning"))
        level = threshold_order.get(drift, 0)
        if level >= min_level:
            eligible_items.append(i)

    created_count = 0
    reused_count = 0
    pattern_ids: List[UUID] = []
    if not payload.dry_run:
        for item in eligible_items:
            result = _create_or_reuse_contract_drift_pattern(
                org_id=payload.org_id,
                drift_item=item,
            )
            pattern_id = UUID(str(result["pattern_id"]))
            pattern_ids.append(pattern_id)
            if bool(result.get("created", False)):
                created_count += 1
            else:
                reused_count += 1

    notification: Optional[Dict[str, Any]] = None
    if eligible_items:
        notification = _dispatch_notification(
            org_id=payload.org_id,
            agent_id=payload.agent_id,
            event_type="contract_drift_patterns_promoted",
            payload={
                "org_id": str(payload.org_id),
                "agent_id": str(payload.agent_id) if payload.agent_id else None,
                "min_drift": payload.min_drift,
                "dry_run": payload.dry_run,
                "scanned_item_count": len(items),
                "eligible_item_count": len(eligible_items),
                "created_pattern_count": created_count,
                "reused_pattern_count": reused_count,
                "pattern_ids": [str(x) for x in pattern_ids],
            },
        )
        _record_activity_event(
            org_id=payload.org_id,
            agent_id=payload.agent_id,
            event_type="contract_drift_promote_patterns",
            title="Contract drift promoted to issue patterns",
            details=(
                f"scanned={len(items)}, eligible={len(eligible_items)}, "
                f"created={created_count}, reused={reused_count}, dry_run={payload.dry_run}"
            ),
            severity="warning",
            metadata={
                "min_drift": payload.min_drift,
                "dry_run": payload.dry_run,
                "scanned_item_count": len(items),
                "eligible_item_count": len(eligible_items),
                "created_pattern_count": created_count,
                "reused_pattern_count": reused_count,
                "pattern_ids": [str(x) for x in pattern_ids],
                "notification": notification,
            },
        )

    data = ContractDriftPromotePatternsData(
        org_id=payload.org_id,
        agent_id=payload.agent_id,
        min_drift=payload.min_drift,
        dry_run=payload.dry_run,
        scanned_item_count=len(items),
        eligible_item_count=len(eligible_items),
        created_pattern_count=created_count,
        reused_pattern_count=reused_count,
        pattern_ids=pattern_ids,
        notification=notification,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/eval/runs/{run_id}/execute", response_model=EvalRunExecuteResponse)
def execute_eval_run(
    run_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    exec_start = time.perf_counter()
    cases: List[Any] = []
    completed_at: datetime
    run_row: Any = None
    agent_id: Any = None
    exec_summary: Dict[str, Any] = {}
    answer_yes_count = 0
    source_yes_count = 0
    quality_good_count = 0
    answer_case_count = 0
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id, org_id, agent_id, golden_set_id, type::text, status::text, config
                    from public.eval_runs
                    where id = %s
                    for update
                    """,
                    (str(run_id),),
                )
                run_row = cur.fetchone()
                if not run_row:
                    _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(run_row[1]), context="eval_run_execute")  # type: ignore[index]

                agent_id = run_row[2]  # type: ignore[index]
                golden_set_id = run_row[3]  # type: ignore[index]
                run_type = str(run_row[4])  # type: ignore[index]
                run_status = run_row[5]  # type: ignore[index]
                run_config = run_row[6] or {}  # type: ignore[index]
                if not isinstance(run_config, dict):
                    run_config = {}
                run_handler = _resolve_run_type_handler(
                    agent_id=UUID(str(agent_id)),
                    run_type=run_type,
                    run_config=run_config,
                )
                _enforce_run_type_handler_mode(
                    handler_key=str(run_handler.get("handler_key", "default")),
                    handler_config=dict(run_handler.get("handler_config") or {}),
                    entrypoint="execute",
                )
                _enforce_golden_set_quality_gate(
                    agent_id=UUID(str(agent_id)),
                    golden_set_id=UUID(str(golden_set_id)) if golden_set_id is not None else None,
                    run_config=run_config,
                )
                _enforce_configured_gates(
                    agent_id=UUID(str(agent_id)),
                    run_type=run_type,
                    golden_set_id=UUID(str(golden_set_id)) if golden_set_id is not None else None,
                    run_config=run_config,
                )
                _enforce_agent_contract_issues(
                    agent_id=UUID(str(agent_id)),
                    run_type=run_type,
                    entrypoint="execute",
                    golden_set_id=UUID(str(golden_set_id)) if golden_set_id is not None else None,
                )
                if golden_set_id is None:
                    _error(
                        "EVAL_RUN_NO_GOLDEN_SET",
                        "Eval run cannot execute without golden_set_id.",
                        status.HTTP_400_BAD_REQUEST,
                    )
                if run_status == "running":
                    _error("EVAL_RUN_ALREADY_RUNNING", f"Eval run {run_id} is already running.", status.HTTP_409_CONFLICT)
                if run_status == "cancelled":
                    _error("EVAL_RUN_CANCELLED", f"Eval run {run_id} is cancelled.", status.HTTP_409_CONFLICT)
                if run_status != "pending":
                    _error(
                        "EVAL_RUN_STATUS_TRANSITION_INVALID",
                        f"Eval run {run_id} cannot execute from status={run_status}.",
                        status.HTTP_409_CONFLICT,
                    )
                _enforce_calibration_gate(
                    agent_id=UUID(str(agent_id)),
                    run_type=run_type,
                    run_config=run_config,
                )
                if _is_eval_run_cancel_requested(run_id):
                    raise EvalRunCancelledError("Cancellation requested before execution start.")

                executor_mode = str(run_config.get("executor_mode", "auto"))
                executor_timeout_ms = int(run_config.get("executor_timeout_ms", 15000))
                executor_headers = run_config.get("executor_headers") or {}
                if not isinstance(executor_headers, dict):
                    executor_headers = {}
                cur.execute(
                    """
                    select a.eval_profile_id, a.agent_type::text, a.api_endpoint
                    from public.agents a
                    where a.id = %s
                    """,
                    (str(agent_id),),
                )
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)

                eval_profile_id = agent_row[0]
                agent_type = agent_row[1]
                agent_api_endpoint = agent_row[2]
                executor = get_execution_service(
                    mode=executor_mode,
                    agent_endpoint=agent_api_endpoint,
                    timeout_ms=executor_timeout_ms,
                    headers=executor_headers,
                )
                if eval_profile_id is not None:
                    cur.execute(
                        """
                        select id::text, default_eval_mode::text, dimensions
                        from public.eval_profiles
                        where id = %s
                        """,
                        (str(eval_profile_id),),
                    )
                else:
                    cur.execute(
                        """
                        select id::text, default_eval_mode::text, dimensions
                        from public.eval_profiles
                        where is_builtin = true
                          and agent_type::text = %s
                        order by created_at asc
                        limit 1
                        """,
                        (str(agent_type),),
                    )
                profile_row = cur.fetchone()
                if not profile_row:
                    raise PolicyContractError(
                        f"No eval profile contract available for agent {agent_id} (agent_type={agent_type})."
                    )
                contract = parse_profile_contract(
                    profile_id=profile_row[0],
                    default_eval_mode=profile_row[1],
                    dimensions_json=profile_row[2],
                )

                try:
                    _assert_eval_run_transition_allowed(run_status, "running")
                except EvalRunStateTransitionError as exc:
                    _error("EVAL_RUN_STATUS_TRANSITION_INVALID", str(exc), status.HTTP_409_CONFLICT)
                cur.execute(
                    """
                    update public.eval_runs
                    set status = 'running',
                        started_at = coalesce(started_at, now()),
                        completed_at = null,
                        failure_reason = null
                    where id = %s
                    """,
                    (str(run_id),),
                )

                cur.execute("delete from public.eval_results where eval_run_id = %s", (str(run_id),))

                cur.execute(
                    """
                    select
                        id,
                        input,
                        expected_output,
                        acceptable_sources,
                        evaluation_mode::text,
                        evaluation_criteria
                    from public.golden_set_cases
                    where golden_set_id = %s
                    order by created_at asc
                    """,
                    (str(golden_set_id),),
                )
                cases = cur.fetchall()
                evaluator_bindings = _get_agent_evaluator_bindings(UUID(str(agent_id)))
                judge_cache: Dict[str, Any] = {}

                now_date = datetime.now(timezone.utc).date()
                for case in cases:
                    if _is_eval_run_cancel_requested(run_id):
                        raise EvalRunCancelledError("Cancellation requested during execution.")
                    case_start = time.perf_counter()
                    case_id = case[0]
                    input_text = case[1] or ""
                    expected_output = case[2]
                    acceptable_sources = case[3]
                    eval_mode = case[4]
                    eval_criteria = case[5]
                    exec_out = executor.execute_case(
                        input_text=input_text,
                        expected_output=expected_output,
                        acceptable_sources=acceptable_sources,
                    )
                    actual_response = exec_out.get("actual_response")
                    actual_sources = exec_out.get("actual_sources")
                    exec_trace = exec_out.get("trace") or {}
                    if _is_eval_run_cancel_requested(run_id):
                        raise EvalRunCancelledError("Cancellation requested during execution.")
                    judge_cfg = _resolve_judge_config_for_eval_mode(
                        eval_mode=str(eval_mode),
                        run_config=run_config,
                        evaluator_bindings=evaluator_bindings,
                    )
                    judge_mode = str(judge_cfg.get("judge_mode", "deterministic"))
                    judge_model = judge_cfg.get("judge_model")
                    judge_prompt_version = judge_cfg.get("judge_prompt_version")
                    judge_cache_key = f"{judge_mode}|{judge_model}|{judge_prompt_version}"
                    judge = judge_cache.get(judge_cache_key)
                    if judge is None:
                        judge = get_judge_service(
                            mode=judge_mode,
                            prompt_version=judge_prompt_version,
                            model=judge_model,
                        )
                        judge_cache[judge_cache_key] = judge

                    if eval_mode == "answer":
                        judge_start = time.perf_counter()
                        score = judge.score_answer_case(
                            input_text=input_text,
                            expected_output=expected_output,
                            acceptable_sources=acceptable_sources,
                            actual_response=actual_response,
                            actual_sources=actual_sources,
                        )
                        judge_latency_ms = round((time.perf_counter() - judge_start) * 1000, 2)
                        answer_case_count += 1
                        if score["answer_correct"] == "yes":
                            answer_yes_count += 1
                        if score["source_correct"] == "yes":
                            source_yes_count += 1
                        if score["response_quality"] == "good":
                            quality_good_count += 1
                        validate_answer_result(
                            contract,
                            evaluation_mode=eval_mode,
                            answer_correct=score["answer_correct"],
                            source_correct=score["source_correct"],
                            response_quality=score["response_quality"],
                            answer_issues=[],
                            source_issues=[],
                            quality_issues=[],
                        )
                        trace_notes = {
                            "trace_version": "v1",
                            "execution_mode": executor_mode,
                            "judge_mode": judge_mode,
                            "judge_model": judge_model,
                            "judge_prompt_version": judge_prompt_version,
                            "case_latency_ms": round((time.perf_counter() - case_start) * 1000, 2),
                            "judge_latency_ms": judge_latency_ms,
                            "execution_trace": exec_trace,
                        }
                        cur.execute(
                            """
                            insert into public.eval_results (
                                eval_run_id,
                                case_id,
                                agent_id,
                                evaluation_mode,
                                actual_response,
                                actual_sources,
                                answer_correct,
                                answer_issues,
                                source_correct,
                                source_issues,
                                response_quality,
                                quality_issues,
                                reasoning,
                                tester,
                                search_mode,
                                eval_date,
                                notes,
                                match_type,
                                matched_case_id
                            )
                            values (
                                %s, %s, %s, 'answer'::public.eval_mode, %s, %s,
                                %s::public.ynp_score, %s::text[],
                                %s::public.ynp_score, %s::text[],
                                %s::public.quality_score, %s::text[],
                                %s, %s, %s, %s, %s,
                                'golden_set'::public.match_type, %s
                            )
                            returning id
                            """,
                            (
                                str(run_id),
                                str(case_id),
                                str(agent_id),
                                actual_response,
                                actual_sources,
                                score["answer_correct"],
                                [],
                                score["source_correct"],
                                [],
                                score["response_quality"],
                                [],
                                score["reasoning"],
                                "system",
                                "default",
                                now_date,
                                json.dumps(trace_notes),
                                str(case_id),
                            ),
                        )
                        eval_result_id = cur.fetchone()[0]  # type: ignore[index]
                        token_usage = score.get("_provider_meta", {}).get("usage")
                        if not isinstance(token_usage, dict):
                            token_usage = {}
                        cur.execute(
                            """
                            insert into public.eval_run_artifacts (
                                eval_run_id,
                                eval_result_id,
                                case_id,
                                agent_id,
                                evaluation_mode,
                                judge_mode,
                                judge_model,
                                judge_prompt_version,
                                judge_prompt_hash,
                                executor_mode,
                                case_latency_ms,
                                execution_latency_ms,
                                judge_latency_ms,
                                token_usage,
                                judge_input,
                                judge_output,
                                execution_trace
                            )
                            values (
                                %s, %s, %s, %s,
                                'answer'::public.eval_mode,
                                %s, %s, %s, %s, %s,
                                %s, %s, %s,
                                %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb
                            )
                            """,
                            (
                                str(run_id),
                                str(eval_result_id),
                                str(case_id),
                                str(agent_id),
                                judge_mode,
                                judge_model,
                                judge_prompt_version,
                                _compute_judge_prompt_hash(
                                    judge_mode=judge_mode,
                                    judge_model=str(judge_model) if judge_model is not None else None,
                                    judge_prompt_version=str(judge_prompt_version) if judge_prompt_version is not None else None,
                                    evaluation_mode="answer",
                                ),
                                executor_mode,
                                float(trace_notes["case_latency_ms"]),
                                float(exec_trace.get("duration_ms")) if exec_trace.get("duration_ms") is not None else None,
                                float(judge_latency_ms),
                                json.dumps(token_usage),
                                json.dumps(
                                    {
                                        "input_text": input_text,
                                        "expected_output": expected_output,
                                        "acceptable_sources": acceptable_sources,
                                        "actual_response": actual_response,
                                        "actual_sources": actual_sources,
                                    }
                                ),
                                json.dumps(_public_judge_output_payload(score)),
                                json.dumps(exec_trace),
                            ),
                        )
                    else:
                        judge_start = time.perf_counter()
                        criteria_eval = judge.score_criteria_case(
                            input_text=input_text,
                            criteria=eval_criteria,
                            actual_response=actual_response,
                        )
                        judge_latency_ms = round((time.perf_counter() - judge_start) * 1000, 2)
                        validate_criteria_result(
                            contract,
                            evaluation_mode=eval_mode,
                            criteria_results=criteria_eval["criteria_results"],
                            dimension_scores=criteria_eval["dimension_scores"],
                            overall_score=criteria_eval["overall_score"],
                        )
                        trace_notes = {
                            "trace_version": "v1",
                            "execution_mode": executor_mode,
                            "judge_mode": judge_mode,
                            "judge_model": judge_model,
                            "judge_prompt_version": judge_prompt_version,
                            "case_latency_ms": round((time.perf_counter() - case_start) * 1000, 2),
                            "judge_latency_ms": judge_latency_ms,
                            "execution_trace": exec_trace,
                        }
                        cur.execute(
                            """
                            insert into public.eval_results (
                                eval_run_id,
                                case_id,
                                agent_id,
                                evaluation_mode,
                                actual_response,
                                criteria_results,
                                dimension_scores,
                                overall_score,
                                reasoning,
                                tester,
                                search_mode,
                                eval_date,
                                notes,
                                match_type,
                                matched_case_id
                            )
                            values (
                                %s, %s, %s, 'criteria'::public.eval_mode, %s,
                                %s::jsonb, %s::jsonb, %s,
                                %s, %s, %s, %s, %s,
                                'golden_set'::public.match_type, %s
                            )
                            returning id
                            """,
                            (
                                str(run_id),
                                str(case_id),
                                str(agent_id),
                                actual_response,
                                json.dumps(criteria_eval["criteria_results"]),
                                json.dumps(criteria_eval["dimension_scores"]),
                                criteria_eval["overall_score"],
                                criteria_eval["reasoning"],
                                "system",
                                "default",
                                now_date,
                                json.dumps(trace_notes),
                                str(case_id),
                            ),
                        )
                        eval_result_id = cur.fetchone()[0]  # type: ignore[index]
                        token_usage = criteria_eval.get("_provider_meta", {}).get("usage")
                        if not isinstance(token_usage, dict):
                            token_usage = {}
                        cur.execute(
                            """
                            insert into public.eval_run_artifacts (
                                eval_run_id,
                                eval_result_id,
                                case_id,
                                agent_id,
                                evaluation_mode,
                                judge_mode,
                                judge_model,
                                judge_prompt_version,
                                judge_prompt_hash,
                                executor_mode,
                                case_latency_ms,
                                execution_latency_ms,
                                judge_latency_ms,
                                token_usage,
                                judge_input,
                                judge_output,
                                execution_trace
                            )
                            values (
                                %s, %s, %s, %s,
                                'criteria'::public.eval_mode,
                                %s, %s, %s, %s, %s,
                                %s, %s, %s,
                                %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb
                            )
                            """,
                            (
                                str(run_id),
                                str(eval_result_id),
                                str(case_id),
                                str(agent_id),
                                judge_mode,
                                judge_model,
                                judge_prompt_version,
                                _compute_judge_prompt_hash(
                                    judge_mode=judge_mode,
                                    judge_model=str(judge_model) if judge_model is not None else None,
                                    judge_prompt_version=str(judge_prompt_version) if judge_prompt_version is not None else None,
                                    evaluation_mode="criteria",
                                ),
                                executor_mode,
                                float(trace_notes["case_latency_ms"]),
                                float(exec_trace.get("duration_ms")) if exec_trace.get("duration_ms") is not None else None,
                                float(judge_latency_ms),
                                json.dumps(token_usage),
                                json.dumps(
                                    {
                                        "input_text": input_text,
                                        "evaluation_criteria": eval_criteria,
                                        "actual_response": actual_response,
                                    }
                                ),
                                json.dumps(_public_judge_output_payload(criteria_eval)),
                                json.dumps(exec_trace),
                            ),
                        )

                exec_summary = {
                    "execution": {
                        "trace_version": "v1",
                        "executor_mode": executor_mode,
                        "executor_timeout_ms": executor_timeout_ms,
                        "executor_has_headers": bool(executor_headers),
                        "judge_mode": judge_mode,
                        "judge_model": judge_model,
                        "judge_prompt_version": judge_prompt_version,
                        "case_count": len(cases),
                        "duration_ms": round((time.perf_counter() - exec_start) * 1000, 2),
                        "executed_at": datetime.now(timezone.utc).isoformat(),
                    }
                }
                cur.execute(
                    """
                    update public.eval_runs
                    set status = 'completed',
                        completed_at = now(),
                        design_context = coalesce(design_context, '{}'::jsonb) || %s::jsonb,
                        failure_reason = null
                    where id = %s
                    returning completed_at
                    """,
                    (json.dumps(exec_summary), str(run_id)),
                )
                completed_at = cur.fetchone()[0]  # type: ignore[index]

    except EvalRunCancelledError as exc:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'cancelled',
                            completed_at = coalesce(completed_at, now()),
                            failure_reason = coalesce(failure_reason, %s)
                        where id = %s
                        returning completed_at
                        """,
                        (str(exc), str(run_id)),
                    )
                    row = cur.fetchone()
                    completed_at = row[0] if row else datetime.now(timezone.utc)
        except Exception:
            completed_at = datetime.now(timezone.utc)
        data = EvalRunExecuteData(
            run_id=run_id,
            status="cancelled",
            case_count=len(cases),
            completed_at=completed_at,
            slo_status="healthy",
            slo_violations=[],
        )
        return {"ok": True, "data": data.model_dump(mode="json")}
    except JudgeConfigurationError as exc:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'failed',
                            completed_at = now(),
                            failure_reason = %s
                        where id = %s
                        """,
                        (str(exc), str(run_id)),
                    )
        except Exception:
            pass
        _error("EVAL_JUDGE_CONFIG_ERROR", str(exc), status.HTTP_400_BAD_REQUEST)
    except ExecutionConfigurationError as exc:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'failed',
                            completed_at = now(),
                            failure_reason = %s
                        where id = %s
                        """,
                        (str(exc), str(run_id)),
                    )
        except Exception:
            pass
        _error("EVAL_EXECUTOR_CONFIG_ERROR", str(exc), status.HTTP_400_BAD_REQUEST)
    except ExecutionRuntimeError as exc:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'failed',
                            completed_at = now(),
                            failure_reason = %s
                        where id = %s
                        """,
                        (str(exc), str(run_id)),
                    )
        except Exception:
            pass
        _error("EVAL_EXECUTOR_RUNTIME_ERROR", str(exc), status.HTTP_502_BAD_GATEWAY)
    except ProviderJudgeNotReadyError as exc:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'failed',
                            completed_at = now(),
                            failure_reason = %s
                        where id = %s
                        """,
                        (str(exc), str(run_id)),
                    )
        except Exception:
            pass
        _error("EVAL_JUDGE_NOT_READY", str(exc), status.HTTP_501_NOT_IMPLEMENTED)
    except ProviderJudgeRuntimeError as exc:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'failed',
                            completed_at = now(),
                            failure_reason = %s
                        where id = %s
                        """,
                        (str(exc), str(run_id)),
                    )
        except Exception:
            pass
        _error("EVAL_JUDGE_PROVIDER_ERROR", str(exc), status.HTTP_502_BAD_GATEWAY)
    except PolicyContractError as exc:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'failed',
                            completed_at = now(),
                            failure_reason = %s
                        where id = %s
                        """,
                        (str(exc), str(run_id)),
                    )
        except Exception:
            pass
        _error("EVAL_POLICY_CONTRACT_ERROR", str(exc), status.HTTP_400_BAD_REQUEST)
    except HTTPException:
        raise
    except Exception as exc:
        # Best effort failure-state write for observability.
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update public.eval_runs
                        set status = 'failed',
                            completed_at = now(),
                            failure_reason = %s
                        where id = %s
                        """,
                        (str(exc), str(run_id)),
                    )
        except Exception:
            pass
        _error("EVAL_RUN_EXECUTION_FAILED", f"Failed to execute eval run: {exc}", status.HTTP_400_BAD_REQUEST)

    data = EvalRunExecuteData(
        run_id=run_id,
        status="completed",
        case_count=len(cases),  # type: ignore[arg-type]
        completed_at=completed_at,
    )
    policy = _get_slo_policy(UUID(str(agent_id)))  # type: ignore[arg-type]
    slo_violations: List[Dict[str, Any]] = []
    if policy:
        denom = answer_case_count if answer_case_count > 0 else 1
        answer_yes_rate = answer_yes_count / denom
        source_yes_rate = source_yes_count / denom
        quality_good_rate = quality_good_count / denom
        duration_ms = float(exec_summary["execution"]["duration_ms"])  # type: ignore[index]

        checks = [
            ("min_answer_yes_rate", policy.get("min_answer_yes_rate"), answer_yes_rate, ">="),
            ("min_source_yes_rate", policy.get("min_source_yes_rate"), source_yes_rate, ">="),
            ("min_quality_good_rate", policy.get("min_quality_good_rate"), quality_good_rate, ">="),
            ("max_run_duration_ms", policy.get("max_run_duration_ms"), duration_ms, "<="),
        ]
        for metric, expected, actual, comparator in checks:
            if expected is None:
                continue
            violated = (actual < expected) if comparator == ">=" else (actual > expected)
            if not violated:
                continue
            notify = _emit_slo_violation(
                org_id=UUID(str(run_row[1])),  # type: ignore[index]
                agent_id=UUID(str(agent_id)),  # type: ignore[arg-type]
                policy_id=UUID(str(policy["id"])),
                source="run_execute",
                source_ref_id=run_id,
                metric=metric,
                actual_value=float(actual),
                expected_value=float(expected),
                comparator=comparator,
                details={"run_id": str(run_id), "case_count": len(cases)},
            )
            slo_violations.append(
                {
                    "metric": metric,
                    "actual_value": float(actual),
                    "expected_value": float(expected),
                    "comparator": comparator,
                    "notification": notify,
                }
            )
    data.slo_status = "violated" if slo_violations else "healthy"
    data.slo_violations = slo_violations
    _record_activity_event(
        org_id=UUID(str(run_row[1])),  # type: ignore[index]
        agent_id=UUID(str(agent_id)),  # type: ignore[arg-type]
        event_type="run_executed",
        title="Eval run executed",
        details=f"run_id={str(run_id)[:8]}, cases={len(cases)}",
        severity="info",
        metadata={"run_id": str(run_id), "case_count": len(cases), "status": "completed"},
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/eval/runs", response_model=EvalRunListResponse)
def list_eval_runs(
    org_id: Optional[UUID] = Query(default=None),
    agent_id: Optional[UUID] = Query(default=None),
    run_type: Optional[RunType] = Query(default=None, alias="type"),
    run_status: Optional[RunStatus] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="eval_run_list")
    where = []
    params: List[Any] = []

    if scoped_org_id is not None:
        where.append("er.org_id = %s")
        params.append(scoped_org_id)
    if agent_id is not None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(agent_row[1]), context="eval_run_list")
        where.append("er.agent_id = %s")
        params.append(str(agent_id))
    if run_type is not None:
        where.append("er.type::text = %s")
        params.append(run_type)
    if run_status is not None:
        where.append("er.status::text = %s")
        params.append(run_status)

    where_sql = f"where {' and '.join(where)}" if where else ""

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select
                    er.id,
                    er.org_id,
                    er.agent_id,
                    er.golden_set_id,
                    er.name,
                    er.type::text,
                    er.status::text,
                    er.created_at,
                    er.started_at,
                    er.completed_at,
                    er.failure_reason,
                    count(r.id) as result_count,
                    count(*) filter (where r.answer_correct = 'yes') as answer_yes_count,
                    count(*) filter (where r.source_correct = 'yes') as source_yes_count,
                    count(*) filter (where r.response_quality = 'good') as quality_good_count
                from public.eval_runs er
                left join public.eval_results r on r.eval_run_id = er.id
                {where_sql}
                group by er.id
                order by er.created_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.eval_runs er
                {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items: List[Dict[str, Any]] = []
    for row in rows:
        result_count = int(row[11] or 0)  # type: ignore[index]
        answer_yes_count = int(row[12] or 0)  # type: ignore[index]
        source_yes_count = int(row[13] or 0)  # type: ignore[index]
        quality_good_count = int(row[14] or 0)  # type: ignore[index]

        def _rate(n: int) -> float:
            if result_count == 0:
                return 0.0
            return n / result_count

        items.append(
            EvalRunListItem(
                id=row[0],  # type: ignore[index]
                org_id=row[1],  # type: ignore[index]
                agent_id=row[2],  # type: ignore[index]
                golden_set_id=row[3],  # type: ignore[index]
                name=row[4],  # type: ignore[index]
                type=row[5],  # type: ignore[index]
                status=row[6],  # type: ignore[index]
                created_at=row[7],  # type: ignore[index]
                started_at=row[8],  # type: ignore[index]
                completed_at=row[9],  # type: ignore[index]
                failure_reason=row[10],  # type: ignore[index]
                result_count=result_count,
                answer_yes_rate=_rate(answer_yes_count),
                source_yes_rate=_rate(source_yes_count),
                quality_good_rate=_rate(quality_good_count),
            ).model_dump(mode="json")
        )

    return {
        "ok": True,
        "data": {
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/eval/runs/{run_id}", response_model=EvalRunResponse)
def get_eval_run(
    run_id: UUID = Path(...),
    include_results: bool = Query(default=False),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    er.id,
                    er.org_id,
                    er.agent_id,
                    er.golden_set_id,
                    er.name,
                    er.type::text,
                    er.status::text,
                    er.config,
                    er.design_context,
                    er.created_at,
                    er.started_at,
                    er.completed_at,
                    er.failure_reason,
                    count(r.id) as result_count
                from public.eval_runs er
                left join public.eval_results r on r.eval_run_id = er.id
                where er.id = %s
                group by er.id
                """,
                (str(run_id),),
            )
            row = cur.fetchone()
            if not row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(row[1]), context="eval_run_read")  # type: ignore[index]

            results = None
            if include_results:
                cur.execute(
                    """
                    select
                        id,
                        case_id,
                        evaluation_mode::text,
                        match_type::text,
                        answer_correct::text,
                        source_correct::text,
                        response_quality::text,
                        overall_score,
                        created_at
                    from public.eval_results
                    where eval_run_id = %s
                    order by created_at asc
                    """,
                    (str(run_id),),
                )
                result_rows = cur.fetchall()
                results = [
                    EvalRunResultItem(
                        id=r[0],
                        case_id=r[1],
                        evaluation_mode=r[2],
                        match_type=r[3],
                        answer_correct=r[4],
                        source_correct=r[5],
                        response_quality=r[6],
                        overall_score=r[7],
                        created_at=r[8],
                    )
                    for r in result_rows
                ]

    data = EvalRunData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        golden_set_id=row[3],  # type: ignore[index]
        name=row[4],  # type: ignore[index]
        type=row[5],  # type: ignore[index]
        status=row[6],  # type: ignore[index]
        config=row[7],  # type: ignore[index]
        design_context=row[8],  # type: ignore[index]
        created_at=row[9],  # type: ignore[index]
        started_at=row[10],  # type: ignore[index]
        completed_at=row[11],  # type: ignore[index]
        failure_reason=row[12],  # type: ignore[index]
        result_count=row[13],  # type: ignore[index]
        results=results,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/eval/runs/{run_id}/results", response_model=EvalRunResultsResponse)
def get_eval_run_results(
    run_id: UUID = Path(...),
    evaluation_mode: Optional[EvaluationMode] = Query(default=None),
    answer_correct: Optional[Literal["yes", "partially", "no"]] = Query(default=None),
    source_correct: Optional[Literal["yes", "partially", "no"]] = Query(default=None),
    response_quality: Optional[Literal["good", "average", "not_good"]] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.eval_runs where id = %s", (str(run_id),))
            run_row = cur.fetchone()
            if not run_row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(run_row[1]), context="eval_run_results_read")  # type: ignore[index]

            where = ["r.eval_run_id = %s"]
            params: List[Any] = [str(run_id)]

            if evaluation_mode is not None:
                where.append("r.evaluation_mode::text = %s")
                params.append(evaluation_mode)
            if answer_correct is not None:
                where.append("r.answer_correct::text = %s")
                params.append(answer_correct)
            if source_correct is not None:
                where.append("r.source_correct::text = %s")
                params.append(source_correct)
            if response_quality is not None:
                where.append("r.response_quality::text = %s")
                params.append(response_quality)

            where_sql = " and ".join(where)
            cur.execute(
                f"""
                select
                    r.id,
                    r.eval_run_id,
                    r.case_id,
                    r.agent_id,
                    r.evaluation_mode::text,
                    r.actual_response,
                    r.actual_sources,
                    r.answer_correct::text,
                    r.answer_issues,
                    r.source_correct::text,
                    r.source_issues,
                    r.response_quality::text,
                    r.quality_issues,
                    r.criteria_results,
                    r.dimension_scores,
                    r.overall_score,
                    r.reasoning,
                    r.tester,
                    r.search_mode,
                    r.eval_date,
                    r.notes,
                    r.match_type::text,
                    r.matched_case_id,
                    r.created_at
                from public.eval_results r
                where {where_sql}
                order by r.created_at asc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.eval_results r
                where {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = [
        EvalRunResultDetailItem(
            id=r[0],
            eval_run_id=r[1],
            case_id=r[2],
            agent_id=r[3],
            evaluation_mode=r[4],
            actual_response=r[5],
            actual_sources=r[6],
            answer_correct=r[7],
            answer_issues=r[8] or [],
            source_correct=r[9],
            source_issues=r[10] or [],
            response_quality=r[11],
            quality_issues=r[12] or [],
            criteria_results=r[13],
            dimension_scores=r[14],
            overall_score=r[15],
            reasoning=r[16],
            tester=r[17],
            search_mode=r[18],
            eval_date=r[19].isoformat() if r[19] else None,
            notes=r[20],
            match_type=r[21],
            matched_case_id=r[22],
            created_at=r[23],
        ).model_dump(mode="json")
        for r in rows
    ]

    return {
        "ok": True,
        "data": {
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/eval/runs/{run_id}/artifacts", response_model=EvalRunArtifactsResponse)
def get_eval_run_artifacts(
    run_id: UUID = Path(...),
    case_id: Optional[UUID] = Query(default=None),
    evaluation_mode: Optional[EvaluationMode] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.eval_runs where id = %s", (str(run_id),))
            run_row = cur.fetchone()
            if not run_row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(run_row[1]), context="eval_run_artifacts_read")  # type: ignore[index]

            where = ["a.eval_run_id = %s"]
            params: List[Any] = [str(run_id)]
            if case_id is not None:
                where.append("a.case_id = %s")
                params.append(str(case_id))
            if evaluation_mode is not None:
                where.append("a.evaluation_mode::text = %s")
                params.append(evaluation_mode)
            where_sql = " and ".join(where)

            cur.execute(
                f"""
                select
                    a.id,
                    a.eval_run_id,
                    a.eval_result_id,
                    a.case_id,
                    a.agent_id,
                    a.evaluation_mode::text,
                    a.judge_mode,
                    a.judge_model,
                    a.judge_prompt_version,
                    a.judge_prompt_hash,
                    a.executor_mode,
                    a.case_latency_ms,
                    a.execution_latency_ms,
                    a.judge_latency_ms,
                    a.token_usage,
                    a.judge_input,
                    a.judge_output,
                    a.execution_trace,
                    a.created_at
                from public.eval_run_artifacts a
                where {where_sql}
                order by a.created_at asc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.eval_run_artifacts a
                where {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = [
        EvalRunArtifactItem(
            id=r[0],
            eval_run_id=r[1],
            eval_result_id=r[2],
            case_id=r[3],
            agent_id=r[4],
            evaluation_mode=r[5],
            judge_mode=r[6],
            judge_model=r[7],
            judge_prompt_version=r[8],
            judge_prompt_hash=r[9],
            executor_mode=r[10],
            case_latency_ms=float(r[11]) if r[11] is not None else None,
            execution_latency_ms=float(r[12]) if r[12] is not None else None,
            judge_latency_ms=float(r[13]) if r[13] is not None else None,
            token_usage=r[14] or {},
            judge_input=r[15] or {},
            judge_output=r[16] or {},
            execution_trace=r[17] or {},
            created_at=r[18],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {
        "ok": True,
        "data": {
            "run_id": str(run_id),
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/eval/runs/{run_id}/review-queue", response_model=EvalRunReviewQueueResponse)
def get_eval_run_review_queue(
    run_id: UUID = Path(...),
    include_reviewed: bool = Query(default=False),
    only_actionable: bool = Query(default=True),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.eval_runs where id = %s", (str(run_id),))
            run_row = cur.fetchone()
            if not run_row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(run_row[1]), context="eval_run_review_queue_read")  # type: ignore[index]

            where = ["r.eval_run_id = %s"]
            params: List[Any] = [str(run_id)]
            if not include_reviewed:
                where.append("r.review_status = 'unreviewed'::public.eval_review_status")
            if only_actionable:
                where.append(
                    "("
                    "(r.evaluation_mode = 'answer'::public.eval_mode and ("
                    "r.answer_correct <> 'yes'::public.ynp_score or "
                    "r.source_correct <> 'yes'::public.ynp_score or "
                    "r.response_quality <> 'good'::public.quality_score"
                    ")) "
                    "or "
                    "(r.evaluation_mode = 'criteria'::public.eval_mode and coalesce(r.overall_score, '') <> 'good')"
                    ")"
                )
            where_sql = " and ".join(where)

            cur.execute(
                f"""
                select
                    r.id,
                    r.eval_run_id,
                    r.case_id,
                    r.agent_id,
                    r.evaluation_mode::text,
                    r.answer_correct::text,
                    r.source_correct::text,
                    r.response_quality::text,
                    r.overall_score,
                    r.reasoning,
                    r.review_status::text,
                    r.review_decision,
                    r.review_reason,
                    r.review_override,
                    r.reviewed_by_api_key_id,
                    r.reviewed_at,
                    r.created_at
                from public.eval_results r
                where {where_sql}
                order by r.created_at asc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.eval_results r
                where {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = []
    for r in rows:
        override = r[13] or {}  # type: ignore[index]
        if not isinstance(override, dict):
            override = {}
        items.append(
            EvalRunReviewQueueItem(
                id=r[0],
                eval_run_id=r[1],
                case_id=r[2],
                agent_id=r[3],
                evaluation_mode=r[4],
                answer_correct=r[5],
                source_correct=r[6],
                response_quality=r[7],
                overall_score=r[8],
                reasoning=r[9],
                review_status=r[10],
                review_decision=r[11],
                review_reason=r[12],
                review_override=override,
                reviewed_by_api_key_id=r[14],
                reviewed_at=r[15],
                review_diff=_compute_review_diff(
                    evaluation_mode=str(r[4]),
                    answer_correct=r[5],
                    source_correct=r[6],
                    response_quality=r[7],
                    overall_score=r[8],
                    review_override=override,
                ),
                created_at=r[16],
            ).model_dump(mode="json")
        )

    return {
        "ok": True,
        "data": {
            "run_id": str(run_id),
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
        },
    }


@app.patch("/api/eval/runs/{run_id}/results/{result_id}/review", response_model=EvalRunResultReviewResponse)
def review_eval_run_result(
    payload: EvalRunResultReviewRequest,
    run_id: UUID = Path(...),
    result_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    override = payload.override if isinstance(payload.override, dict) else {}
    decision = payload.decision

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    r.id,
                    r.eval_run_id,
                    r.agent_id,
                    er.org_id,
                    r.evaluation_mode::text,
                    r.answer_correct::text,
                    r.source_correct::text,
                    r.response_quality::text,
                    r.overall_score
                from public.eval_results r
                join public.eval_runs er on er.id = r.eval_run_id
                where r.id = %s and r.eval_run_id = %s
                for update
                """,
                (str(result_id), str(run_id)),
            )
            row = cur.fetchone()
            if not row:
                _error("EVAL_RESULT_NOT_FOUND", f"Eval result {result_id} was not found for run {run_id}.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(row[3]), context="eval_result_review")  # type: ignore[index]

            evaluation_mode = str(row[4])  # type: ignore[index]
            sanitized_override: Dict[str, Any] = {}
            if decision == "override":
                if not payload.reason or not payload.reason.strip():
                    _error("EVAL_RESULT_REVIEW_REASON_REQUIRED", "reason is required when decision=override.", status.HTTP_400_BAD_REQUEST)
                if evaluation_mode == "answer":
                    allowed = {"answer_correct", "source_correct", "response_quality"}
                    sanitized_override = {k: v for k, v in override.items() if k in allowed}
                    if "answer_correct" in sanitized_override and sanitized_override["answer_correct"] not in {"yes", "partially", "no"}:
                        _error("EVAL_RESULT_REVIEW_OVERRIDE_INVALID", "answer_correct override must be yes|partially|no.", status.HTTP_400_BAD_REQUEST)
                    if "source_correct" in sanitized_override and sanitized_override["source_correct"] not in {"yes", "partially", "no"}:
                        _error("EVAL_RESULT_REVIEW_OVERRIDE_INVALID", "source_correct override must be yes|partially|no.", status.HTTP_400_BAD_REQUEST)
                    if "response_quality" in sanitized_override and sanitized_override["response_quality"] not in {"good", "average", "not_good"}:
                        _error("EVAL_RESULT_REVIEW_OVERRIDE_INVALID", "response_quality override must be good|average|not_good.", status.HTTP_400_BAD_REQUEST)
                else:
                    allowed = {"overall_score", "dimension_scores", "criteria_results"}
                    sanitized_override = {k: v for k, v in override.items() if k in allowed}
                if not sanitized_override:
                    _error("EVAL_RESULT_REVIEW_OVERRIDE_REQUIRED", "override payload must include at least one supported field.", status.HTTP_400_BAD_REQUEST)
                review_status: ReviewStatus = "overridden"
            else:
                review_status = "accepted"
                sanitized_override = {}

            reviewed_by = api_key_ctx.get("key_id")
            reviewed_at = datetime.now(timezone.utc)
            cur.execute(
                """
                update public.eval_results
                set review_status = %s::public.eval_review_status,
                    reviewed_by_api_key_id = %s,
                    reviewed_at = %s,
                    review_decision = %s,
                    review_reason = %s,
                    review_override = %s::jsonb
                where id = %s and eval_run_id = %s
                returning
                    review_status::text,
                    review_decision,
                    review_reason,
                    review_override,
                    reviewed_by_api_key_id,
                    reviewed_at
                """,
                (
                    review_status,
                    str(reviewed_by) if reviewed_by else None,
                    reviewed_at,
                    decision,
                    payload.reason.strip() if payload.reason else None,
                    json.dumps(sanitized_override),
                    str(result_id),
                    str(run_id),
                ),
            )
            updated = cur.fetchone()

    review_override = updated[3] or {}  # type: ignore[index]
    if not isinstance(review_override, dict):
        review_override = {}
    review_diff = _compute_review_diff(
        evaluation_mode=evaluation_mode,
        answer_correct=row[5],  # type: ignore[index]
        source_correct=row[6],  # type: ignore[index]
        response_quality=row[7],  # type: ignore[index]
        overall_score=row[8],  # type: ignore[index]
        review_override=review_override,
    )
    _record_activity_event(
        org_id=UUID(str(row[3])),  # type: ignore[index]
        agent_id=UUID(str(row[2])),  # type: ignore[index]
        event_type="result_reviewed",
        title="Eval result reviewed",
        details=f"run_id={str(run_id)[:8]}, result_id={str(result_id)[:8]}, decision={decision}",
        severity="info",
        metadata={
            "run_id": str(run_id),
            "result_id": str(result_id),
            "decision": decision,
            "review_status": updated[0],  # type: ignore[index]
            "review_diff": review_diff,
        },
    )
    data = EvalRunResultReviewData(
        run_id=run_id,
        result_id=result_id,
        review_status=updated[0],  # type: ignore[index]
        review_decision=updated[1],  # type: ignore[index]
        review_reason=updated[2],  # type: ignore[index]
        review_override=review_override,
        reviewed_by_api_key_id=updated[4],  # type: ignore[index]
        reviewed_at=updated[5],  # type: ignore[index]
        review_diff=review_diff,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/eval/runs/{run_id}/summary", response_model=EvalRunSummaryResponse)
def get_eval_run_summary(
    run_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select org_id from public.eval_runs where id = %s", (str(run_id),))
            org_row = cur.fetchone()
            if not org_row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(org_row[0]), context="eval_run_summary_read")  # type: ignore[index]

            cur.execute(
                """
                select
                    er.id,
                    er.status::text,
                    er.created_at,
                    er.completed_at,
                    count(r.id) as total_results,
                    count(*) filter (where r.answer_correct = 'yes') as answer_yes_count,
                    count(*) filter (where r.answer_correct = 'partially') as answer_partially_count,
                    count(*) filter (where r.answer_correct = 'no') as answer_no_count,
                    count(*) filter (where r.source_correct = 'yes') as source_yes_count,
                    count(*) filter (where r.source_correct = 'partially') as source_partially_count,
                    count(*) filter (where r.source_correct = 'no') as source_no_count,
                    count(*) filter (where r.response_quality = 'good') as quality_good_count,
                    count(*) filter (where r.response_quality = 'average') as quality_average_count,
                    count(*) filter (where r.response_quality = 'not_good') as quality_not_good_count
                from public.eval_runs er
                left join public.eval_results r on r.eval_run_id = er.id
                where er.id = %s
                group by er.id
                """,
                (str(run_id),),
            )
            row = cur.fetchone()
            if not row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)

    data = _summary_from_row(row)
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/eval/runs/{run_id}/events", response_model=EvalRunEventsResponse)
def get_eval_run_events(
    run_id: UUID = Path(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id, agent_id from public.eval_runs where id = %s", (str(run_id),))
            run_row = cur.fetchone()
            if not run_row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(run_row[1]), context="eval_run_events_read")  # type: ignore[index]
            agent_id = str(run_row[2])  # type: ignore[index]

            cur.execute(
                """
                select
                    ae.id,
                    ae.org_id,
                    ae.agent_id,
                    ae.event_type,
                    ae.severity::text,
                    ae.title,
                    ae.details,
                    ae.metadata,
                    ae.created_at
                from public.activity_events ae
                where ae.agent_id = %s
                  and ae.metadata->>'run_id' = %s
                order by ae.created_at desc
                limit %s
                offset %s
                """,
                (agent_id, str(run_id), limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                """
                select count(1)
                from public.activity_events ae
                where ae.agent_id = %s
                  and ae.metadata->>'run_id' = %s
                """,
                (agent_id, str(run_id)),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = [
        EvalRunEventItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            event_type=r[3],
            severity=r[4],
            title=r[5],
            details=r[6],
            metadata=r[7] or {},
            created_at=r[8],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {
        "ok": True,
        "data": {
            "run_id": str(run_id),
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
        },
    }


def _resolve_eval_compare_ref(
    *,
    cur: Any,
    agent_id: UUID,
    kind: RunRefKind,
    ref: str,
) -> UUID:
    ref_value = ref.strip()
    if not ref_value:
        _error(
            "EVAL_RUN_COMPARE_REFERENCE_INVALID",
            "Run reference cannot be empty.",
            status.HTTP_400_BAD_REQUEST,
        )
    ref_lower = ref_value.lower()
    if ref_lower == "latest":
        cur.execute(
            """
            select id
            from public.eval_runs
            where agent_id = %s
            order by created_at desc
            limit 1
            """,
            (str(agent_id),),
        )
        row = cur.fetchone()
        if not row:
            _error(
                "EVAL_RUN_COMPARE_REFERENCE_NOT_FOUND",
                f"No eval runs found for agent {agent_id}.",
                status.HTTP_404_NOT_FOUND,
            )
        return row[0]  # type: ignore[index]

    if ref_lower in {"active", "current"}:
        cur.execute(
            """
            select run_id
            from public.run_registry
            where agent_id = %s and kind = %s and is_active = true
            order by updated_at desc
            limit 1
            """,
            (str(agent_id), kind),
        )
    else:
        cur.execute(
            """
            select run_id
            from public.run_registry
            where agent_id = %s and kind = %s and name = %s
            limit 1
            """,
            (str(agent_id), kind, ref_value),
        )
    row = cur.fetchone()
    if not row:
        _error(
            "EVAL_RUN_COMPARE_REFERENCE_NOT_FOUND",
            f"Could not resolve {kind} reference '{ref_value}' for agent {agent_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    return row[0]  # type: ignore[index]


@app.get("/api/eval/compare", response_model=EvalRunComparisonResponse)
def compare_eval_runs(
    baseline_run_id: Optional[UUID] = Query(default=None),
    candidate_run_id: Optional[UUID] = Query(default=None),
    agent_id: Optional[UUID] = Query(default=None),
    baseline_ref: Optional[str] = Query(default=None),
    candidate_ref: Optional[str] = Query(default=None),
    auto_create_pattern: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1000),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    direct_mode = baseline_run_id is not None or candidate_run_id is not None
    ref_mode = agent_id is not None or baseline_ref is not None or candidate_ref is not None

    if direct_mode and ref_mode:
        _error(
            "EVAL_RUN_COMPARE_INVALID",
            "Use either direct run IDs or reference mode, not both.",
            status.HTTP_400_BAD_REQUEST,
        )
    if direct_mode:
        if baseline_run_id is None or candidate_run_id is None:
            _error(
                "EVAL_RUN_COMPARE_INVALID",
                "baseline_run_id and candidate_run_id are both required in direct mode.",
                status.HTTP_400_BAD_REQUEST,
            )
    elif ref_mode:
        if agent_id is None or not baseline_ref or not candidate_ref:
            _error(
                "EVAL_RUN_COMPARE_INVALID",
                "agent_id, baseline_ref, and candidate_ref are all required in reference mode.",
                status.HTTP_400_BAD_REQUEST,
            )
    else:
        _error(
            "EVAL_RUN_COMPARE_INVALID",
            "Provide either direct run IDs or reference mode parameters.",
            status.HTTP_400_BAD_REQUEST,
        )

    resolved_agent_id: Optional[UUID] = agent_id
    if ref_mode:
        assert agent_id is not None and baseline_ref is not None and candidate_ref is not None
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(agent_row[1]), context="eval_compare")  # type: ignore[index]
                baseline_run_id = _resolve_eval_compare_ref(cur=cur, agent_id=agent_id, kind="baseline", ref=baseline_ref)
                candidate_run_id = _resolve_eval_compare_ref(
                    cur=cur,
                    agent_id=agent_id,
                    kind="candidate",
                    ref=candidate_ref,
                )

    assert baseline_run_id is not None and candidate_run_id is not None
    if baseline_run_id == candidate_run_id:
        _error(
            "EVAL_RUN_COMPARE_INVALID",
            "baseline_run_id and candidate_run_id must be different.",
            status.HTTP_400_BAD_REQUEST,
        )

    summary_sql = """
        select
            er.id,
            er.status::text,
            er.created_at,
            er.completed_at,
            count(r.id) as total_results,
            count(*) filter (where r.answer_correct = 'yes') as answer_yes_count,
            count(*) filter (where r.answer_correct = 'partially') as answer_partially_count,
            count(*) filter (where r.answer_correct = 'no') as answer_no_count,
            count(*) filter (where r.source_correct = 'yes') as source_yes_count,
            count(*) filter (where r.source_correct = 'partially') as source_partially_count,
            count(*) filter (where r.source_correct = 'no') as source_no_count,
            count(*) filter (where r.response_quality = 'good') as quality_good_count,
            count(*) filter (where r.response_quality = 'average') as quality_average_count,
            count(*) filter (where r.response_quality = 'not_good') as quality_not_good_count
        from public.eval_runs er
        left join public.eval_results r on r.eval_run_id = er.id
        where er.id = %s
        group by er.id
    """

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id, agent_id from public.eval_runs where id = %s", (str(baseline_run_id),))
            baseline_run = cur.fetchone()
            if not baseline_run:
                _error(
                    "EVAL_RUN_NOT_FOUND",
                    f"Eval run {baseline_run_id} was not found.",
                    status.HTTP_404_NOT_FOUND,
                )

            cur.execute("select id, org_id, agent_id from public.eval_runs where id = %s", (str(candidate_run_id),))
            candidate_run = cur.fetchone()
            if not candidate_run:
                _error(
                    "EVAL_RUN_NOT_FOUND",
                    f"Eval run {candidate_run_id} was not found.",
                    status.HTTP_404_NOT_FOUND,
                )

            baseline_org_id = baseline_run[1]  # type: ignore[index]
            baseline_agent_id = baseline_run[2]  # type: ignore[index]
            candidate_org_id = candidate_run[1]  # type: ignore[index]
            candidate_agent_id = candidate_run[2]  # type: ignore[index]
            _assert_org_access(api_key_ctx, str(baseline_org_id), context="eval_compare")
            if baseline_agent_id != candidate_agent_id:
                _error(
                    "EVAL_RUN_COMPARE_MISMATCH",
                    "Both runs must belong to the same agent.",
                    status.HTTP_400_BAD_REQUEST,
                )
            if baseline_org_id != candidate_org_id:
                _error(
                    "EVAL_RUN_COMPARE_MISMATCH",
                    "Both runs must belong to the same org.",
                    status.HTTP_400_BAD_REQUEST,
                )
            if resolved_agent_id is not None and str(resolved_agent_id) != str(baseline_agent_id):
                _error(
                    "EVAL_RUN_COMPARE_MISMATCH",
                    "Resolved runs do not belong to the requested agent_id.",
                    status.HTTP_400_BAD_REQUEST,
                )
            cur.execute("select name from public.agents where id = %s", (str(baseline_agent_id),))
            agent_row = cur.fetchone()
            agent_name = agent_row[0] if agent_row else None

            cur.execute(summary_sql, (str(baseline_run_id),))
            baseline_summary_row = cur.fetchone()
            cur.execute(summary_sql, (str(candidate_run_id),))
            candidate_summary_row = cur.fetchone()

            if not baseline_summary_row or not candidate_summary_row:
                _error(
                    "EVAL_RUN_COMPARE_NO_SUMMARY",
                    "Could not compute summaries for one or both runs.",
                    status.HTTP_400_BAD_REQUEST,
                )

            cur.execute(
                """
                select
                    coalesce(case_id, matched_case_id) as case_ref,
                    evaluation_mode::text,
                    answer_correct::text,
                    source_correct::text,
                    response_quality::text
                from public.eval_results
                where eval_run_id = %s
                """,
                (str(baseline_run_id),),
            )
            baseline_rows = cur.fetchall()

            cur.execute(
                """
                select
                    coalesce(case_id, matched_case_id) as case_ref,
                    evaluation_mode::text,
                    answer_correct::text,
                    source_correct::text,
                    response_quality::text
                from public.eval_results
                where eval_run_id = %s
                """,
                (str(candidate_run_id),),
            )
            candidate_rows = cur.fetchall()

    baseline_summary = _summary_from_row(baseline_summary_row)
    candidate_summary = _summary_from_row(candidate_summary_row)

    baseline_map: Dict[str, Dict[str, Optional[str]]] = {
        str(r[0]): {
            "evaluation_mode": r[1],
            "answer_correct": r[2],
            "source_correct": r[3],
            "response_quality": r[4],
        }
        for r in baseline_rows
        if r[0] is not None
    }
    candidate_map: Dict[str, Dict[str, Optional[str]]] = {
        str(r[0]): {
            "evaluation_mode": r[1],
            "answer_correct": r[2],
            "source_correct": r[3],
            "response_quality": r[4],
        }
        for r in candidate_rows
        if r[0] is not None
    }

    shared_case_ids = sorted(set(baseline_map.keys()) & set(candidate_map.keys()))
    regressions: List[EvalRunRegressionItem] = []

    for case_id in shared_case_ids:
        base_case = baseline_map[case_id]
        cand_case = candidate_map[case_id]
        mode = str(cand_case.get("evaluation_mode") or base_case.get("evaluation_mode") or "answer")
        for metric in ("answer_correct", "source_correct", "response_quality"):
            base_value = base_case.get(metric)
            cand_value = cand_case.get(metric)
            if _is_value_regression(metric, base_value, cand_value):
                regressions.append(
                    EvalRunRegressionItem(
                        case_id=UUID(case_id),
                        evaluation_mode=mode,
                        metric=metric,
                        baseline_value=str(base_value),
                        candidate_value=str(cand_value),
                    )
                )
            if len(regressions) >= limit:
                break
        if len(regressions) >= limit:
            break

    answer_yes_rate_delta = round(candidate_summary.answer_yes_rate - baseline_summary.answer_yes_rate, 6)
    source_yes_rate_delta = round(candidate_summary.source_yes_rate - baseline_summary.source_yes_rate, 6)
    quality_good_rate_delta = round(candidate_summary.quality_good_rate - baseline_summary.quality_good_rate, 6)

    auto_pattern: Dict[str, Any] = {"enabled": auto_create_pattern, "created": False, "pattern_id": None}
    if auto_create_pattern and regressions:
        try:
            auto_pattern = _create_or_reuse_regression_pattern(
                org_id=baseline_org_id,  # type: ignore[arg-type]
                agent_id=baseline_agent_id,  # type: ignore[arg-type]
                baseline_run_id=baseline_run_id,
                candidate_run_id=candidate_run_id,
                regressions=regressions,
                answer_yes_rate_delta=answer_yes_rate_delta,
                source_yes_rate_delta=source_yes_rate_delta,
                quality_good_rate_delta=quality_good_rate_delta,
            )
        except Exception as exc:
            _error(
                "PATTERN_AUTO_CREATE_FAILED",
                f"Failed to auto-create issue pattern: {exc}",
                status.HTTP_400_BAD_REQUEST,
            )

    notification: Dict[str, Any] = {"sent": False, "event_type": "regression_detected"}
    if regressions:
        notification = _dispatch_notification(
            org_id=UUID(str(baseline_org_id)),  # type: ignore[arg-type]
            agent_id=UUID(str(baseline_agent_id)),  # type: ignore[arg-type]
            event_type="regression_detected",
            payload={
                "org_id": str(baseline_org_id),
                "agent_id": str(baseline_agent_id),
                "agent_name": str(agent_name) if agent_name else None,
                "baseline_run_id": str(baseline_run_id),
                "candidate_run_id": str(candidate_run_id),
                "regression_count": len(regressions),
                "total_compared_cases": len(shared_case_ids),
                "answer_yes_rate_delta": answer_yes_rate_delta,
                "source_yes_rate_delta": source_yes_rate_delta,
                "quality_good_rate_delta": quality_good_rate_delta,
                "pattern_id": auto_pattern.get("pattern_id"),
            },
        )

    _record_activity_event(
        org_id=UUID(str(baseline_org_id)),  # type: ignore[arg-type]
        agent_id=UUID(str(baseline_agent_id)),  # type: ignore[arg-type]
        event_type="regression_compare",
        title="Regression compare executed",
        details=f"baseline={str(baseline_run_id)[:8]}, candidate={str(candidate_run_id)[:8]}, regressions={len(regressions)}",
        severity="error" if regressions else "info",
        metadata={
            "baseline_run_id": str(baseline_run_id),
            "candidate_run_id": str(candidate_run_id),
            "regression_count": len(regressions),
            "answer_yes_rate_delta": answer_yes_rate_delta,
            "source_yes_rate_delta": source_yes_rate_delta,
            "quality_good_rate_delta": quality_good_rate_delta,
            "notification": notification,
            "auto_pattern": auto_pattern,
        },
    )

    slo_data: Dict[str, Any] = {"status": "healthy", "violations": []}
    policy = _get_slo_policy(UUID(str(baseline_agent_id)))  # type: ignore[arg-type]
    max_regression_count = policy.get("max_regression_count") if policy else None
    if max_regression_count is not None and len(regressions) > int(max_regression_count):
        notify = _emit_slo_violation(
            org_id=UUID(str(baseline_org_id)),  # type: ignore[arg-type]
            agent_id=UUID(str(baseline_agent_id)),  # type: ignore[arg-type]
            policy_id=UUID(str(policy["id"])) if policy else None,  # type: ignore[index]
            source="run_compare",
            source_ref_id=candidate_run_id,
            metric="max_regression_count",
            actual_value=float(len(regressions)),
            expected_value=float(max_regression_count),
            comparator="<=",
            details={"baseline_run_id": str(baseline_run_id), "candidate_run_id": str(candidate_run_id)},
        )
        slo_data = {
            "status": "violated",
            "violations": [
                {
                    "metric": "max_regression_count",
                    "actual_value": len(regressions),
                    "expected_value": int(max_regression_count),
                    "comparator": "<=",
                    "notification": notify,
                }
            ],
        }

    remediation_data: Dict[str, Any] = {"auto_closed": False, "updated_patterns": 0, "resolved_slo_violations": 0}
    if len(regressions) == 0:
        remediation_data = {"auto_closed": True, **_auto_close_remediation_on_clean_compare(
            org_id=UUID(str(baseline_org_id)),  # type: ignore[arg-type]
            agent_id=UUID(str(baseline_agent_id)),  # type: ignore[arg-type]
            baseline_run_id=baseline_run_id,
            candidate_run_id=candidate_run_id,
        )}

    comparison = EvalRunComparisonData(
        baseline_run_id=baseline_run_id,
        candidate_run_id=candidate_run_id,
        agent_id=baseline_agent_id,  # type: ignore[arg-type]
        baseline_summary=baseline_summary,
        candidate_summary=candidate_summary,
        total_compared_cases=len(shared_case_ids),
        regression_count=len(regressions),
        regressions=regressions,
        answer_yes_rate_delta=answer_yes_rate_delta,
        source_yes_rate_delta=source_yes_rate_delta,
        quality_good_rate_delta=quality_good_rate_delta,
        auto_pattern=auto_pattern,
        notification=notification,
        slo=slo_data,
        remediation=remediation_data,
    )
    return {"ok": True, "data": comparison.model_dump(mode="json")}


@app.get("/api/agents", response_model=AgentListResponse)
def list_agents(
    org_id: Optional[UUID] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    agent_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    scoped_org_id = _effective_org_for_scope(api_key_ctx, org_id, context="agent_list")
    where = []
    params: List[Any] = []

    if scoped_org_id is not None:
        where.append("a.org_id = %s")
        params.append(scoped_org_id)
    if status_filter is not None:
        where.append("a.status::text = %s")
        params.append(status_filter)
    if agent_type is not None:
        where.append("a.agent_type::text = %s")
        params.append(agent_type)

    where_sql = f"where {' and '.join(where)}" if where else ""

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select
                    a.id,
                    a.org_id,
                    a.name,
                    a.description,
                    a.agent_type::text,
                    a.status::text,
                    a.model,
                    a.api_endpoint,
                    a.owner_user_id,
                    a.eval_profile_id,
                    a.created_at,
                    a.updated_at
                from public.agents a
                {where_sql}
                order by a.created_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

    data = [
        AgentListItem(
            id=r[0],
            org_id=r[1],
            name=r[2],
            description=r[3],
            agent_type=r[4],
            status=r[5],
            model=r[6],
            api_endpoint=r[7],
            owner_user_id=r[8],
            eval_profile_id=r[9],
            created_at=r[10],
            updated_at=r[11],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"items": data, "count": len(data), "limit": limit, "offset": offset}}


@app.post("/api/agents", status_code=status.HTTP_201_CREATED, response_model=AgentDetailResponse)
def create_agent(
    payload: AgentCreateRequest = Body(
        ...,
        examples=[
            {
                "name": "create-agent",
                "summary": "Register a document generator agent",
                "value": {
                    "org_id": "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb",
                    "name": "Acme Story Draft Agent",
                    "description": "Generates first-pass user stories",
                    "agent_type": "document_generator",
                    "status": "build",
                    "model": "gpt-4.1",
                },
            }
        ],
    ),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="agent_create")
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.agents (
                        org_id,
                        name,
                        description,
                        agent_type,
                        status,
                        model,
                        api_endpoint,
                        owner_user_id,
                        eval_profile_id
                    )
                    values (
                        %s,
                        %s,
                        %s,
                        %s::public.agent_type,
                        %s::public.agent_status,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    returning
                        id,
                        org_id,
                        name,
                        description,
                        agent_type::text,
                        status::text,
                        model,
                        api_endpoint,
                        owner_user_id,
                        eval_profile_id,
                        created_at,
                        updated_at
                    """,
                    (
                        str(payload.org_id),
                        payload.name,
                        payload.description,
                        payload.agent_type,
                        payload.status,
                        payload.model,
                        payload.api_endpoint,
                        str(payload.owner_user_id) if payload.owner_user_id else None,
                        str(payload.eval_profile_id) if payload.eval_profile_id else None,
                    ),
                )
                row = cur.fetchone()
    except Exception as exc:
        _error("AGENT_CREATE_FAILED", f"Failed to create agent: {exc}", status.HTTP_400_BAD_REQUEST)

    item = AgentListItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        name=row[2],  # type: ignore[index]
        description=row[3],  # type: ignore[index]
        agent_type=row[4],  # type: ignore[index]
        status=row[5],  # type: ignore[index]
        model=row[6],  # type: ignore[index]
        api_endpoint=row[7],  # type: ignore[index]
        owner_user_id=row[8],  # type: ignore[index]
        eval_profile_id=row[9],  # type: ignore[index]
        created_at=row[10],  # type: ignore[index]
        updated_at=row[11],  # type: ignore[index]
    )
    return {"ok": True, "data": item.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}", response_model=AgentDetailResponse)
def get_agent(
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    a.id,
                    a.org_id,
                    a.name,
                    a.description,
                    a.agent_type::text,
                    a.status::text,
                    a.model,
                    a.api_endpoint,
                    a.owner_user_id,
                    a.eval_profile_id,
                    a.created_at,
                    a.updated_at
                from public.agents a
                where a.id = %s
                """,
                (str(agent_id),),
            )
            row = cur.fetchone()
            if not row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
    _assert_org_access(api_key_ctx, str(row[1]), context="agent_read")  # type: ignore[index]

    item = AgentListItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        name=row[2],  # type: ignore[index]
        description=row[3],  # type: ignore[index]
        agent_type=row[4],  # type: ignore[index]
        status=row[5],  # type: ignore[index]
        model=row[6],  # type: ignore[index]
        api_endpoint=row[7],  # type: ignore[index]
        owner_user_id=row[8],  # type: ignore[index]
        eval_profile_id=row[9],  # type: ignore[index]
        created_at=row[10],  # type: ignore[index]
        updated_at=row[11],  # type: ignore[index]
    )
    return {"ok": True, "data": item.model_dump(mode="json")}


@app.post("/api/agents/{agent_id}/invoke-contract/validate", response_model=AgentInvokeContractResponse)
def validate_agent_invoke(
    payload: AgentInvokeContractValidateRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, org_id, api_endpoint
                from public.agents
                where id = %s
                """,
                (str(agent_id),),
            )
            row = cur.fetchone()
            if not row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(row[1]), context="agent_invoke_contract_validate")  # type: ignore[index]
            endpoint = payload.endpoint_override or row[2]  # type: ignore[index]

    try:
        result = validate_agent_invoke_contract(
            endpoint=endpoint,
            sample_input=payload.sample_input,
            timeout_ms=payload.timeout_ms,
            headers=payload.headers,
        )
    except ExecutionConfigurationError as exc:
        _error("AGENT_INVOKE_CONTRACT_CONFIG_ERROR", str(exc), status.HTTP_400_BAD_REQUEST)
    except ExecutionRuntimeError as exc:
        _error("AGENT_INVOKE_CONTRACT_RUNTIME_ERROR", str(exc), status.HTTP_502_BAD_GATEWAY)

    data = AgentInvokeContractData(
        agent_id=agent_id,
        endpoint=str(result["endpoint"]),
        valid=bool(result["valid"]),
        issues=[str(x) for x in result["issues"]],
        status_code=int(result["status_code"]),
        latency_ms=float(result["latency_ms"]),
        content_type=str(result["content_type"]),
        response_preview=str(result["response_preview"]),
        request_hash=str(result["request_hash"]),
        response_hash=str(result["response_hash"]),
        response_key_used=result.get("response_key_used"),
        source_key_used=result.get("source_key_used"),
        extracted_response=str(result["extracted_response"]),
        extracted_sources=result.get("extracted_sources"),
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/latest", response_model=AgentLatestResponse)
def get_agent_latest(
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_latest")  # type: ignore[index]

            cur.execute(
                """
                with latest as (
                  select
                    er.id,
                    er.name,
                    er.type::text as type,
                    er.status::text as status,
                    er.created_at,
                    er.completed_at
                  from public.eval_runs er
                  where er.agent_id = %s
                  order by er.created_at desc
                  limit 1
                )
                select
                  l.id,
                  l.name,
                  l.type,
                  l.status,
                  l.created_at,
                  l.completed_at,
                  count(r.id) as total_results,
                  count(*) filter (where r.answer_correct = 'yes') as answer_yes_count,
                  count(*) filter (where r.answer_correct = 'partially') as answer_partially_count,
                  count(*) filter (where r.answer_correct = 'no') as answer_no_count,
                  count(*) filter (where r.source_correct = 'yes') as source_yes_count,
                  count(*) filter (where r.source_correct = 'partially') as source_partially_count,
                  count(*) filter (where r.source_correct = 'no') as source_no_count,
                  count(*) filter (where r.response_quality = 'good') as quality_good_count,
                  count(*) filter (where r.response_quality = 'average') as quality_average_count,
                  count(*) filter (where r.response_quality = 'not_good') as quality_not_good_count
                from latest l
                left join public.eval_results r on r.eval_run_id = l.id
                group by l.id, l.name, l.type, l.status, l.created_at, l.completed_at
                """,
                (str(agent_id),),
            )
            row = cur.fetchone()

    if not row:
        return {"ok": True, "data": {"agent_id": str(agent_id), "latest_run": None}}

    total = int(row[6])  # type: ignore[index]

    def rate(n: int) -> float:
        if total == 0:
            return 0.0
        return n / total

    latest = AgentLatestRunSummary(
        run_id=row[0],  # type: ignore[index]
        run_name=row[1],  # type: ignore[index]
        run_type=row[2],  # type: ignore[index]
        run_status=row[3],  # type: ignore[index]
        created_at=row[4],  # type: ignore[index]
        completed_at=row[5],  # type: ignore[index]
        total_results=total,
        answer_yes_count=int(row[7] or 0),  # type: ignore[index]
        answer_partially_count=int(row[8] or 0),  # type: ignore[index]
        answer_no_count=int(row[9] or 0),  # type: ignore[index]
        source_yes_count=int(row[10] or 0),  # type: ignore[index]
        source_partially_count=int(row[11] or 0),  # type: ignore[index]
        source_no_count=int(row[12] or 0),  # type: ignore[index]
        quality_good_count=int(row[13] or 0),  # type: ignore[index]
        quality_average_count=int(row[14] or 0),  # type: ignore[index]
        quality_not_good_count=int(row[15] or 0),  # type: ignore[index]
        answer_yes_rate=rate(int(row[7] or 0)),  # type: ignore[index]
        source_yes_rate=rate(int(row[10] or 0)),  # type: ignore[index]
        quality_good_rate=rate(int(row[13] or 0)),  # type: ignore[index]
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "latest_run": latest.model_dump(mode="json")}}


@app.get("/api/agents/{agent_id}/score-trend", response_model=AgentScoreTrendResponse)
def get_agent_score_trend(
    agent_id: UUID = Path(...),
    window_days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=30, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_score_trend")  # type: ignore[index]

            cur.execute(
                """
                select
                    er.id,
                    er.name,
                    er.type::text,
                    er.status::text,
                    er.created_at,
                    er.completed_at,
                    count(r.id) as total_results,
                    count(*) filter (where r.answer_correct = 'yes') as answer_yes_count,
                    count(*) filter (where r.source_correct = 'yes') as source_yes_count,
                    count(*) filter (where r.response_quality = 'good') as quality_good_count
                from public.eval_runs er
                left join public.eval_results r on r.eval_run_id = er.id
                where er.agent_id = %s
                  and er.created_at >= now() - (%s::text || ' days')::interval
                group by er.id
                order by er.created_at desc
                limit %s
                offset %s
                """,
                (str(agent_id), window_days, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                """
                select count(1)
                from public.eval_runs er
                where er.agent_id = %s
                  and er.created_at >= now() - (%s::text || ' days')::interval
                """,
                (str(agent_id), window_days),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items: List[Dict[str, Any]] = []
    for row in rows:
        total_results = int(row[6] or 0)  # type: ignore[index]
        answer_yes_count = int(row[7] or 0)  # type: ignore[index]
        source_yes_count = int(row[8] or 0)  # type: ignore[index]
        quality_good_count = int(row[9] or 0)  # type: ignore[index]

        def _rate(n: int) -> float:
            if total_results == 0:
                return 0.0
            return n / total_results

        items.append(
            AgentScoreTrendPoint(
                run_id=row[0],  # type: ignore[index]
                run_name=row[1],  # type: ignore[index]
                run_type=row[2],  # type: ignore[index]
                run_status=row[3],  # type: ignore[index]
                created_at=row[4],  # type: ignore[index]
                completed_at=row[5],  # type: ignore[index]
                total_results=total_results,
                answer_yes_rate=_rate(answer_yes_count),
                source_yes_rate=_rate(source_yes_count),
                quality_good_rate=_rate(quality_good_count),
            ).model_dump(mode="json")
        )

    return {
        "ok": True,
        "data": {
            "agent_id": str(agent_id),
            "window_days": window_days,
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/agents/{agent_id}/health", response_model=AgentHealthResponse)
def get_agent_health(
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    launch = _evaluate_launch_gate(agent_id)
    _assert_org_access(api_key_ctx, str(launch["org_id"]), context="agent_health")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    er.id,
                    er.completed_at,
                    count(r.id) as total_results,
                    count(*) filter (where r.answer_correct = 'yes') as answer_yes_count,
                    count(*) filter (where r.source_correct = 'yes') as source_yes_count,
                    count(*) filter (where r.response_quality = 'good') as quality_good_count
                from public.eval_runs er
                left join public.eval_results r on r.eval_run_id = er.id
                where er.agent_id = %s
                  and er.status = 'completed'::public.run_status
                group by er.id
                order by er.completed_at desc nulls last
                limit 1
                """,
                (str(agent_id),),
            )
            latest_completed = cur.fetchone()

            cur.execute(
                """
                select count(1)
                from public.issue_patterns
                where agent_id = %s
                  and status not in ('resolved'::public.issue_status, 'wont_fix'::public.issue_status)
                """,
                (str(agent_id),),
            )
            active_issue_count = int(cur.fetchone()[0])  # type: ignore[index]

            cur.execute(
                """
                select decision, decision_date
                from public.launch_readiness
                where agent_id = %s
                limit 1
                """,
                (str(agent_id),),
            )
            readiness_row = cur.fetchone()

    answer_yes_rate: Optional[float] = None
    source_yes_rate: Optional[float] = None
    quality_good_rate: Optional[float] = None
    latest_completed_run_id: Optional[UUID] = None
    latest_completed_at: Optional[datetime] = None

    if latest_completed:
        total_results = int(latest_completed[2] or 0)  # type: ignore[index]
        latest_completed_run_id = latest_completed[0]  # type: ignore[index]
        latest_completed_at = latest_completed[1]  # type: ignore[index]
        if total_results > 0:
            answer_yes_rate = int(latest_completed[3] or 0) / total_results  # type: ignore[index]
            source_yes_rate = int(latest_completed[4] or 0) / total_results  # type: ignore[index]
            quality_good_rate = int(latest_completed[5] or 0) / total_results  # type: ignore[index]

    data = AgentHealthData(
        agent_id=agent_id,
        org_id=launch["org_id"],
        can_launch=bool(launch["can_launch"]),
        blockers=[str(x) for x in (launch.get("blockers") or [])],
        latest_run_id=launch["latest_run_id"],
        latest_run_status=launch["latest_run_status"],
        latest_completed_run_id=latest_completed_run_id,
        latest_completed_at=latest_completed_at,
        answer_yes_rate=answer_yes_rate,
        source_yes_rate=source_yes_rate,
        quality_good_rate=quality_good_rate,
        active_issue_count=active_issue_count,
        active_critical_issues=int(launch["active_critical_issues"]),
        open_slo_violations=int(launch["open_slo_violations"]),
        readiness_pending_items=int(launch["readiness_pending_items"]),
        readiness_decision=readiness_row[0] if readiness_row else None,  # type: ignore[index]
        readiness_decision_date=readiness_row[1] if readiness_row else None,  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/orgs/{org_id}/portfolio-health", response_model=PortfolioHealthResponse, tags=["Agents"])
def get_org_portfolio_health(
    org_id: UUID = Path(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(org_id), context="portfolio_health")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                with agents_page as (
                    select id, name, status::text as status
                    from public.agents
                    where org_id = %s
                    order by created_at desc
                    limit %s
                    offset %s
                ),
                latest_completed_run as (
                    select distinct on (er.agent_id)
                        er.agent_id,
                        er.id as run_id
                    from public.eval_runs er
                    where er.org_id = %s
                      and er.status = 'completed'::public.run_status
                    order by er.agent_id, er.completed_at desc nulls last
                ),
                run_scores as (
                    select
                        lcr.agent_id,
                        count(r.id) as total_results,
                        count(*) filter (where r.answer_correct = 'yes') as answer_yes_count,
                        count(*) filter (where r.source_correct = 'yes') as source_yes_count,
                        count(*) filter (where r.response_quality = 'good') as quality_good_count
                    from latest_completed_run lcr
                    left join public.eval_results r on r.eval_run_id = lcr.run_id
                    group by lcr.agent_id
                ),
                latest_run as (
                    select distinct on (er.agent_id)
                        er.agent_id,
                        er.status::text as latest_run_status
                    from public.eval_runs er
                    where er.org_id = %s
                    order by er.agent_id, er.created_at desc
                ),
                active_critical as (
                    select agent_id, count(1) as active_critical_issues
                    from public.issue_patterns
                    where org_id = %s
                      and priority = 'critical'::public.issue_priority
                      and status not in ('resolved'::public.issue_status, 'wont_fix'::public.issue_status)
                    group by agent_id
                ),
                open_slo as (
                    select agent_id, count(1) as open_slo_violations
                    from public.slo_violations
                    where org_id = %s
                      and status = 'open'::public.slo_violation_status
                    group by agent_id
                ),
                readiness_pending as (
                    select
                        lr.agent_id,
                        coalesce(sum(case when lower(coalesce(item->>'status', '')) = 'done' then 0 else 1 end), 0)::int as readiness_pending_items
                    from public.launch_readiness lr
                    left join lateral jsonb_array_elements(coalesce(lr.items, '[]'::jsonb)) item on true
                    where lr.org_id = %s
                    group by lr.agent_id
                )
                select
                    ap.id,
                    ap.name,
                    ap.status,
                    lr.latest_run_status,
                    rs.total_results,
                    rs.answer_yes_count,
                    rs.source_yes_count,
                    rs.quality_good_count,
                    coalesce(ac.active_critical_issues, 0) as active_critical_issues,
                    coalesce(os.open_slo_violations, 0) as open_slo_violations,
                    coalesce(rp.readiness_pending_items, 0) as readiness_pending_items
                from agents_page ap
                left join latest_run lr on lr.agent_id = ap.id
                left join run_scores rs on rs.agent_id = ap.id
                left join active_critical ac on ac.agent_id = ap.id
                left join open_slo os on os.agent_id = ap.id
                left join readiness_pending rp on rp.agent_id = ap.id
                order by ap.name asc
                """,
                (str(org_id), limit, offset, str(org_id), str(org_id), str(org_id), str(org_id), str(org_id)),
            )
            rows = cur.fetchall()

            cur.execute("select count(1) from public.agents where org_id = %s", (str(org_id),))
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items: List[Dict[str, Any]] = []
    answer_rates: List[float] = []
    source_rates: List[float] = []
    quality_rates: List[float] = []
    healthy_agents = 0

    for row in rows:
        total_results = int(row[4] or 0)  # type: ignore[index]
        answer_yes_rate: Optional[float] = None
        source_yes_rate: Optional[float] = None
        quality_good_rate: Optional[float] = None
        if total_results > 0:
            answer_yes_rate = int(row[5] or 0) / total_results  # type: ignore[index]
            source_yes_rate = int(row[6] or 0) / total_results  # type: ignore[index]
            quality_good_rate = int(row[7] or 0) / total_results  # type: ignore[index]
            answer_rates.append(answer_yes_rate)
            source_rates.append(source_yes_rate)
            quality_rates.append(quality_good_rate)

        active_critical_issues = int(row[8] or 0)  # type: ignore[index]
        open_slo_violations = int(row[9] or 0)  # type: ignore[index]
        readiness_pending_items = int(row[10] or 0)  # type: ignore[index]
        latest_run_status = row[3]  # type: ignore[index]
        can_launch = latest_run_status == "completed" and active_critical_issues == 0 and open_slo_violations == 0 and readiness_pending_items == 0
        if can_launch:
            healthy_agents += 1

        items.append(
            PortfolioHealthAgentItem(
                agent_id=row[0],  # type: ignore[index]
                name=row[1],  # type: ignore[index]
                status=row[2],  # type: ignore[index]
                can_launch=can_launch,
                latest_run_status=latest_run_status,
                answer_yes_rate=answer_yes_rate,
                source_yes_rate=source_yes_rate,
                quality_good_rate=quality_good_rate,
                active_critical_issues=active_critical_issues,
                open_slo_violations=open_slo_violations,
                readiness_pending_items=readiness_pending_items,
            ).model_dump(mode="json")
        )

    def _avg(xs: List[float]) -> Optional[float]:
        if not xs:
            return None
        return sum(xs) / len(xs)

    return {
        "ok": True,
        "data": {
            "org_id": str(org_id),
            "total_agents": total_count,
            "healthy_agents": healthy_agents,
            "blocked_agents": max(total_count - healthy_agents, 0),
            "avg_answer_yes_rate": _avg(answer_rates),
            "avg_source_yes_rate": _avg(source_rates),
            "avg_quality_good_rate": _avg(quality_rates),
            "items": items,
            "count": len(items),
            "limit": limit,
            "offset": offset,
        },
    }


@app.post("/api/agents/{agent_id}/run-registry", status_code=status.HTTP_201_CREATED, response_model=RunRegistryItemResponse)
def upsert_agent_run_registry(
    payload: RunRegistryUpsertRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            org_id = str(agent_row[1])  # type: ignore[index]
            _assert_org_access(api_key_ctx, org_id, context="agent_run_registry_write")

            cur.execute("select id, org_id, agent_id from public.eval_runs where id = %s", (str(payload.run_id),))
            run_row = cur.fetchone()
            if not run_row:
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {payload.run_id} was not found.", status.HTTP_404_NOT_FOUND)
            if str(run_row[1]) != org_id or str(run_row[2]) != str(agent_id):  # type: ignore[index]
                _error(
                    "RUN_REGISTRY_MISMATCH",
                    "run_id must belong to the same org and agent.",
                    status.HTTP_400_BAD_REQUEST,
                )

            if payload.is_active:
                cur.execute(
                    """
                    update public.run_registry
                    set is_active = false
                    where agent_id = %s and kind = %s and is_active = true
                    """,
                    (str(agent_id), payload.kind),
                )

            cur.execute(
                """
                insert into public.run_registry (
                    org_id, agent_id, kind, name, run_id, is_active, notes, metadata
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                on conflict (agent_id, kind, name) do update
                set
                    run_id = excluded.run_id,
                    is_active = excluded.is_active,
                    notes = excluded.notes,
                    metadata = excluded.metadata,
                    updated_at = now()
                returning id, org_id, agent_id, kind, name, run_id, is_active, notes, metadata, created_at, updated_at
                """,
                (
                    org_id,
                    str(agent_id),
                    payload.kind,
                    payload.name.strip(),
                    str(payload.run_id),
                    bool(payload.is_active),
                    payload.notes,
                    json.dumps(payload.metadata),
                ),
            )
            row = cur.fetchone()

    item = RunRegistryItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        kind=row[3],  # type: ignore[index]
        name=row[4],  # type: ignore[index]
        run_id=row[5],  # type: ignore[index]
        is_active=bool(row[6]),  # type: ignore[index]
        notes=row[7],  # type: ignore[index]
        metadata=row[8] or {},  # type: ignore[index]
        created_at=row[9],  # type: ignore[index]
        updated_at=row[10],  # type: ignore[index]
    )
    return {"ok": True, "data": item.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/run-registry", response_model=RunRegistryListResponse)
def list_agent_run_registry(
    agent_id: UUID = Path(...),
    kind: Optional[RunRefKind] = Query(default=None),
    include_inactive: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_run_registry_read")  # type: ignore[index]

            where = ["agent_id = %s"]
            params: List[Any] = [str(agent_id)]
            if kind is not None:
                where.append("kind = %s")
                params.append(kind)
            if not include_inactive:
                where.append("is_active = true")

            where_sql = " and ".join(where)
            cur.execute(
                f"""
                select id, org_id, agent_id, kind, name, run_id, is_active, notes, metadata, created_at, updated_at
                from public.run_registry
                where {where_sql}
                order by updated_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

    items = [
        RunRegistryItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            kind=r[3],
            name=r[4],
            run_id=r[5],
            is_active=bool(r[6]),
            notes=r[7],
            metadata=r[8] or {},
            created_at=r[9],
            updated_at=r[10],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"agent_id": str(agent_id), "items": items, "count": len(items), "limit": limit, "offset": offset}}


@app.get("/api/agents/{agent_id}/run-registry/resolve", response_model=RunRegistryResolveResponse)
def resolve_agent_run_registry(
    agent_id: UUID = Path(...),
    kind: RunRefKind = Query(...),
    name: Optional[str] = Query(default=None),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_run_registry_resolve")  # type: ignore[index]

            if name and name.strip():
                cur.execute(
                    """
                    select id, org_id, agent_id, kind, name, run_id, is_active, notes, metadata, created_at, updated_at
                    from public.run_registry
                    where agent_id = %s and kind = %s and name = %s
                    limit 1
                    """,
                    (str(agent_id), kind, name.strip()),
                )
            else:
                cur.execute(
                    """
                    select id, org_id, agent_id, kind, name, run_id, is_active, notes, metadata, created_at, updated_at
                    from public.run_registry
                    where agent_id = %s and kind = %s and is_active = true
                    order by updated_at desc
                    limit 1
                    """,
                    (str(agent_id), kind),
                )
            row = cur.fetchone()

    if not row:
        return {"ok": True, "data": {"agent_id": str(agent_id), "kind": kind, "ref": None}}

    item = RunRegistryItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        kind=row[3],  # type: ignore[index]
        name=row[4],  # type: ignore[index]
        run_id=row[5],  # type: ignore[index]
        is_active=bool(row[6]),  # type: ignore[index]
        notes=row[7],  # type: ignore[index]
        metadata=row[8] or {},  # type: ignore[index]
        created_at=row[9],  # type: ignore[index]
        updated_at=row[10],  # type: ignore[index]
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "kind": kind, "ref": item.model_dump(mode="json")}}


@app.post("/api/agents/{agent_id}/run-registry/promote-candidate", response_model=RunRegistryPromoteResponse)
def promote_candidate_run_to_baseline(
    payload: RunRegistryPromoteRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            org_id = str(agent_row[1])  # type: ignore[index]
            _assert_org_access(api_key_ctx, org_id, context="agent_run_registry_promote")

            resolved_candidate_run_id: Optional[UUID] = payload.candidate_run_id
            if resolved_candidate_run_id is None:
                ref = (payload.candidate_ref or "active").strip()
                try:
                    resolved_candidate_run_id = _resolve_eval_compare_ref(
                        cur=cur,
                        agent_id=agent_id,
                        kind="candidate",
                        ref=ref,
                    )
                except HTTPException as exc:
                    if isinstance(exc.detail, dict) and (exc.detail.get("error") or {}).get("code") == "EVAL_RUN_COMPARE_REFERENCE_NOT_FOUND":
                        _error(
                            "RUN_REGISTRY_CANDIDATE_NOT_FOUND",
                            f"Could not resolve candidate ref '{ref}' for agent {agent_id}.",
                            status.HTTP_404_NOT_FOUND,
                        )
                    raise

            cur.execute("select id, org_id, agent_id from public.eval_runs where id = %s", (str(resolved_candidate_run_id),))
            run_row = cur.fetchone()
            if not run_row:
                _error(
                    "EVAL_RUN_NOT_FOUND",
                    f"Eval run {resolved_candidate_run_id} was not found.",
                    status.HTTP_404_NOT_FOUND,
                )
            if str(run_row[1]) != org_id or str(run_row[2]) != str(agent_id):  # type: ignore[index]
                _error(
                    "RUN_REGISTRY_MISMATCH",
                    "candidate run must belong to the same org and agent.",
                    status.HTTP_400_BAD_REQUEST,
                )

            baseline_for_gate: Optional[UUID] = payload.baseline_run_id
            if baseline_for_gate is None:
                try:
                    baseline_for_gate = _resolve_eval_compare_ref(
                        cur=cur,
                        agent_id=agent_id,
                        kind="baseline",
                        ref="active",
                    )
                except HTTPException:
                    baseline_for_gate = None

            if baseline_for_gate is not None:
                cur.execute("select id, org_id, agent_id from public.eval_runs where id = %s", (str(baseline_for_gate),))
                baseline_row = cur.fetchone()
                if not baseline_row:
                    _error(
                        "EVAL_RUN_NOT_FOUND",
                        f"Eval run {baseline_for_gate} was not found.",
                        status.HTTP_404_NOT_FOUND,
                    )
                if str(baseline_row[1]) != org_id or str(baseline_row[2]) != str(agent_id):  # type: ignore[index]
                    _error(
                        "RUN_REGISTRY_MISMATCH",
                        "baseline run must belong to the same org and agent.",
                        status.HTTP_400_BAD_REQUEST,
                    )

            compare_row = None
            if payload.require_clean_compare:
                if baseline_for_gate is None:
                    _error(
                        "RUN_REGISTRY_PROMOTION_BLOCKED",
                        "Promotion requires a baseline run (active baseline ref or baseline_run_id).",
                        status.HTTP_409_CONFLICT,
                    )
                if str(baseline_for_gate) == str(resolved_candidate_run_id):
                    _error(
                        "RUN_REGISTRY_PROMOTION_BLOCKED",
                        "Promotion requires different baseline and candidate runs.",
                        status.HTTP_409_CONFLICT,
                    )
                cur.execute(
                    """
                    select id, created_at
                    from public.activity_events
                    where agent_id = %s
                      and event_type = 'regression_compare'
                      and metadata->>'baseline_run_id' = %s
                      and metadata->>'candidate_run_id' = %s
                      and (metadata->>'regression_count') ~ '^[0-9]+$'
                      and (metadata->>'regression_count')::int = 0
                      and created_at >= (now() - (%s || ' minutes')::interval)
                    order by created_at desc
                    limit 1
                    """,
                    (
                        str(agent_id),
                        str(baseline_for_gate),
                        str(resolved_candidate_run_id),
                        int(payload.clean_compare_window_minutes),
                    ),
                )
                compare_row = cur.fetchone()
                if not compare_row:
                    _error(
                        "RUN_REGISTRY_PROMOTION_BLOCKED",
                        "No recent clean compare found for the requested baseline/candidate pair.",
                        status.HTTP_409_CONFLICT,
                    )

            baseline_name = payload.baseline_name.strip()
            cur.execute(
                """
                update public.run_registry
                set is_active = false
                where agent_id = %s and kind = 'baseline' and is_active = true
                """,
                (str(agent_id),),
            )

            promoted_metadata = dict(payload.metadata or {})
            promoted_metadata["promoted_from_candidate_run_id"] = str(resolved_candidate_run_id)
            promoted_metadata["promoted_at"] = datetime.now(timezone.utc).isoformat()
            if baseline_for_gate is not None:
                promoted_metadata["baseline_run_id"] = str(baseline_for_gate)
            if compare_row is not None:
                promoted_metadata["clean_compare_event_id"] = str(compare_row[0])
                promoted_metadata["clean_compare_at"] = compare_row[1].isoformat() if hasattr(compare_row[1], "isoformat") else str(compare_row[1])

            cur.execute(
                """
                insert into public.run_registry (
                    org_id, agent_id, kind, name, run_id, is_active, notes, metadata
                )
                values (%s, %s, 'baseline', %s, %s, true, %s, %s::jsonb)
                on conflict (agent_id, kind, name) do update
                set
                    run_id = excluded.run_id,
                    is_active = true,
                    notes = excluded.notes,
                    metadata = excluded.metadata,
                    updated_at = now()
                returning id, org_id, agent_id, kind, name, run_id, is_active, notes, metadata, created_at, updated_at
                """,
                (
                    org_id,
                    str(agent_id),
                    baseline_name,
                    str(resolved_candidate_run_id),
                    payload.notes,
                    json.dumps(promoted_metadata),
                ),
            )
            row = cur.fetchone()

    baseline_ref = RunRegistryItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        kind=row[3],  # type: ignore[index]
        name=row[4],  # type: ignore[index]
        run_id=row[5],  # type: ignore[index]
        is_active=bool(row[6]),  # type: ignore[index]
        notes=row[7],  # type: ignore[index]
        metadata=row[8] or {},  # type: ignore[index]
        created_at=row[9],  # type: ignore[index]
        updated_at=row[10],  # type: ignore[index]
    )

    _record_activity_event(
        org_id=UUID(org_id),
        agent_id=agent_id,
        event_type="run_registry_promoted",
        title="Candidate promoted to baseline",
        details=f"candidate_run_id={str(resolved_candidate_run_id)[:8]}, baseline_name={baseline_name}",
        severity="info",
        metadata={
            "candidate_run_id": str(resolved_candidate_run_id),
            "baseline_name": baseline_name,
            "baseline_run_id": str(baseline_ref.run_id),
        },
    )

    data = RunRegistryPromoteData(
        agent_id=agent_id,
        candidate_run_id=resolved_candidate_run_id,
        baseline_ref=baseline_ref,
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/slo-policy", response_model=AgentSloPolicyResponse)
def get_agent_slo_policy(
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_slo_policy_read")  # type: ignore[index]

            cur.execute(
                """
                select
                    id, org_id, agent_id, min_answer_yes_rate, min_source_yes_rate, min_quality_good_rate,
                    max_run_duration_ms, max_regression_count,
                    require_calibration_gate, min_calibration_overall_agreement, max_calibration_age_days,
                    require_golden_set_quality_gate, min_verified_case_ratio, min_active_case_count,
                    created_at, updated_at
                from public.slo_policies
                where agent_id = %s
                """,
                (str(agent_id),),
            )
            row = cur.fetchone()

    if not row:
        return {"ok": True, "data": {"agent_id": str(agent_id), "slo_policy": None}}

    data = SloPolicyData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        min_answer_yes_rate=float(row[3]) if row[3] is not None else None,  # type: ignore[index]
        min_source_yes_rate=float(row[4]) if row[4] is not None else None,  # type: ignore[index]
        min_quality_good_rate=float(row[5]) if row[5] is not None else None,  # type: ignore[index]
        max_run_duration_ms=int(row[6]) if row[6] is not None else None,  # type: ignore[index]
        max_regression_count=int(row[7]) if row[7] is not None else None,  # type: ignore[index]
        require_calibration_gate=bool(row[8]),  # type: ignore[index]
        min_calibration_overall_agreement=float(row[9]),  # type: ignore[index]
        max_calibration_age_days=int(row[10]),  # type: ignore[index]
        require_golden_set_quality_gate=bool(row[11]),  # type: ignore[index]
        min_verified_case_ratio=float(row[12]),  # type: ignore[index]
        min_active_case_count=int(row[13]),  # type: ignore[index]
        created_at=row[14],  # type: ignore[index]
        updated_at=row[15],  # type: ignore[index]
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "slo_policy": data.model_dump(mode="json")}}


@app.post("/api/agents/{agent_id}/slo-policy", status_code=status.HTTP_201_CREATED, response_model=AgentSloPolicyResponse)
def upsert_agent_slo_policy(
    payload: SloPolicyUpsertRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_slo_policy_write")  # type: ignore[index]
                org_id = agent_row[1]  # type: ignore[index]

                cur.execute(
                    """
                    insert into public.slo_policies (
                        org_id, agent_id, min_answer_yes_rate, min_source_yes_rate, min_quality_good_rate,
                        max_run_duration_ms, max_regression_count,
                        require_calibration_gate, min_calibration_overall_agreement, max_calibration_age_days,
                        require_golden_set_quality_gate, min_verified_case_ratio, min_active_case_count
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (agent_id) do update
                    set
                        min_answer_yes_rate = excluded.min_answer_yes_rate,
                        min_source_yes_rate = excluded.min_source_yes_rate,
                        min_quality_good_rate = excluded.min_quality_good_rate,
                        max_run_duration_ms = excluded.max_run_duration_ms,
                        max_regression_count = excluded.max_regression_count,
                        require_calibration_gate = excluded.require_calibration_gate,
                        min_calibration_overall_agreement = excluded.min_calibration_overall_agreement,
                        max_calibration_age_days = excluded.max_calibration_age_days,
                        require_golden_set_quality_gate = excluded.require_golden_set_quality_gate,
                        min_verified_case_ratio = excluded.min_verified_case_ratio,
                        min_active_case_count = excluded.min_active_case_count,
                        updated_at = now()
                    returning
                        id, org_id, agent_id, min_answer_yes_rate, min_source_yes_rate, min_quality_good_rate,
                        max_run_duration_ms, max_regression_count,
                        require_calibration_gate, min_calibration_overall_agreement, max_calibration_age_days,
                        require_golden_set_quality_gate, min_verified_case_ratio, min_active_case_count,
                        created_at, updated_at
                    """,
                    (
                        str(org_id),
                        str(agent_id),
                        payload.min_answer_yes_rate,
                        payload.min_source_yes_rate,
                        payload.min_quality_good_rate,
                        payload.max_run_duration_ms,
                        payload.max_regression_count,
                        payload.require_calibration_gate,
                        payload.min_calibration_overall_agreement,
                        payload.max_calibration_age_days,
                        payload.require_golden_set_quality_gate,
                        payload.min_verified_case_ratio,
                        payload.min_active_case_count,
                    ),
                )
                row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("SLO_POLICY_UPSERT_FAILED", f"Failed to upsert SLO policy: {exc}", status.HTTP_400_BAD_REQUEST)

    data = SloPolicyData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        min_answer_yes_rate=float(row[3]) if row[3] is not None else None,  # type: ignore[index]
        min_source_yes_rate=float(row[4]) if row[4] is not None else None,  # type: ignore[index]
        min_quality_good_rate=float(row[5]) if row[5] is not None else None,  # type: ignore[index]
        max_run_duration_ms=int(row[6]) if row[6] is not None else None,  # type: ignore[index]
        max_regression_count=int(row[7]) if row[7] is not None else None,  # type: ignore[index]
        require_calibration_gate=bool(row[8]),  # type: ignore[index]
        min_calibration_overall_agreement=float(row[9]),  # type: ignore[index]
        max_calibration_age_days=int(row[10]),  # type: ignore[index]
        require_golden_set_quality_gate=bool(row[11]),  # type: ignore[index]
        min_verified_case_ratio=float(row[12]),  # type: ignore[index]
        min_active_case_count=int(row[13]),  # type: ignore[index]
        created_at=row[14],  # type: ignore[index]
        updated_at=row[15],  # type: ignore[index]
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "slo_policy": data.model_dump(mode="json")}}


@app.get("/api/agents/{agent_id}/slo-status", response_model=AgentSloStatusResponse)
def get_agent_slo_status(
    agent_id: UUID = Path(...),
    limit_violations: int = Query(default=10, ge=1, le=100),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_slo_status_read")  # type: ignore[index]

            cur.execute(
                """
                select
                    id, org_id, agent_id, policy_id, source::text, source_ref_id,
                    metric, actual_value, expected_value, comparator, details, created_at
                from public.slo_violations
                where agent_id = %s
                order by created_at desc
                limit %s
                """,
                (str(agent_id), limit_violations),
            )
            rows = cur.fetchall()

    items = [
        SloViolationItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            policy_id=r[3],
            source=r[4],
            source_ref_id=r[5],
            metric=r[6],
            actual_value=float(r[7]),
            expected_value=float(r[8]),
            comparator=r[9],
            details=r[10] or {},
            created_at=r[11],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {
        "ok": True,
        "data": {
            "agent_id": str(agent_id),
            "slo_status": "violated" if items else "healthy",
            "open_violation_count": len(items),
            "recent_violations": items,
        },
    }


@app.patch("/api/agents/{agent_id}/slo-violations/{violation_id}/resolve", response_model=SloViolationResolveResponse)
def resolve_slo_violation(
    agent_id: UUID = Path(...),
    violation_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_slo_violation_resolve")  # type: ignore[index]
            cur.execute(
                """
                update public.slo_violations
                set status = 'resolved'::public.slo_violation_status,
                    resolved_at = now()
                where id = %s and agent_id = %s
                returning id, org_id, agent_id, metric
                """,
                (str(violation_id), str(agent_id)),
            )
            row = cur.fetchone()
            if not row:
                _error("SLO_VIOLATION_NOT_FOUND", f"SLO violation {violation_id} not found.", status.HTTP_404_NOT_FOUND)

    _record_activity_event(
        org_id=UUID(str(row[1])),  # type: ignore[index]
        agent_id=UUID(str(row[2])),  # type: ignore[index]
        event_type="slo_violation_resolved",
        title="SLO violation resolved",
        details=f"violation={str(row[0])[:8]}, metric={row[3]}",
        severity="info",
        metadata={"violation_id": str(row[0]), "metric": row[3]},
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "violation_id": str(row[0]), "status": "resolved"}}


def _normalize_token(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text.lower().replace("-", "_").replace(" ", "_")


def _golden_set_case_from_row(row: Any) -> GoldenSetCaseItem:
    return GoldenSetCaseItem(
        id=row[0],
        golden_set_id=row[1],
        input=row[2],
        expected_output=row[3],
        acceptable_sources=row[4],
        evaluation_mode=row[5],
        evaluation_criteria=row[6],
        difficulty=row[7],
        capability=row[8],
        scenario_type=row[9],
        domain=row[10],
        verification_status=row[11],
        verified_by=row[12],
        verified_date=row[13].isoformat() if row[13] is not None and hasattr(row[13], "isoformat") else row[13],
        version=int(row[14] or 1),
        is_active=bool(row[15]),
        superseded_by=row[16],
        last_reviewed_at=row[17],
        review_notes=row[18],
        created_at=row[19],
    )


def _normalize_case_row(row: Dict[str, Any], row_number: int) -> GoldenSetCaseUpload:
    alias_map = {
        "input": ["input", "query", "prompt", "question"],
        "expected_output": ["expected_output", "expected", "expected_answer", "golden_answer"],
        "acceptable_sources": ["acceptable_sources", "sources", "source", "citations", "references"],
        "evaluation_mode": ["evaluation_mode", "mode"],
        "evaluation_criteria": ["evaluation_criteria", "criteria", "rubric"],
        "difficulty": ["difficulty", "difficulty_level"],
        "capability": ["capability", "capability_type"],
        "scenario_type": ["scenario_type", "scenario"],
        "domain": ["domain"],
        "verification_status": ["verification_status", "verification"],
        "verified_by": ["verified_by"],
        "verified_date": ["verified_date"],
    }

    normalized: Dict[str, Any] = {}
    for target, aliases in alias_map.items():
        for alias in aliases:
            if alias in row and row[alias] not in (None, ""):
                normalized[target] = row[alias]
                break

    normalized["evaluation_mode"] = _normalize_token(normalized.get("evaluation_mode")) or "answer"
    normalized["difficulty"] = _normalize_token(normalized.get("difficulty")) or "medium"
    normalized["capability"] = _normalize_token(normalized.get("capability")) or "retrieval"
    normalized["scenario_type"] = _normalize_token(normalized.get("scenario_type")) or "straightforward"
    normalized["verification_status"] = _normalize_token(normalized.get("verification_status")) or "unverified"

    criteria = normalized.get("evaluation_criteria")
    if isinstance(criteria, str):
        text = criteria.strip()
        if text:
            try:
                normalized["evaluation_criteria"] = json.loads(text)
            except Exception as exc:
                raise ValueError(f"row {row_number}: evaluation_criteria is not valid JSON: {exc}") from exc
        else:
            normalized["evaluation_criteria"] = None

    try:
        return GoldenSetCaseUpload.model_validate(normalized)
    except ValidationError as exc:
        raise ValueError(f"row {row_number}: {exc.errors()}") from exc


def _read_rows_from_upload(filename: str, raw: bytes) -> tuple[str, List[Dict[str, Any]]]:
    lower = filename.lower()
    if lower.endswith(".jsonl"):
        rows: List[Dict[str, Any]] = []
        for idx, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
            if not line.strip():
                continue
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                raise ValueError(f"line {idx}: JSONL record must be an object")
            rows.append({str(k).strip().lower(): v for k, v in parsed.items()})
        return "jsonl", rows

    if lower.endswith(".csv"):
        import pandas as pd

        df = pd.read_csv(io.BytesIO(raw))
        rows = [
            {str(k).strip().lower(): (None if pd.isna(v) else v) for k, v in record.items()}
            for record in df.to_dict(orient="records")
        ]
        return "csv", rows

    if lower.endswith(".xlsx") or lower.endswith(".xls"):
        import pandas as pd

        df = pd.read_excel(io.BytesIO(raw))
        rows = [
            {str(k).strip().lower(): (None if pd.isna(v) else v) for k, v in record.items()}
            for record in df.to_dict(orient="records")
        ]
        return "xlsx", rows

    raise ValueError("Unsupported file type. Use .csv, .jsonl, or .xlsx.")


def _persist_golden_set_payload(payload: GoldenSetUploadRequest) -> Dict[str, Any]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(payload.agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {payload.agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                if str(agent_row[1]) != str(payload.org_id):  # type: ignore[index]
                    _error("GOLDEN_SET_ORG_MISMATCH", "agent_id does not belong to org_id.", status.HTTP_400_BAD_REQUEST)
                cur.execute(
                    """
                    insert into public.golden_sets (
                        org_id, agent_id, name, description, generation_method, source_files
                    )
                    values (%s, %s, %s, %s, %s::public.generation_method, %s::jsonb)
                    returning id, created_at
                    """,
                    (
                        str(payload.org_id),
                        str(payload.agent_id),
                        payload.name,
                        payload.description,
                        payload.generation_method,
                        json.dumps(payload.source_files),
                    ),
                )
                gs_row = cur.fetchone()
                golden_set_id = gs_row[0]  # type: ignore[index]
                created_at = gs_row[1]  # type: ignore[index]

                case_ids: List[str] = []
                for case in payload.cases:
                    cur.execute(
                        """
                        insert into public.golden_set_cases (
                            golden_set_id,
                            input,
                            expected_output,
                            acceptable_sources,
                            evaluation_mode,
                            evaluation_criteria,
                            difficulty,
                            capability,
                            scenario_type,
                            domain,
                            verification_status,
                            verified_by,
                            verified_date
                        )
                        values (
                            %s,
                            %s,
                            %s,
                            %s,
                            %s::public.eval_mode,
                            %s::jsonb,
                            %s::public.difficulty_level,
                            %s::public.capability_type,
                            %s::public.scenario_type,
                            %s,
                            %s::public.verification_status,
                            %s,
                            %s
                        )
                        returning id
                        """,
                        (
                            str(golden_set_id),
                            case.input,
                            case.expected_output,
                            case.acceptable_sources,
                            case.evaluation_mode,
                            json.dumps(case.evaluation_criteria) if case.evaluation_criteria is not None else None,
                            case.difficulty,
                            case.capability,
                            case.scenario_type,
                            case.domain,
                            case.verification_status,
                            str(case.verified_by) if case.verified_by else None,
                            case.verified_date,
                        ),
                    )
                    case_ids.append(str(cur.fetchone()[0]))  # type: ignore[index]
        return {
            "golden_set_id": str(golden_set_id),
            "name": payload.name,
            "case_count": len(case_ids),
            "case_ids": case_ids,
            "created_at": created_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as exc:
        _error("GOLDEN_SET_UPLOAD_FAILED", f"Failed to upload golden set: {exc}", status.HTTP_400_BAD_REQUEST)
    return {}


@app.post("/api/golden-sets/upload", status_code=status.HTTP_201_CREATED, response_model=GoldenSetUploadResponse)
def upload_golden_set(
    payload: GoldenSetUploadRequest = Body(
        ...,
        examples=[
            {
                "name": "upload-golden-set",
                "summary": "Upload canonical JSON golden set",
                "value": {
                    "org_id": "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb",
                    "agent_id": "e3660b25-47cf-47f3-ab53-c080fb7ffdcc",
                    "name": "Acme Retrieval GS v1",
                    "description": "Core retrieval smoke set",
                    "generation_method": "manual",
                    "source_files": ["acme-kb-v1.pdf"],
                    "cases": [
                        {
                            "input": "What is Acme remote policy?",
                            "expected_output": "Acme uses a hybrid policy with three in-office days.",
                            "acceptable_sources": "HR Policy 2026",
                            "evaluation_mode": "answer",
                            "difficulty": "easy",
                            "capability": "retrieval",
                            "scenario_type": "straightforward",
                            "domain": "hr",
                            "verification_status": "unverified",
                        }
                    ],
                },
            }
        ],
    ),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="golden_set_upload")
    result = _persist_golden_set_payload(payload)
    return {"ok": True, "data": result}


@app.post("/api/golden-sets/upload-file", status_code=status.HTTP_201_CREATED, response_model=GoldenSetUploadResponse)
def upload_golden_set_file(
    payload: GoldenSetFileUploadRequest,
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    _assert_org_access(api_key_ctx, str(payload.org_id), context="golden_set_upload_file")
    if not payload.filename:
        _error("GOLDEN_SET_FILE_INVALID", "Uploaded file is missing a filename.", status.HTTP_400_BAD_REQUEST)

    try:
        raw = base64.b64decode(payload.file_content_base64, validate=True)
    except Exception as exc:
        _error("GOLDEN_SET_FILE_INVALID", f"file_content_base64 is invalid: {exc}", status.HTTP_400_BAD_REQUEST)
    if not raw:
        _error("GOLDEN_SET_FILE_INVALID", "Uploaded file is empty.", status.HTTP_400_BAD_REQUEST)

    try:
        input_format, rows = _read_rows_from_upload(payload.filename, raw)
    except Exception as exc:
        _error("GOLDEN_SET_FILE_PARSE_FAILED", f"Failed to parse uploaded file: {exc}", status.HTTP_400_BAD_REQUEST)

    issues: List[GoldenSetUploadValidationIssue] = []
    accepted_cases: List[GoldenSetCaseUpload] = []
    for idx, row in enumerate(rows, start=1):
        try:
            accepted_cases.append(_normalize_case_row(row, idx))
        except Exception as exc:
            issues.append(GoldenSetUploadValidationIssue(row=idx, message=str(exc)))

    if not accepted_cases:
        detail = {
            "ok": False,
            "error": {
                "code": "GOLDEN_SET_FILE_VALIDATION_FAILED",
                "message": "No valid golden set rows found in uploaded file.",
                "details": [x.model_dump(mode="json") for x in issues[:100]],
            },
        }
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    normalized_payload = GoldenSetUploadRequest(
        org_id=payload.org_id,
        agent_id=payload.agent_id,
        name=payload.name,
        description=payload.description,
        generation_method=payload.generation_method,
        source_files=payload.source_files,
        cases=accepted_cases,
    )
    result = _persist_golden_set_payload(normalized_payload)
    result["validation_report"] = GoldenSetUploadValidationReport(
        input_format=input_format,
        total_rows=len(rows),
        accepted_rows=len(accepted_cases),
        rejected_rows=len(issues),
        issues=issues[:100],
    ).model_dump(mode="json")
    return {"ok": True, "data": result}


@app.get("/api/golden-sets/{golden_set_id}/cases", response_model=GoldenSetCaseListResponse)
def list_golden_set_cases(
    golden_set_id: UUID = Path(...),
    include_inactive: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.golden_sets where id = %s", (str(golden_set_id),))
            gs_row = cur.fetchone()
            if not gs_row:
                _error("GOLDEN_SET_NOT_FOUND", f"Golden set {golden_set_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(gs_row[1]), context="golden_set_cases_read")  # type: ignore[index]

            where = ["c.golden_set_id = %s"]
            params: List[Any] = [str(golden_set_id)]
            if not include_inactive:
                where.append("c.is_active = true")
            where_sql = " and ".join(where)

            cur.execute(
                f"""
                select
                    c.id,
                    c.golden_set_id,
                    c.input,
                    c.expected_output,
                    c.acceptable_sources,
                    c.evaluation_mode::text,
                    c.evaluation_criteria,
                    c.difficulty::text,
                    c.capability::text,
                    c.scenario_type::text,
                    c.domain,
                    c.verification_status::text,
                    c.verified_by,
                    c.verified_date,
                    c.version,
                    c.is_active,
                    c.superseded_by,
                    c.last_reviewed_at,
                    c.review_notes,
                    c.created_at
                from public.golden_set_cases c
                where {where_sql}
                order by c.version desc, c.created_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.golden_set_cases c
                where {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = [_golden_set_case_from_row(r).model_dump(mode="json") for r in rows]
    return {
        "ok": True,
        "data": {
            "golden_set_id": str(golden_set_id),
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
        },
    }


@app.patch("/api/golden-sets/{golden_set_id}/cases/{case_id}/verify", response_model=GoldenSetCaseVerifyResponse)
def verify_golden_set_case(
    payload: GoldenSetCaseVerifyRequest,
    golden_set_id: UUID = Path(...),
    case_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    reviewer_key_id = _coerce_uuid_str(api_key_ctx.get("key_id"))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id, agent_id from public.golden_sets where id = %s", (str(golden_set_id),))
            gs_row = cur.fetchone()
            if not gs_row:
                _error("GOLDEN_SET_NOT_FOUND", f"Golden set {golden_set_id} was not found.", status.HTTP_404_NOT_FOUND)
            org_id = str(gs_row[1])  # type: ignore[index]
            agent_id = str(gs_row[2])  # type: ignore[index]
            _assert_org_access(api_key_ctx, org_id, context="golden_set_case_verify")

            cur.execute(
                """
                select id, verification_status::text
                from public.golden_set_cases
                where id = %s and golden_set_id = %s
                """,
                (str(case_id), str(golden_set_id)),
            )
            current_row = cur.fetchone()
            if not current_row:
                _error("GOLDEN_SET_CASE_NOT_FOUND", f"Golden set case {case_id} was not found.", status.HTTP_404_NOT_FOUND)
            previous_status = str(current_row[1])  # type: ignore[index]

            cur.execute(
                """
                update public.golden_set_cases
                set verification_status = %s::public.verification_status,
                    verified_date = current_date,
                    last_reviewed_at = now(),
                    review_notes = %s
                where id = %s and golden_set_id = %s
                returning
                    id,
                    golden_set_id,
                    input,
                    expected_output,
                    acceptable_sources,
                    evaluation_mode::text,
                    evaluation_criteria,
                    difficulty::text,
                    capability::text,
                    scenario_type::text,
                    domain,
                    verification_status::text,
                    verified_by,
                    verified_date,
                    version,
                    is_active,
                    superseded_by,
                    last_reviewed_at,
                    review_notes,
                    created_at
                """,
                (payload.verification_status, payload.notes, str(case_id), str(golden_set_id)),
            )
            row = cur.fetchone()

            cur.execute(
                """
                insert into public.golden_set_case_reviews (
                    org_id, golden_set_id, case_id, review_type, previous_status, new_status, reviewer_api_key_id, notes, metadata
                )
                values (%s, %s, %s, 'verify', %s::public.verification_status, %s::public.verification_status, %s, %s, %s::jsonb)
                """,
                (
                    org_id,
                    str(golden_set_id),
                    str(case_id),
                    previous_status,
                    payload.verification_status,
                    reviewer_key_id,
                    payload.notes,
                    json.dumps({"action": "verify_case"}),
                ),
            )

    _record_activity_event(
        org_id=UUID(org_id),
        agent_id=UUID(agent_id),
        event_type="golden_case_verified",
        title="Golden set case verified",
        details=f"golden_set={str(golden_set_id)[:8]}, case={str(case_id)[:8]}, status={payload.verification_status}",
        severity="info",
        metadata={"golden_set_id": str(golden_set_id), "case_id": str(case_id), "verification_status": payload.verification_status},
    )
    item = _golden_set_case_from_row(row)
    return {"ok": True, "data": item.model_dump(mode="json")}


@app.post("/api/golden-sets/{golden_set_id}/cases/{case_id}/supersede", response_model=GoldenSetCaseSupersedeResponse)
def supersede_golden_set_case(
    payload: GoldenSetCaseSupersedeRequest,
    golden_set_id: UUID = Path(...),
    case_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    reviewer_key_id = _coerce_uuid_str(api_key_ctx.get("key_id"))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id, agent_id from public.golden_sets where id = %s", (str(golden_set_id),))
            gs_row = cur.fetchone()
            if not gs_row:
                _error("GOLDEN_SET_NOT_FOUND", f"Golden set {golden_set_id} was not found.", status.HTTP_404_NOT_FOUND)
            org_id = str(gs_row[1])  # type: ignore[index]
            agent_id = str(gs_row[2])  # type: ignore[index]
            _assert_org_access(api_key_ctx, org_id, context="golden_set_case_supersede")

            cur.execute(
                """
                select id, verification_status::text, version
                from public.golden_set_cases
                where id = %s and golden_set_id = %s
                """,
                (str(case_id), str(golden_set_id)),
            )
            current_row = cur.fetchone()
            if not current_row:
                _error("GOLDEN_SET_CASE_NOT_FOUND", f"Golden set case {case_id} was not found.", status.HTTP_404_NOT_FOUND)
            previous_status = str(current_row[1])  # type: ignore[index]
            next_version = int(current_row[2] or 1) + 1  # type: ignore[index]

            cur.execute(
                """
                insert into public.golden_set_cases (
                    golden_set_id,
                    input,
                    expected_output,
                    acceptable_sources,
                    evaluation_mode,
                    evaluation_criteria,
                    difficulty,
                    capability,
                    scenario_type,
                    domain,
                    verification_status,
                    verified_by,
                    verified_date,
                    version,
                    is_active
                )
                values (
                    %s, %s, %s, %s, %s::public.eval_mode, %s::jsonb,
                    %s::public.difficulty_level, %s::public.capability_type, %s::public.scenario_type,
                    %s, %s::public.verification_status, %s, %s, %s, true
                )
                returning id
                """,
                (
                    str(golden_set_id),
                    payload.input,
                    payload.expected_output,
                    payload.acceptable_sources,
                    payload.evaluation_mode,
                    json.dumps(payload.evaluation_criteria) if payload.evaluation_criteria is not None else None,
                    payload.difficulty,
                    payload.capability,
                    payload.scenario_type,
                    payload.domain,
                    payload.verification_status,
                    str(payload.verified_by) if payload.verified_by else None,
                    payload.verified_date,
                    next_version,
                ),
            )
            new_case_id = cur.fetchone()[0]  # type: ignore[index]

            cur.execute(
                """
                update public.golden_set_cases
                set is_active = false,
                    superseded_by = %s,
                    last_reviewed_at = now(),
                    review_notes = %s
                where id = %s and golden_set_id = %s
                """,
                (str(new_case_id), payload.notes, str(case_id), str(golden_set_id)),
            )

            cur.execute(
                """
                insert into public.golden_set_case_reviews (
                    org_id, golden_set_id, case_id, review_type, previous_status, new_status, reviewer_api_key_id, notes, metadata
                )
                values (%s, %s, %s, 'supersede', %s::public.verification_status, %s::public.verification_status, %s, %s, %s::jsonb)
                """,
                (
                    org_id,
                    str(golden_set_id),
                    str(case_id),
                    previous_status,
                    payload.verification_status,
                    reviewer_key_id,
                    payload.notes,
                    json.dumps({"action": "supersede_case", "new_case_id": str(new_case_id), "new_version": next_version}),
                ),
            )

            cur.execute(
                """
                select
                    id,
                    golden_set_id,
                    input,
                    expected_output,
                    acceptable_sources,
                    evaluation_mode::text,
                    evaluation_criteria,
                    difficulty::text,
                    capability::text,
                    scenario_type::text,
                    domain,
                    verification_status::text,
                    verified_by,
                    verified_date,
                    version,
                    is_active,
                    superseded_by,
                    last_reviewed_at,
                    review_notes,
                    created_at
                from public.golden_set_cases
                where id = %s
                """,
                (str(new_case_id),),
            )
            new_case_row = cur.fetchone()

    _record_activity_event(
        org_id=UUID(org_id),
        agent_id=UUID(agent_id),
        event_type="golden_case_superseded",
        title="Golden set case superseded",
        details=f"golden_set={str(golden_set_id)[:8]}, old_case={str(case_id)[:8]}, new_case={str(new_case_id)[:8]}",
        severity="warning",
        metadata={"golden_set_id": str(golden_set_id), "previous_case_id": str(case_id), "new_case_id": str(new_case_id)},
    )
    new_case = _golden_set_case_from_row(new_case_row)
    return {"ok": True, "data": {"previous_case_id": str(case_id), "new_case": new_case.model_dump(mode="json")}}


@app.get("/api/agents/{agent_id}/golden-sets", response_model=AgentGoldenSetListResponse)
def list_agent_golden_sets(
    agent_id: UUID = Path(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_golden_sets_read")  # type: ignore[index]

            cur.execute(
                """
                select
                    gs.id,
                    gs.org_id,
                    gs.agent_id,
                    gs.name,
                    gs.description,
                    gs.generation_method::text,
                    gs.created_at,
                    count(c.id) as case_count
                from public.golden_sets gs
                left join public.golden_set_cases c on c.golden_set_id = gs.id
                where gs.agent_id = %s
                group by gs.id
                order by gs.created_at desc
                limit %s
                offset %s
                """,
                (str(agent_id), limit, offset),
            )
            rows = cur.fetchall()

    items = [
        AgentGoldenSetItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            name=r[3],
            description=r[4],
            generation_method=r[5],
            created_at=r[6],
            case_count=int(r[7] or 0),
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"items": items, "count": len(items), "limit": limit, "offset": offset}}


@app.get("/api/agents/{agent_id}/patterns", response_model=IssuePatternListResponse)
def list_agent_patterns(
    agent_id: UUID = Path(...),
    status_filter: Optional[IssueStatus] = Query(default=None, alias="status"),
    priority: Optional[IssuePriority] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_patterns_read")  # type: ignore[index]

            where = ["ip.agent_id = %s"]
            params: List[Any] = [str(agent_id)]

            if status_filter is not None:
                where.append("ip.status::text = %s")
                params.append(status_filter)
            if priority is not None:
                where.append("ip.priority::text = %s")
                params.append(priority)

            where_sql = " and ".join(where)
            cur.execute(
                f"""
                select
                    ip.id,
                    ip.org_id,
                    ip.agent_id,
                    ip.title,
                    ip.primary_tag,
                    ip.related_tags,
                    ip.status::text,
                    ip.priority::text,
                    ip.root_cause,
                    ip.root_cause_type::text,
                    ip.suggested_fix,
                    ip.owner,
                    ip.linked_case_ids,
                    ip.created_at,
                    ip.updated_at,
                    ip.resolved_date
                from public.issue_patterns ip
                where {where_sql}
                order by ip.updated_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

    items = [
        IssuePatternItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            title=r[3],
            primary_tag=r[4],
            related_tags=r[5] or [],
            status=r[6],
            priority=r[7],
            root_cause=r[8],
            root_cause_type=r[9],
            suggested_fix=r[10],
            owner=r[11],
            linked_case_ids=r[12] or [],
            created_at=r[13],
            updated_at=r[14],
            resolved_date=r[15].isoformat() if r[15] else None,
        ).model_dump(mode="json")
        for r in rows
    ]

    return {"ok": True, "data": {"items": items, "count": len(items), "limit": limit, "offset": offset}}


@app.get("/api/agents/{agent_id}/patterns/{pattern_id}/history", response_model=PatternHistoryResponse)
def get_agent_pattern_history(
    agent_id: UUID = Path(...),
    pattern_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_pattern_history_read")  # type: ignore[index]

            cur.execute(
                """
                select id, status::text, status_history, updated_at
                from public.issue_patterns
                where id = %s and agent_id = %s
                """,
                (str(pattern_id), str(agent_id)),
            )
            row = cur.fetchone()
            if not row:
                _error(
                    "PATTERN_NOT_FOUND",
                    f"Issue pattern {pattern_id} was not found for agent {agent_id}.",
                    status.HTTP_404_NOT_FOUND,
                )

    data = PatternHistoryData(
        pattern_id=row[0],  # type: ignore[index]
        agent_id=agent_id,
        status=row[1],  # type: ignore[index]
        status_history=row[2] or [],  # type: ignore[index]
        updated_at=row[3],  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/activity", response_model=AgentActivityResponse)
def list_agent_activity(
    agent_id: UUID = Path(...),
    event_type: Optional[str] = Query(default=None),
    severity: Optional[ActivitySeverity] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_activity_read")  # type: ignore[index]

            where = ["ae.agent_id = %s"]
            params: List[Any] = [str(agent_id)]
            if event_type is not None:
                where.append("ae.event_type = %s")
                params.append(event_type)
            if severity is not None:
                where.append("ae.severity::text = %s")
                params.append(severity)
            where_sql = " and ".join(where)

            cur.execute(
                f"""
                select
                    ae.id,
                    ae.org_id,
                    ae.agent_id,
                    ae.event_type,
                    ae.severity::text,
                    ae.title,
                    ae.details,
                    ae.metadata,
                    ae.created_at
                from public.activity_events ae
                where {where_sql}
                order by ae.created_at desc
                limit %s
                offset %s
                """,
                (*params, limit, offset),
            )
            rows = cur.fetchall()

            cur.execute(
                f"""
                select count(1)
                from public.activity_events ae
                where {where_sql}
                """,
                tuple(params),
            )
            total_count = int(cur.fetchone()[0])  # type: ignore[index]

    items = [
        ActivityEventItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            event_type=r[3],
            severity=r[4],
            title=r[5],
            details=r[6],
            metadata=r[7] or {},
            created_at=r[8],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {
        "ok": True,
        "data": {"agent_id": str(agent_id), "items": items, "count": len(items), "total_count": total_count, "limit": limit, "offset": offset},
    }


@app.get("/api/agents/{agent_id}/readiness", response_model=AgentReadinessResponse)
def get_agent_readiness(
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_readiness_read")  # type: ignore[index]

            cur.execute(
                """
                select
                    lr.id,
                    lr.org_id,
                    lr.agent_id,
                    lr.items,
                    lr.thresholds,
                    lr.decision::text,
                    lr.decision_notes,
                    lr.decision_date,
                    lr.created_at,
                    lr.updated_at
                from public.launch_readiness lr
                where lr.agent_id = %s
                limit 1
                """,
                (str(agent_id),),
            )
            row = cur.fetchone()

    if not row:
        return {"ok": True, "data": {"agent_id": str(agent_id), "readiness": None}}

    readiness = LaunchReadinessData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        items=row[3] or [],  # type: ignore[index]
        thresholds=row[4] or {},  # type: ignore[index]
        decision=row[5],  # type: ignore[index]
        decision_notes=row[6],  # type: ignore[index]
        decision_date=row[7].isoformat() if row[7] else None,  # type: ignore[index]
        created_at=row[8],  # type: ignore[index]
        updated_at=row[9],  # type: ignore[index]
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "readiness": readiness.model_dump(mode="json")}}


@app.get("/api/agents/{agent_id}/launch-gate", response_model=LaunchGateResponse)
def get_agent_launch_gate(
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_launch_gate_read")  # type: ignore[index]
    gate = _evaluate_launch_gate(agent_id)
    data = LaunchGateData(
        agent_id=agent_id,
        can_launch=bool(gate["can_launch"]),
        blockers=gate["blockers"],
        latest_run_id=gate["latest_run_id"],
        latest_run_status=gate["latest_run_status"],
        active_critical_issues=int(gate["active_critical_issues"]),
        open_slo_violations=int(gate["open_slo_violations"]),
        readiness_pending_items=int(gate["readiness_pending_items"]),
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents/{agent_id}/launch-decisions", response_model=LaunchDecisionListResponse)
def list_agent_launch_decisions(
    agent_id: UUID = Path(...),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_launch_decisions_read")  # type: ignore[index]

            cur.execute(
                """
                select id, org_id, agent_id, decision::text, reason, blockers, decided_by_api_key_id, decided_at
                from public.launch_decisions
                where agent_id = %s
                order by decided_at desc
                limit %s
                offset %s
                """,
                (str(agent_id), limit, offset),
            )
            rows = cur.fetchall()
    items = [
        LaunchDecisionItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            decision=r[3],
            reason=r[4],
            blockers=r[5] or [],
            decided_by_api_key_id=r[6],
            decided_at=r[7],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"agent_id": str(agent_id), "items": items, "count": len(items), "limit": limit, "offset": offset}}


@app.get("/api/agents/{agent_id}/launch-certifications", response_model=LaunchCertificationListResponse)
def list_agent_launch_certifications(
    agent_id: UUID = Path(...),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key_ctx: Dict[str, Any] = Depends(require_viewer),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_launch_certifications_read")  # type: ignore[index]

            cur.execute(
                """
                select id, org_id, agent_id, decision::text, certification_status, reason, blockers, evidence, created_by_api_key_id, created_at
                from public.launch_certifications
                where agent_id = %s
                order by created_at desc
                limit %s
                offset %s
                """,
                (str(agent_id), limit, offset),
            )
            rows = cur.fetchall()

    items = [
        LaunchCertificationItem(
            id=r[0],
            org_id=r[1],
            agent_id=r[2],
            decision=r[3],
            certification_status=r[4],
            reason=r[5],
            blockers=r[6] or [],
            evidence=r[7] or {},
            created_by_api_key_id=r[8],
            created_at=r[9],
        ).model_dump(mode="json")
        for r in rows
    ]
    return {"ok": True, "data": {"agent_id": str(agent_id), "items": items, "count": len(items), "limit": limit, "offset": offset}}


@app.post(
    "/api/agents/{agent_id}/launch-certify",
    status_code=status.HTTP_201_CREATED,
    response_model=LaunchCertificationCreateResponse,
)
def create_launch_certification(
    payload: LaunchCertificationCreateRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    gate = _evaluate_launch_gate(agent_id)
    gate_blockers: List[str] = list(gate.get("blockers") or [])
    compare_blockers: List[str] = []
    latest_compare_event: Optional[Dict[str, Any]] = None

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            org_id = str(agent_row[1])  # type: ignore[index]
            _assert_org_access(api_key_ctx, org_id, context="agent_launch_certify")

            cur.execute(
                """
                select id, metadata, created_at
                from public.activity_events
                where agent_id = %s and event_type = 'regression_compare'
                order by created_at desc
                limit 1
                """,
                (str(agent_id),),
            )
            compare_row = cur.fetchone()
            if not compare_row:
                compare_blockers.append("No regression compare evidence found.")
            else:
                latest_compare_event = {
                    "event_id": str(compare_row[0]),
                    "created_at": compare_row[2].isoformat() if hasattr(compare_row[2], "isoformat") else str(compare_row[2]),
                    "metadata": compare_row[1] or {},
                }
                compare_meta = compare_row[1] or {}
                regression_count = int(compare_meta.get("regression_count", 0))
                if regression_count > 0:
                    compare_blockers.append(f"Latest compare has {regression_count} regression(s).")
                latest_run_id = gate.get("latest_run_id")
                compare_candidate_id = compare_meta.get("candidate_run_id")
                if latest_run_id and compare_candidate_id and str(latest_run_id) != str(compare_candidate_id):
                    compare_blockers.append("Latest run is not the compared candidate run.")

            blockers = [*gate_blockers, *compare_blockers]
            certification_status = "certified" if payload.decision == "go" and not blockers else "blocked"
            evidence = {
                "gate": gate,
                "latest_compare_event": latest_compare_event,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

            cur.execute(
                """
                insert into public.launch_certifications (
                    org_id, agent_id, decision, certification_status, reason, blockers, evidence, created_by_api_key_id
                )
                values (%s, %s, %s::public.launch_decision_action, %s, %s, %s::jsonb, %s::jsonb, %s)
                returning id, org_id, agent_id, decision::text, certification_status, reason, blockers, evidence, created_by_api_key_id, created_at
                """,
                (
                    org_id,
                    str(agent_id),
                    payload.decision,
                    certification_status,
                    payload.reason,
                    json.dumps(blockers),
                    json.dumps(evidence),
                    _coerce_uuid_str(api_key_ctx.get("key_id")),
                ),
            )
            row = cur.fetchone()

    _record_activity_event(
        org_id=UUID(org_id),
        agent_id=agent_id,
        event_type="launch_certification",
        title=f"Launch certification: {row[4]}",  # type: ignore[index]
        details=payload.reason,
        severity="info" if row[4] == "certified" else "warning",  # type: ignore[index]
        metadata={"certification_id": str(row[0]), "decision": row[3], "status": row[4], "blockers": row[6] or []},  # type: ignore[index]
    )

    certification = LaunchCertificationItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        decision=row[3],  # type: ignore[index]
        certification_status=row[4],  # type: ignore[index]
        reason=row[5],  # type: ignore[index]
        blockers=row[6] or [],  # type: ignore[index]
        evidence=row[7] or {},  # type: ignore[index]
        created_by_api_key_id=row[8],  # type: ignore[index]
        created_at=row[9],  # type: ignore[index]
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "certification": certification.model_dump(mode="json")}}


@app.post("/api/agents/{agent_id}/launch-decision", status_code=status.HTTP_201_CREATED, response_model=LaunchDecisionCreateResponse)
def create_launch_decision(
    payload: LaunchDecisionCreateRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    gate = _evaluate_launch_gate(agent_id)
    if payload.decision == "go" and not bool(gate["can_launch"]):
        _error(
            "LAUNCH_GATE_BLOCKED",
            f"Launch decision 'go' is blocked: {'; '.join(gate['blockers'])}",
            status.HTTP_400_BAD_REQUEST,
        )

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
            _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_launch_decision_create")  # type: ignore[index]
            org_id = agent_row[1]  # type: ignore[index]

            cur.execute(
                """
                insert into public.launch_decisions (
                    org_id, agent_id, decision, reason, blockers, decided_by_api_key_id
                )
                values (%s, %s, %s::public.launch_decision_action, %s, %s::jsonb, %s)
                returning id, org_id, agent_id, decision::text, reason, blockers, decided_by_api_key_id, decided_at
                """,
                (
                    str(org_id),
                    str(agent_id),
                    payload.decision,
                    payload.reason,
                    json.dumps(gate["blockers"]),
                    api_key_ctx.get("key_id"),
                ),
            )
            row = cur.fetchone()

            cur.execute(
                """
                insert into public.launch_readiness (
                    org_id, agent_id, items, thresholds, decision, decision_notes, decision_date
                )
                values (%s, %s, '[]'::jsonb, '{}'::jsonb, %s::public.readiness_decision, %s, now()::date)
                on conflict (agent_id) do update
                set decision = excluded.decision,
                    decision_notes = excluded.decision_notes,
                    decision_date = excluded.decision_date,
                    updated_at = now()
                """,
                (str(org_id), str(agent_id), payload.decision, payload.reason),
            )

    notification = _dispatch_notification(
        org_id=UUID(str(row[1])),  # type: ignore[index]
        agent_id=UUID(str(row[2])),  # type: ignore[index]
        event_type="launch_decision_changed",
        payload={
            "org_id": str(row[1]),  # type: ignore[index]
            "agent_id": str(row[2]),  # type: ignore[index]
            "decision_id": str(row[0]),  # type: ignore[index]
            "decision": row[3],  # type: ignore[index]
            "reason": row[4],  # type: ignore[index]
            "blockers": row[5] or [],  # type: ignore[index]
        },
    )

    _record_activity_event(
        org_id=UUID(str(row[1])),  # type: ignore[index]
        agent_id=UUID(str(row[2])),  # type: ignore[index]
        event_type="launch_decision",
        title=f"Launch decision: {row[3]}",  # type: ignore[index]
        details=payload.reason,
        severity="warning" if row[3] != "go" else "info",  # type: ignore[index]
        metadata={
            "decision_id": str(row[0]),  # type: ignore[index]
            "decision": row[3],  # type: ignore[index]
            "blockers": row[5] or [],  # type: ignore[index]
            "notification": notification,
        },
    )

    item = LaunchDecisionItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        decision=row[3],  # type: ignore[index]
        reason=row[4],  # type: ignore[index]
        blockers=row[5] or [],  # type: ignore[index]
        decided_by_api_key_id=row[6],  # type: ignore[index]
        decided_at=row[7],  # type: ignore[index]
        notification=notification,
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "decision": item.model_dump(mode="json"), "gate": gate}}


@app.post("/api/agents/{agent_id}/patterns", status_code=status.HTTP_201_CREATED, response_model=IssuePatternResponse)
def create_agent_pattern(
    payload: IssuePatternCreateRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_pattern_create")  # type: ignore[index]
                org_id = agent_row[1]  # type: ignore[index]

                cur.execute(
                    """
                    insert into public.issue_patterns (
                        org_id,
                        agent_id,
                        title,
                        primary_tag,
                        related_tags,
                        status,
                        priority,
                        root_cause,
                        root_cause_type,
                        suggested_fix,
                        owner,
                        linked_case_ids,
                        history,
                        status_history,
                        fix_notes,
                        verification_result,
                        resolved_date
                    )
                    values (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s::public.issue_status,
                        %s::public.issue_priority,
                        %s,
                        %s::public.root_cause_type,
                        %s,
                        %s,
                        %s::uuid[],
                        %s::jsonb,
                        %s::jsonb,
                        %s::jsonb,
                        %s::jsonb,
                        %s
                    )
                    returning
                        id,
                        org_id,
                        agent_id,
                        title,
                        primary_tag,
                        related_tags,
                        status::text,
                        priority::text,
                        root_cause,
                        root_cause_type::text,
                        suggested_fix,
                        owner,
                        linked_case_ids,
                        created_at,
                        updated_at,
                        resolved_date
                    """,
                    (
                        str(org_id),
                        str(agent_id),
                        payload.title,
                        payload.primary_tag,
                        payload.related_tags,
                        payload.status,
                        payload.priority,
                        payload.root_cause,
                        payload.root_cause_type,
                        payload.suggested_fix,
                        payload.owner,
                        [str(x) for x in payload.linked_case_ids],
                        json.dumps(payload.history),
                        json.dumps(payload.status_history),
                        json.dumps(payload.fix_notes),
                        json.dumps(payload.verification_result),
                        payload.resolved_date,
                    ),
                )
                row = cur.fetchone()
    except Exception as exc:
        _error("PATTERN_CREATE_FAILED", f"Failed to create issue pattern: {exc}", status.HTTP_400_BAD_REQUEST)

    item = IssuePatternItem(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        title=row[3],  # type: ignore[index]
        primary_tag=row[4],  # type: ignore[index]
        related_tags=row[5] or [],  # type: ignore[index]
        status=row[6],  # type: ignore[index]
        priority=row[7],  # type: ignore[index]
        root_cause=row[8],  # type: ignore[index]
        root_cause_type=row[9],  # type: ignore[index]
        suggested_fix=row[10],  # type: ignore[index]
        owner=row[11],  # type: ignore[index]
        linked_case_ids=row[12] or [],  # type: ignore[index]
        created_at=row[13],  # type: ignore[index]
        updated_at=row[14],  # type: ignore[index]
        resolved_date=row[15].isoformat() if row[15] else None,  # type: ignore[index]
    )
    return {"ok": True, "data": item.model_dump(mode="json")}


@app.patch("/api/agents/{agent_id}/patterns/{pattern_id}", response_model=IssuePatternUpdateResponse)
def update_agent_pattern(
    payload: IssuePatternUpdateRequest,
    agent_id: UUID = Path(...),
    pattern_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    current_status = ""
    new_status = ""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select
                        id,
                        org_id,
                        agent_id,
                        title,
                        primary_tag,
                        related_tags,
                        status::text,
                        priority::text,
                        root_cause,
                        root_cause_type::text,
                        suggested_fix,
                        owner,
                        linked_case_ids,
                        history,
                        status_history,
                        fix_notes,
                        verification_result,
                        created_at,
                        updated_at,
                        resolved_date
                    from public.issue_patterns
                    where id = %s and agent_id = %s
                    """,
                    (str(pattern_id), str(agent_id)),
                )
                row = cur.fetchone()
                if not row:
                    _error(
                        "PATTERN_NOT_FOUND",
                        f"Issue pattern {pattern_id} was not found for agent {agent_id}.",
                        status.HTTP_404_NOT_FOUND,
                    )
                _assert_org_access(api_key_ctx, str(row[1]), context="agent_pattern_update")  # type: ignore[index]

                current_status = str(row[6])  # type: ignore[index]
                new_status = payload.status or current_status
                if not _is_allowed_pattern_transition(current_status, new_status):
                    if payload.force:
                        # Platform-admin override: global API key (org_id is null).
                        if api_key_ctx.get("org_id") is not None:
                            _error(
                                "FORBIDDEN",
                                "force=true is only allowed for platform-admin keys.",
                                status.HTTP_403_FORBIDDEN,
                            )
                    else:
                        _error(
                            "PATTERN_INVALID_TRANSITION",
                            f"Invalid status transition: {current_status} -> {new_status}.",
                            status.HTTP_400_BAD_REQUEST,
                        )
                current_status_history = row[14] or []  # type: ignore[index]
                new_status_history = _append_status_history(
                    current_status_history,
                    old_status=current_status,
                    new_status=new_status,
                    note=payload.status_note,
                )

                # If resolved_date omitted but status set to resolved, auto-stamp current date.
                resolved_date = payload.resolved_date
                if resolved_date is None and payload.status == "resolved":
                    resolved_date = datetime.now(timezone.utc).date().isoformat()

                cur.execute(
                    """
                    update public.issue_patterns
                    set
                        status = coalesce(%s::public.issue_status, status),
                        priority = coalesce(%s::public.issue_priority, priority),
                        root_cause = coalesce(%s, root_cause),
                        root_cause_type = coalesce(%s::public.root_cause_type, root_cause_type),
                        suggested_fix = coalesce(%s, suggested_fix),
                        owner = coalesce(%s, owner),
                        related_tags = coalesce(%s::text[], related_tags),
                        linked_case_ids = coalesce(%s::uuid[], linked_case_ids),
                        verification_result = coalesce(%s::jsonb, verification_result),
                        resolved_date = coalesce(%s::date, resolved_date),
                        status_history = %s::jsonb
                    where id = %s and agent_id = %s
                    returning
                        id,
                        org_id,
                        agent_id,
                        title,
                        primary_tag,
                        related_tags,
                        status::text,
                        priority::text,
                        root_cause,
                        root_cause_type::text,
                        suggested_fix,
                        owner,
                        linked_case_ids,
                        created_at,
                        updated_at,
                        resolved_date
                    """,
                    (
                        payload.status,
                        payload.priority,
                        payload.root_cause,
                        payload.root_cause_type,
                        payload.suggested_fix,
                        payload.owner,
                        payload.related_tags,
                        [str(x) for x in payload.linked_case_ids] if payload.linked_case_ids is not None else None,
                        json.dumps(payload.verification_result) if payload.verification_result is not None else None,
                        resolved_date,
                        json.dumps(new_status_history),
                        str(pattern_id),
                        str(agent_id),
                    ),
                )
                updated = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:
        _error("PATTERN_UPDATE_FAILED", f"Failed to update issue pattern: {exc}", status.HTTP_400_BAD_REQUEST)

    notification: Dict[str, Any] = {"sent": False, "event_type": "pattern_status_changed"}
    if current_status != new_status:
        notification = _dispatch_notification(
            org_id=UUID(str(updated[1])),  # type: ignore[index]
            agent_id=UUID(str(updated[2])),  # type: ignore[index]
            event_type="pattern_status_changed",
            payload={
                "org_id": str(updated[1]),  # type: ignore[index]
                "agent_id": str(updated[2]),  # type: ignore[index]
                "pattern_id": str(updated[0]),  # type: ignore[index]
                "title": str(updated[3]),  # type: ignore[index]
                "from_status": current_status,
                "to_status": new_status,
                "priority": str(updated[7]),  # type: ignore[index]
                "owner": updated[11],  # type: ignore[index]
            },
        )

    _record_activity_event(
        org_id=UUID(str(updated[1])),  # type: ignore[index]
        agent_id=UUID(str(updated[2])),  # type: ignore[index]
        event_type="pattern_transition",
        title="Pattern status updated",
        details=f"pattern={str(updated[0])[:8]}, {current_status}->{new_status}",
        severity="warning" if new_status == "regressed" else "info",
        metadata={
            "pattern_id": str(updated[0]),
            "from_status": current_status,
            "to_status": new_status,
            "priority": str(updated[7]),  # type: ignore[index]
            "owner": updated[11],  # type: ignore[index]
            "notification": notification,
        },
    )

    item = IssuePatternItem(
        id=updated[0],  # type: ignore[index]
        org_id=updated[1],  # type: ignore[index]
        agent_id=updated[2],  # type: ignore[index]
        title=updated[3],  # type: ignore[index]
        primary_tag=updated[4],  # type: ignore[index]
        related_tags=updated[5] or [],  # type: ignore[index]
        status=updated[6],  # type: ignore[index]
        priority=updated[7],  # type: ignore[index]
        root_cause=updated[8],  # type: ignore[index]
        root_cause_type=updated[9],  # type: ignore[index]
        suggested_fix=updated[10],  # type: ignore[index]
        owner=updated[11],  # type: ignore[index]
        linked_case_ids=updated[12] or [],  # type: ignore[index]
        created_at=updated[13],  # type: ignore[index]
        updated_at=updated[14],  # type: ignore[index]
        resolved_date=updated[15].isoformat() if updated[15] else None,  # type: ignore[index]
    )
    return {"ok": True, "data": {**item.model_dump(mode="json"), "notification": notification}}


@app.post("/api/agents/{agent_id}/readiness", status_code=status.HTTP_201_CREATED, response_model=AgentReadinessResponse)
def upsert_agent_readiness(
    payload: LaunchReadinessUpsertRequest,
    agent_id: UUID = Path(...),
    api_key_ctx: Dict[str, Any] = Depends(require_member),
) -> Dict[str, Any]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
                _assert_org_access(api_key_ctx, str(agent_row[1]), context="agent_readiness_write")  # type: ignore[index]
                org_id = agent_row[1]  # type: ignore[index]

                cur.execute(
                    """
                    insert into public.launch_readiness (
                        org_id,
                        agent_id,
                        items,
                        thresholds,
                        decision,
                        decision_notes,
                        decision_date
                    )
                    values (
                        %s,
                        %s,
                        %s::jsonb,
                        %s::jsonb,
                        %s::public.readiness_decision,
                        %s,
                        %s
                    )
                    on conflict (agent_id) do update
                    set
                        items = excluded.items,
                        thresholds = excluded.thresholds,
                        decision = excluded.decision,
                        decision_notes = excluded.decision_notes,
                        decision_date = excluded.decision_date,
                        updated_at = now()
                    returning
                        id,
                        org_id,
                        agent_id,
                        items,
                        thresholds,
                        decision::text,
                        decision_notes,
                        decision_date,
                        created_at,
                        updated_at
                    """,
                    (
                        str(org_id),
                        str(agent_id),
                        json.dumps(payload.items),
                        json.dumps(payload.thresholds),
                        payload.decision,
                        payload.decision_notes,
                        payload.decision_date,
                    ),
                )
                row = cur.fetchone()
    except Exception as exc:
        _error("READINESS_UPSERT_FAILED", f"Failed to upsert launch readiness: {exc}", status.HTTP_400_BAD_REQUEST)

    readiness = LaunchReadinessData(
        id=row[0],  # type: ignore[index]
        org_id=row[1],  # type: ignore[index]
        agent_id=row[2],  # type: ignore[index]
        items=row[3] or [],  # type: ignore[index]
        thresholds=row[4] or {},  # type: ignore[index]
        decision=row[5],  # type: ignore[index]
        decision_notes=row[6],  # type: ignore[index]
        decision_date=row[7].isoformat() if row[7] else None,  # type: ignore[index]
        created_at=row[8],  # type: ignore[index]
        updated_at=row[9],  # type: ignore[index]
    )
    return {"ok": True, "data": {"agent_id": str(agent_id), "readiness": readiness.model_dump(mode="json")}}
