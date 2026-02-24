from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Path, Query, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.api.db import get_conn
from src.api.services.judge import (
    JudgeConfigurationError,
    ProviderJudgeNotReadyError,
    ProviderJudgeRuntimeError,
    compute_agreement,
    get_judge_service,
)

RunType = Literal["eval", "regression", "ab_comparison", "calibration"]
RunStatus = Literal["pending", "running", "completed", "failed"]
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

app = FastAPI(title="Greenlight API", version="v1")


def _error(code: str, message: str, http_status: int) -> None:
    raise HTTPException(
        status_code=http_status,
        detail={"ok": False, "error": {"code": code, "message": message}},
    )


def _api_key_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validate_db_api_key(token: str) -> bool:
    token_hash = _api_key_hash(token)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id
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
                    return False
                cur.execute("update public.api_keys set last_used_at = now() where id = %s", (row[0],))
                return True
    except Exception:
        return False


def require_api_key(authorization: Optional[str] = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        _error(
            code="UNAUTHORIZED",
            message="Missing or invalid Authorization header.",
            http_status=status.HTTP_401_UNAUTHORIZED,
        )
    token = authorization.removeprefix("Bearer ").strip()

    # Primary auth source: hashed keys in DB.
    if _validate_db_api_key(token):
        return token

    _error(
        code="UNAUTHORIZED",
        message="Invalid API key.",
        http_status=status.HTTP_401_UNAUTHORIZED,
    )
    return token


class EvalRunCreateRequest(BaseModel):
    org_id: UUID
    agent_id: UUID
    golden_set_id: Optional[UUID] = None
    name: str = Field(min_length=1, max_length=255)
    type: RunType
    config: Dict[str, Any] = Field(default_factory=dict)
    design_context: Dict[str, Any] = Field(default_factory=dict)


class EvalRunCreateData(BaseModel):
    run_id: UUID
    status: RunStatus
    created_at: datetime


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


class ApiKeyListItem(BaseModel):
    id: UUID
    org_id: Optional[UUID]
    name: str
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


class GoldenSetUploadRequest(BaseModel):
    org_id: UUID
    agent_id: UUID
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    generation_method: GenerationMethod
    source_files: List[Any] = Field(default_factory=list)
    cases: List[GoldenSetCaseUpload] = Field(min_length=1)


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
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "ok": False,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed.",
                "details": exc.errors(),
            },
        },
    )


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "data": {"status": "healthy"}}


@app.post("/api/system/api-keys", status_code=status.HTTP_201_CREATED)
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
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    # Plaintext key is returned once at creation time.
    plaintext = f"sk_live_{secrets.token_urlsafe(24)}"
    key_hash = _api_key_hash(plaintext)
    key_prefix = plaintext[:10]

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into public.api_keys (org_id, name, key_prefix, key_hash, status, expires_at)
                    values (%s, %s, %s, %s, 'active', %s)
                    returning id, org_id, name, key_prefix, status::text, expires_at, created_at
                    """,
                    (
                        str(payload.org_id) if payload.org_id else None,
                        payload.name,
                        key_prefix,
                        key_hash,
                        payload.expires_at,
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
            "key_prefix": row[3],  # type: ignore[index]
            "status": row[4],  # type: ignore[index]
            "expires_at": row[5].isoformat() if row[5] else None,  # type: ignore[index]
            "created_at": row[6].isoformat(),  # type: ignore[index]
            "api_key": plaintext,
        },
    }


@app.get("/api/system/api-keys")
def list_api_keys(
    status_filter: Optional[Literal["active", "revoked"]] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            where = []
            params: List[Any] = []
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
            key_prefix=r[3],
            status=r[4],
            expires_at=r[5],
            last_used_at=r[6],
            created_at=r[7],
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


@app.post("/api/system/api-keys/{key_id}/revoke")
def revoke_api_key(
    key_id: UUID = Path(...),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
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
            if not row:
                _error("API_KEY_NOT_FOUND", f"API key {key_id} was not found.", status.HTTP_404_NOT_FOUND)

    return {"ok": True, "data": {"id": str(row[0]), "status": row[1]}}  # type: ignore[index]


@app.post("/api/eval/runs", status_code=status.HTTP_202_ACCEPTED)
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
                    "golden_set_id": "6755aac9-2d1e-46bd-8962-5731dbe4b6b5",
                    "name": "acme-gs-exec-001",
                    "type": "eval",
                    "config": {"sample_size": "all"},
                    "design_context": {"reason": "execute endpoint test"},
                },
            }
        ],
    ),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
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
                        str(payload.golden_set_id) if payload.golden_set_id else None,
                        payload.name,
                        payload.type,
                        json.dumps(payload.config),
                        json.dumps(payload.design_context),
                    ),
                )
                row = cur.fetchone()
    except Exception as exc:
        _error("EVAL_RUN_CREATE_FAILED", f"Failed to create eval run: {exc}", status.HTTP_400_BAD_REQUEST)

    data = EvalRunCreateData(run_id=row[0], status=row[1], created_at=row[2])  # type: ignore[index]
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.post("/api/calibration/runs", status_code=status.HTTP_201_CREATED)
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
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    cases_json = [c.model_dump(mode="json") for c in payload.per_case_comparison]
    overall_agreement, clean_agreement = compute_agreement(cases_json)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
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


@app.get("/api/calibration/runs/{calibration_id}")
def get_calibration_run(
    calibration_id: UUID = Path(...),
    _: str = Depends(require_api_key),
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


@app.get("/api/agents/{agent_id}/calibration/latest")
def get_agent_latest_calibration(
    agent_id: UUID = Path(...),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.agents where id = %s", (str(agent_id),))
            if not cur.fetchone():
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)

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


@app.post("/api/eval/runs/{run_id}/execute")
def execute_eval_run(
    run_id: UUID = Path(...),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    exec_start = time.perf_counter()
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id, org_id, agent_id, golden_set_id, status::text, config
                    from public.eval_runs
                    where id = %s
                    for update
                    """,
                    (str(run_id),),
                )
                run_row = cur.fetchone()
                if not run_row:
                    _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)

                agent_id = run_row[2]  # type: ignore[index]
                golden_set_id = run_row[3]  # type: ignore[index]
                run_status = run_row[4]  # type: ignore[index]
                run_config = run_row[5] or {}  # type: ignore[index]
                judge_mode = str(run_config.get("judge_mode", "deterministic"))
                judge_model = run_config.get("judge_model")
                judge_prompt_version = run_config.get("judge_prompt_version")
                judge = get_judge_service(
                    mode=judge_mode,
                    prompt_version=judge_prompt_version,
                    model=judge_model,
                )

                if golden_set_id is None:
                    _error(
                        "EVAL_RUN_NO_GOLDEN_SET",
                        "Eval run cannot execute without golden_set_id.",
                        status.HTTP_400_BAD_REQUEST,
                    )
                if run_status == "running":
                    _error("EVAL_RUN_ALREADY_RUNNING", f"Eval run {run_id} is already running.", status.HTTP_409_CONFLICT)

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

                now_date = datetime.now(timezone.utc).date()

                for case in cases:
                    case_start = time.perf_counter()
                    case_id = case[0]
                    input_text = case[1] or ""
                    expected_output = case[2]
                    acceptable_sources = case[3]
                    eval_mode = case[4]
                    eval_criteria = case[5]

                    if eval_mode == "answer":
                        score = judge.evaluate_answer_case(input_text, expected_output, acceptable_sources)
                        trace_notes = {
                            "trace_version": "v1",
                            "judge_mode": judge_mode,
                            "judge_model": judge_model,
                            "judge_prompt_version": judge_prompt_version,
                            "case_latency_ms": round((time.perf_counter() - case_start) * 1000, 2),
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
                            """,
                            (
                                str(run_id),
                                str(case_id),
                                str(agent_id),
                                score["generated"],
                                acceptable_sources,
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
                    else:
                        criteria_eval = judge.evaluate_criteria_case(input_text, eval_criteria)
                        trace_notes = {
                            "trace_version": "v1",
                            "judge_mode": judge_mode,
                            "judge_model": judge_model,
                            "judge_prompt_version": judge_prompt_version,
                            "case_latency_ms": round((time.perf_counter() - case_start) * 1000, 2),
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
                            """,
                            (
                                str(run_id),
                                str(case_id),
                                str(agent_id),
                                criteria_eval["generated"],
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

                exec_summary = {
                    "execution": {
                        "trace_version": "v1",
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
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/eval/runs/{run_id}")
def get_eval_run(
    run_id: UUID = Path(...),
    include_results: bool = Query(default=False),
    _: str = Depends(require_api_key),
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


@app.get("/api/eval/runs/{run_id}/results")
def get_eval_run_results(
    run_id: UUID = Path(...),
    evaluation_mode: Optional[EvaluationMode] = Query(default=None),
    answer_correct: Optional[Literal["yes", "partially", "no"]] = Query(default=None),
    source_correct: Optional[Literal["yes", "partially", "no"]] = Query(default=None),
    response_quality: Optional[Literal["good", "average", "not_good"]] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.eval_runs where id = %s", (str(run_id),))
            if not cur.fetchone():
                _error("EVAL_RUN_NOT_FOUND", f"Eval run {run_id} was not found.", status.HTTP_404_NOT_FOUND)

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


@app.get("/api/eval/runs/{run_id}/summary")
def get_eval_run_summary(
    run_id: UUID = Path(...),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
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

    total = int(row[4])  # type: ignore[index]

    def rate(n: int) -> float:
        if total == 0:
            return 0.0
        return n / total

    data = EvalRunSummaryData(
        run_id=row[0],  # type: ignore[index]
        status=row[1],  # type: ignore[index]
        created_at=row[2],  # type: ignore[index]
        completed_at=row[3],  # type: ignore[index]
        total_results=total,
        answer_yes_count=int(row[5] or 0),  # type: ignore[index]
        answer_partially_count=int(row[6] or 0),  # type: ignore[index]
        answer_no_count=int(row[7] or 0),  # type: ignore[index]
        source_yes_count=int(row[8] or 0),  # type: ignore[index]
        source_partially_count=int(row[9] or 0),  # type: ignore[index]
        source_no_count=int(row[10] or 0),  # type: ignore[index]
        quality_good_count=int(row[11] or 0),  # type: ignore[index]
        quality_average_count=int(row[12] or 0),  # type: ignore[index]
        quality_not_good_count=int(row[13] or 0),  # type: ignore[index]
        answer_yes_rate=rate(int(row[5] or 0)),  # type: ignore[index]
        source_yes_rate=rate(int(row[8] or 0)),  # type: ignore[index]
        quality_good_rate=rate(int(row[11] or 0)),  # type: ignore[index]
    )
    return {"ok": True, "data": data.model_dump(mode="json")}


@app.get("/api/agents")
def list_agents(
    org_id: Optional[UUID] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    agent_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    where = []
    params: List[Any] = []

    if org_id is not None:
        where.append("a.org_id = %s")
        params.append(str(org_id))
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


@app.post("/api/agents", status_code=status.HTTP_201_CREATED)
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
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
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


@app.get("/api/agents/{agent_id}")
def get_agent(
    agent_id: UUID = Path(...),
    _: str = Depends(require_api_key),
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


@app.get("/api/agents/{agent_id}/latest")
def get_agent_latest(
    agent_id: UUID = Path(...),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.agents where id = %s", (str(agent_id),))
            agent_row = cur.fetchone()
            if not agent_row:
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)

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


@app.post("/api/golden-sets/upload", status_code=status.HTTP_201_CREATED)
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
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
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
    except Exception as exc:
        _error("GOLDEN_SET_UPLOAD_FAILED", f"Failed to upload golden set: {exc}", status.HTTP_400_BAD_REQUEST)

    return {
        "ok": True,
        "data": {
            "golden_set_id": str(golden_set_id),
            "name": payload.name,
            "case_count": len(case_ids),
            "case_ids": case_ids,
            "created_at": created_at.isoformat(),
        },
    }


@app.get("/api/agents/{agent_id}/golden-sets")
def list_agent_golden_sets(
    agent_id: UUID = Path(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.agents where id = %s", (str(agent_id),))
            if not cur.fetchone():
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)

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


@app.get("/api/agents/{agent_id}/patterns")
def list_agent_patterns(
    agent_id: UUID = Path(...),
    status_filter: Optional[IssueStatus] = Query(default=None, alias="status"),
    priority: Optional[IssuePriority] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.agents where id = %s", (str(agent_id),))
            if not cur.fetchone():
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)

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


@app.get("/api/agents/{agent_id}/readiness")
def get_agent_readiness(
    agent_id: UUID = Path(...),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from public.agents where id = %s", (str(agent_id),))
            if not cur.fetchone():
                _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)

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


@app.post("/api/agents/{agent_id}/patterns", status_code=status.HTTP_201_CREATED)
def create_agent_pattern(
    payload: IssuePatternCreateRequest,
    agent_id: UUID = Path(...),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
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


@app.post("/api/agents/{agent_id}/readiness", status_code=status.HTTP_201_CREATED)
def upsert_agent_readiness(
    payload: LaunchReadinessUpsertRequest,
    agent_id: UUID = Path(...),
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id, org_id from public.agents where id = %s", (str(agent_id),))
                agent_row = cur.fetchone()
                if not agent_row:
                    _error("AGENT_NOT_FOUND", f"Agent {agent_id} was not found.", status.HTTP_404_NOT_FOUND)
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
