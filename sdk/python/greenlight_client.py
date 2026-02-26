"""Generated client baseline for Greenlight API. Do not edit by hand."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Literal, NotRequired, Optional, TypeAlias, TypedDict, Union

ApiResponse: TypeAlias = Dict[str, Any]

class ActivityEventItem(TypedDict):
    id: str
    org_id: str
    agent_id: str
    event_type: str
    severity: Literal['info', 'warning', 'error']
    title: str
    details: Union[str, Any]
    metadata: Dict[str, Any]
    created_at: str

class AgentActivityData(TypedDict):
    agent_id: str
    items: List[ActivityEventItem]
    count: int
    total_count: int
    limit: int
    offset: int

class AgentActivityResponse(TypedDict):
    ok: bool
    data: AgentActivityData

class AgentCreateRequest(TypedDict):
    org_id: str
    name: str
    description: NotRequired[Union[str, Any]]
    agent_type: Literal['search_retrieval', 'document_generator', 'dashboard_assistant', 'triage_classification', 'analysis']
    status: NotRequired[Literal['backlog', 'build', 'testing', 'production', 'retired']]
    model: NotRequired[Union[str, Any]]
    api_endpoint: NotRequired[Union[str, Any]]
    owner_user_id: NotRequired[Union[str, Any]]
    eval_profile_id: NotRequired[Union[str, Any]]

class AgentDetailResponse(TypedDict):
    ok: bool
    data: AgentListItem

class AgentGoldenSetItem(TypedDict):
    id: str
    org_id: str
    agent_id: str
    name: str
    description: Union[str, Any]
    generation_method: str
    case_count: int
    created_at: str

class AgentGoldenSetListData(TypedDict):
    items: List[AgentGoldenSetItem]
    count: int
    limit: int
    offset: int

class AgentGoldenSetListResponse(TypedDict):
    ok: bool
    data: AgentGoldenSetListData

class AgentLatestCalibrationData(TypedDict):
    agent_id: str
    latest_calibration: Union[CalibrationRunData, Any]

class AgentLatestCalibrationResponse(TypedDict):
    ok: bool
    data: AgentLatestCalibrationData

class AgentLatestData(TypedDict):
    agent_id: str
    latest_run: Union[AgentLatestRunSummary, Any]

class AgentLatestResponse(TypedDict):
    ok: bool
    data: AgentLatestData

class AgentLatestRunSummary(TypedDict):
    run_id: str
    run_name: str
    run_type: str
    run_status: str
    created_at: str
    completed_at: Union[str, Any]
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

class AgentListData(TypedDict):
    items: List[AgentListItem]
    count: int
    limit: int
    offset: int

class AgentListItem(TypedDict):
    id: str
    org_id: str
    name: str
    description: Union[str, Any]
    agent_type: str
    status: str
    model: Union[str, Any]
    api_endpoint: Union[str, Any]
    owner_user_id: Union[str, Any]
    eval_profile_id: Union[str, Any]
    created_at: str
    updated_at: str

class AgentListResponse(TypedDict):
    ok: bool
    data: AgentListData

class AgentReadinessData(TypedDict):
    agent_id: str
    readiness: Union[LaunchReadinessData, Any]

class AgentReadinessResponse(TypedDict):
    ok: bool
    data: AgentReadinessData

class AgentSloPolicyData(TypedDict):
    agent_id: str
    slo_policy: Union[SloPolicyData, Any]

class AgentSloPolicyResponse(TypedDict):
    ok: bool
    data: AgentSloPolicyData

class AgentSloStatusData(TypedDict):
    agent_id: str
    slo_status: str
    open_violation_count: int
    recent_violations: List[SloViolationItem]

class AgentSloStatusResponse(TypedDict):
    ok: bool
    data: AgentSloStatusData

class ApiAuditLogItem(TypedDict):
    id: str
    request_id: str
    api_key_id: Union[str, Any]
    org_id: Union[str, Any]
    method: str
    path: str
    status_code: int
    latency_ms: int
    error_code: Union[str, Any]
    created_at: str

class ApiAuditLogListData(TypedDict):
    items: List[ApiAuditLogItem]
    count: int
    total_count: int
    limit: int
    offset: int

class ApiAuditLogListResponse(TypedDict):
    ok: bool
    data: ApiAuditLogListData

class ApiKeyCreateData(TypedDict):
    id: str
    org_id: Union[str, Any]
    name: str
    role: Literal['admin', 'member', 'viewer']
    key_prefix: str
    status: str
    expires_at: Union[str, Any]
    created_at: str
    api_key: str

class ApiKeyCreateRequest(TypedDict):
    name: str
    org_id: NotRequired[Union[str, Any]]
    expires_at: NotRequired[Union[str, Any]]
    role: NotRequired[Literal['admin', 'member', 'viewer']]

class ApiKeyCreateResponse(TypedDict):
    ok: bool
    data: ApiKeyCreateData

class ApiKeyListData(TypedDict):
    items: List[ApiKeyListItem]
    count: int
    total_count: int
    limit: int
    offset: int

class ApiKeyListItem(TypedDict):
    id: str
    org_id: Union[str, Any]
    name: str
    role: Literal['admin', 'member', 'viewer']
    key_prefix: str
    status: str
    expires_at: Union[str, Any]
    last_used_at: Union[str, Any]
    created_at: str

class ApiKeyListResponse(TypedDict):
    ok: bool
    data: ApiKeyListData

class ApiKeyRevokeData(TypedDict):
    id: str
    status: str

class ApiKeyRevokeResponse(TypedDict):
    ok: bool
    data: ApiKeyRevokeData

class CalibrationCaseComparison(TypedDict):
    case_id: NotRequired[Union[str, Any]]
    human_label: str
    judge_label: str
    is_clean: NotRequired[bool]
    notes: NotRequired[Union[str, Any]]

class CalibrationRunCreateRequest(TypedDict):
    org_id: str
    agent_id: str
    prompt_version: str
    judge_model: str
    per_case_comparison: List[CalibrationCaseComparison]

class CalibrationRunData(TypedDict):
    id: str
    org_id: str
    agent_id: str
    prompt_version: str
    judge_model: str
    overall_agreement: float
    clean_agreement: Union[float, Any]
    per_case_comparison: List[Dict[str, Any]]
    created_at: str

class CalibrationRunResponse(TypedDict):
    ok: bool
    data: CalibrationRunData

class EvalRunComparisonData(TypedDict):
    baseline_run_id: str
    candidate_run_id: str
    agent_id: str
    baseline_summary: EvalRunSummaryData
    candidate_summary: EvalRunSummaryData
    total_compared_cases: int
    regression_count: int
    regressions: List[EvalRunRegressionItem]
    answer_yes_rate_delta: float
    source_yes_rate_delta: float
    quality_good_rate_delta: float
    auto_pattern: NotRequired[Union[Dict[str, Any], Any]]
    notification: NotRequired[Union[Dict[str, Any], Any]]
    slo: NotRequired[Union[Dict[str, Any], Any]]
    remediation: NotRequired[Union[Dict[str, Any], Any]]

class EvalRunComparisonResponse(TypedDict):
    ok: bool
    data: EvalRunComparisonData

class EvalRunCreateData(TypedDict):
    run_id: str
    status: Literal['pending', 'running', 'completed', 'failed']
    created_at: str

class EvalRunCreateRequest(TypedDict):
    org_id: str
    agent_id: str
    golden_set_id: NotRequired[Union[str, Any]]
    name: str
    type: Literal['eval', 'regression', 'ab_comparison', 'calibration']
    config: NotRequired[Dict[str, Any]]
    design_context: NotRequired[Dict[str, Any]]

class EvalRunCreateResponse(TypedDict):
    ok: bool
    data: EvalRunCreateData

class EvalRunData(TypedDict):
    id: str
    org_id: str
    agent_id: str
    golden_set_id: Union[str, Any]
    name: str
    type: Literal['eval', 'regression', 'ab_comparison', 'calibration']
    status: Literal['pending', 'running', 'completed', 'failed']
    config: Dict[str, Any]
    design_context: Dict[str, Any]
    created_at: str
    started_at: Union[str, Any]
    completed_at: Union[str, Any]
    failure_reason: Union[str, Any]
    result_count: int
    results: NotRequired[Union[List[EvalRunResultItem], Any]]

class EvalRunExecuteData(TypedDict):
    run_id: str
    status: Literal['pending', 'running', 'completed', 'failed']
    case_count: int
    completed_at: str
    slo_status: NotRequired[Union[str, Any]]
    slo_violations: NotRequired[List[Dict[str, Any]]]

class EvalRunExecuteResponse(TypedDict):
    ok: bool
    data: EvalRunExecuteData

class EvalRunRegressionItem(TypedDict):
    case_id: str
    evaluation_mode: str
    metric: str
    baseline_value: str
    candidate_value: str

class EvalRunResponse(TypedDict):
    ok: bool
    data: EvalRunData

class EvalRunResultDetailItem(TypedDict):
    id: str
    eval_run_id: str
    case_id: Union[str, Any]
    agent_id: str
    evaluation_mode: str
    actual_response: Union[str, Any]
    actual_sources: Union[str, Any]
    answer_correct: Union[str, Any]
    answer_issues: List[str]
    source_correct: Union[str, Any]
    source_issues: List[str]
    response_quality: Union[str, Any]
    quality_issues: List[str]
    criteria_results: Union[Any]
    dimension_scores: Union[Dict[str, Any], Any]
    overall_score: Union[str, Any]
    reasoning: Union[str, Any]
    tester: Union[str, Any]
    search_mode: Union[str, Any]
    eval_date: Union[str, Any]
    notes: Union[str, Any]
    match_type: str
    matched_case_id: Union[str, Any]
    created_at: str

class EvalRunResultItem(TypedDict):
    id: str
    case_id: Union[str, Any]
    evaluation_mode: str
    match_type: str
    answer_correct: Union[str, Any]
    source_correct: Union[str, Any]
    response_quality: Union[str, Any]
    overall_score: Union[str, Any]
    created_at: str

class EvalRunResultsData(TypedDict):
    items: List[EvalRunResultDetailItem]
    count: int
    total_count: int
    limit: int
    offset: int

class EvalRunResultsResponse(TypedDict):
    ok: bool
    data: EvalRunResultsData

class EvalRunSummaryData(TypedDict):
    run_id: str
    status: Literal['pending', 'running', 'completed', 'failed']
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
    created_at: str
    completed_at: Union[str, Any]

class EvalRunSummaryResponse(TypedDict):
    ok: bool
    data: EvalRunSummaryData

class GoldenSetCaseUpload(TypedDict):
    input: str
    expected_output: NotRequired[Union[str, Any]]
    acceptable_sources: NotRequired[Union[str, Any]]
    evaluation_mode: NotRequired[Literal['answer', 'criteria']]
    evaluation_criteria: NotRequired[Union[Any]]
    difficulty: Literal['easy', 'medium', 'hard']
    capability: Literal['retrieval', 'synthesis', 'reasoning', 'extraction']
    scenario_type: Literal['straightforward', 'cross_reference', 'contradiction', 'version_conflict', 'authority', 'temporal', 'entity_ambiguity', 'dense_technical']
    domain: NotRequired[Union[str, Any]]
    verification_status: NotRequired[Literal['unverified', 'verified', 'disputed']]
    verified_by: NotRequired[Union[str, Any]]
    verified_date: NotRequired[Union[str, Any]]

class GoldenSetUploadData(TypedDict):
    golden_set_id: str
    name: str
    case_count: int
    case_ids: List[str]
    created_at: str

class GoldenSetUploadRequest(TypedDict):
    org_id: str
    agent_id: str
    name: str
    description: NotRequired[Union[str, Any]]
    generation_method: Literal['documents', 'prd_schema', 'data_fixtures', 'manual', 'clone', 'prod_logs']
    source_files: NotRequired[List[Any]]
    cases: List[GoldenSetCaseUpload]

class GoldenSetUploadResponse(TypedDict):
    ok: bool
    data: GoldenSetUploadData

class HTTPValidationError(TypedDict):
    detail: NotRequired[List[ValidationError]]

class HealthData(TypedDict):
    status: str

class HealthResponse(TypedDict):
    ok: bool
    data: HealthData

class IssuePatternCreateRequest(TypedDict):
    title: str
    primary_tag: str
    related_tags: NotRequired[List[str]]
    status: NotRequired[Literal['detected', 'diagnosed', 'assigned', 'in_progress', 'fixed', 'verifying', 'resolved', 'regressed', 'wont_fix']]
    priority: NotRequired[Literal['critical', 'high', 'medium', 'low']]
    root_cause: NotRequired[Union[str, Any]]
    root_cause_type: NotRequired[Union[Literal['retrieval', 'prompt', 'data', 'model', 'config'], Any]]
    suggested_fix: NotRequired[Union[str, Any]]
    owner: NotRequired[Union[str, Any]]
    linked_case_ids: NotRequired[List[str]]
    history: NotRequired[List[Any]]
    status_history: NotRequired[List[Any]]
    fix_notes: NotRequired[List[Any]]
    verification_result: NotRequired[Dict[str, Any]]
    resolved_date: NotRequired[Union[str, Any]]

class IssuePatternDataWithNotification(TypedDict):
    id: str
    org_id: str
    agent_id: str
    title: str
    primary_tag: str
    related_tags: List[str]
    status: Literal['detected', 'diagnosed', 'assigned', 'in_progress', 'fixed', 'verifying', 'resolved', 'regressed', 'wont_fix']
    priority: Literal['critical', 'high', 'medium', 'low']
    root_cause: Union[str, Any]
    root_cause_type: Union[str, Any]
    suggested_fix: Union[str, Any]
    owner: Union[str, Any]
    linked_case_ids: List[str]
    created_at: str
    updated_at: str
    resolved_date: Union[str, Any]
    notification: NotRequired[Union[Dict[str, Any], Any]]

class IssuePatternItem(TypedDict):
    id: str
    org_id: str
    agent_id: str
    title: str
    primary_tag: str
    related_tags: List[str]
    status: Literal['detected', 'diagnosed', 'assigned', 'in_progress', 'fixed', 'verifying', 'resolved', 'regressed', 'wont_fix']
    priority: Literal['critical', 'high', 'medium', 'low']
    root_cause: Union[str, Any]
    root_cause_type: Union[str, Any]
    suggested_fix: Union[str, Any]
    owner: Union[str, Any]
    linked_case_ids: List[str]
    created_at: str
    updated_at: str
    resolved_date: Union[str, Any]

class IssuePatternListData(TypedDict):
    items: List[IssuePatternItem]
    count: int
    limit: int
    offset: int

class IssuePatternListResponse(TypedDict):
    ok: bool
    data: IssuePatternListData

class IssuePatternResponse(TypedDict):
    ok: bool
    data: IssuePatternItem

class IssuePatternUpdateRequest(TypedDict):
    status: NotRequired[Union[Literal['detected', 'diagnosed', 'assigned', 'in_progress', 'fixed', 'verifying', 'resolved', 'regressed', 'wont_fix'], Any]]
    priority: NotRequired[Union[Literal['critical', 'high', 'medium', 'low'], Any]]
    root_cause: NotRequired[Union[str, Any]]
    root_cause_type: NotRequired[Union[Literal['retrieval', 'prompt', 'data', 'model', 'config'], Any]]
    suggested_fix: NotRequired[Union[str, Any]]
    owner: NotRequired[Union[str, Any]]
    related_tags: NotRequired[Union[List[str], Any]]
    linked_case_ids: NotRequired[Union[List[str], Any]]
    verification_result: NotRequired[Union[Dict[str, Any], Any]]
    resolved_date: NotRequired[Union[str, Any]]
    status_note: NotRequired[Union[str, Any]]
    force: NotRequired[bool]

class IssuePatternUpdateResponse(TypedDict):
    ok: bool
    data: IssuePatternDataWithNotification

class LaunchDecisionCreateData(TypedDict):
    agent_id: str
    decision: LaunchDecisionItem
    gate: Dict[str, Any]

class LaunchDecisionCreateRequest(TypedDict):
    decision: Literal['go', 'no_go', 'deferred']
    reason: NotRequired[Union[str, Any]]

class LaunchDecisionCreateResponse(TypedDict):
    ok: bool
    data: LaunchDecisionCreateData

class LaunchDecisionItem(TypedDict):
    id: str
    org_id: str
    agent_id: str
    decision: Literal['go', 'no_go', 'deferred']
    reason: Union[str, Any]
    blockers: List[Any]
    decided_by_api_key_id: Union[str, Any]
    decided_at: str
    notification: NotRequired[Union[Dict[str, Any], Any]]

class LaunchDecisionListData(TypedDict):
    agent_id: str
    items: List[LaunchDecisionItem]
    count: int
    limit: int
    offset: int

class LaunchDecisionListResponse(TypedDict):
    ok: bool
    data: LaunchDecisionListData

class LaunchGateData(TypedDict):
    agent_id: str
    can_launch: bool
    blockers: List[str]
    latest_run_id: Union[str, Any]
    latest_run_status: Union[str, Any]
    active_critical_issues: int
    open_slo_violations: int
    readiness_pending_items: int

class LaunchGateResponse(TypedDict):
    ok: bool
    data: LaunchGateData

class LaunchReadinessData(TypedDict):
    id: str
    org_id: str
    agent_id: str
    items: List[Any]
    thresholds: Dict[str, Any]
    decision: Union[str, Any]
    decision_notes: Union[str, Any]
    decision_date: Union[str, Any]
    created_at: str
    updated_at: str

class LaunchReadinessUpsertRequest(TypedDict):
    items: NotRequired[List[Any]]
    thresholds: NotRequired[Dict[str, Any]]
    decision: NotRequired[Union[Literal['go', 'no_go', 'deferred'], Any]]
    decision_notes: NotRequired[Union[str, Any]]
    decision_date: NotRequired[Union[str, Any]]

class PatternHistoryData(TypedDict):
    pattern_id: str
    agent_id: str
    status: str
    status_history: List[Any]
    updated_at: str

class PatternHistoryResponse(TypedDict):
    ok: bool
    data: PatternHistoryData

class SloPolicyData(TypedDict):
    id: str
    org_id: str
    agent_id: str
    min_answer_yes_rate: Union[float, Any]
    min_source_yes_rate: Union[float, Any]
    min_quality_good_rate: Union[float, Any]
    max_run_duration_ms: Union[int, Any]
    max_regression_count: Union[int, Any]
    created_at: str
    updated_at: str

class SloPolicyUpsertRequest(TypedDict):
    min_answer_yes_rate: NotRequired[Union[float, Any]]
    min_source_yes_rate: NotRequired[Union[float, Any]]
    min_quality_good_rate: NotRequired[Union[float, Any]]
    max_run_duration_ms: NotRequired[Union[int, Any]]
    max_regression_count: NotRequired[Union[int, Any]]

class SloViolationItem(TypedDict):
    id: str
    org_id: str
    agent_id: str
    policy_id: Union[str, Any]
    source: Literal['run_execute', 'run_compare']
    source_ref_id: Union[str, Any]
    metric: str
    actual_value: float
    expected_value: float
    comparator: str
    details: Dict[str, Any]
    created_at: str

class SloViolationResolveData(TypedDict):
    agent_id: str
    violation_id: str
    status: str

class SloViolationResolveResponse(TypedDict):
    ok: bool
    data: SloViolationResolveData

class ValidationError(TypedDict):
    loc: List[Union[str, int]]
    msg: str
    type: str

class GreenlightApiError(Exception):
    def __init__(
        self,
        *,
        status_code: Optional[int],
        code: str,
        message: str,
        request_id: Optional[str] = None,
        details: Optional[Any] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.request_id = request_id
        self.details = details

class GreenlightClient:
    def __init__(self, base_url: str, api_key: str, timeout: int = 30, max_retries: int = 3, backoff_base_seconds: float = 0.25, logger: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base_seconds = backoff_base_seconds
        self.logger = logger

    def _should_retry_status(self, status_code: int) -> bool:
        return status_code == 429 or 500 <= status_code < 600

    def _sleep_backoff(self, attempt: int) -> None:
        delay = self.backoff_base_seconds * (2 ** attempt)
        time.sleep(delay)

    def _build_api_error_from_http_error(self, exc: urllib.error.HTTPError) -> GreenlightApiError:
        request_id = exc.headers.get('X-Request-Id') if exc.headers else None
        raw = ''
        try:
            raw = exc.read().decode('utf-8', errors='replace')
        except Exception:
            raw = ''
        code = 'HTTP_ERROR'
        message = f'HTTP {exc.code}'
        details: Optional[Any] = None
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    err = parsed.get('error')
                    if isinstance(err, dict):
                        code = str(err.get('code') or code)
                        message = str(err.get('message') or message)
                        details = err.get('details')
            except Exception:
                message = raw[:500]
        return GreenlightApiError(status_code=exc.code, code=code, message=message, request_id=request_id, details=details)

    def _build_api_error_from_url_error(self, exc: urllib.error.URLError, request_id: Optional[str] = None) -> GreenlightApiError:
        reason = getattr(exc, 'reason', None)
        message = str(reason) if reason is not None else str(exc)
        return GreenlightApiError(status_code=None, code='NETWORK_ERROR', message=message, request_id=request_id)

    def _emit_log(self, event: Dict[str, Any], logger_override: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        log_fn = logger_override or self.logger
        if not log_fn:
            return
        try:
            log_fn(event)
        except Exception:
            pass

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
        backoff_base_seconds: Optional[float] = None,
        logger: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        if params:
            query = urllib.parse.urlencode(params, doseq=True)
            url = f"{url}?{query}"
        payload = None
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        }
        if body is not None:
            payload = json.dumps(body).encode('utf-8')
        effective_timeout = timeout if timeout is not None else self.timeout
        effective_retries = max_retries if max_retries is not None else self.max_retries
        effective_backoff = backoff_base_seconds if backoff_base_seconds is not None else self.backoff_base_seconds
        last_exc: Optional[Exception] = None
        last_request_id: Optional[str] = None
        attempts = max(effective_retries, 0) + 1
        for attempt in range(attempts):
            attempt_start = time.perf_counter()
            req = urllib.request.Request(url=url, data=payload, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
                    raw = resp.read().decode('utf-8')
                    parsed = json.loads(raw) if raw else {}
                    request_id = resp.headers.get('X-Request-Id') if resp.headers else None
                    last_request_id = request_id or last_request_id
                    self._emit_log({
                        'event': 'http_request',
                        'method': method,
                        'path': path,
                        'status_code': getattr(resp, 'status', None),
                        'duration_ms': round((time.perf_counter() - attempt_start) * 1000, 2),
                        'attempt': attempt + 1,
                        'request_id': request_id,
                        'has_body': body is not None,
                        'query_keys': sorted((params or {}).keys()),
                    }, logger_override=logger)
                    return parsed
            except urllib.error.HTTPError as exc:
                last_exc = exc
                api_err = self._build_api_error_from_http_error(exc)
                last_request_id = api_err.request_id or last_request_id
                self._emit_log({
                    'event': 'http_error',
                    'method': method,
                    'path': path,
                    'status_code': exc.code,
                    'duration_ms': round((time.perf_counter() - attempt_start) * 1000, 2),
                    'attempt': attempt + 1,
                    'request_id': api_err.request_id,
                    'error_code': api_err.code,
                    'has_body': body is not None,
                    'query_keys': sorted((params or {}).keys()),
                }, logger_override=logger)
                if attempt + 1 < attempts and self._should_retry_status(exc.code):
                    time.sleep(effective_backoff * (2 ** attempt))
                    continue
                raise api_err
            except urllib.error.URLError as exc:
                last_exc = exc
                api_err = self._build_api_error_from_url_error(exc, request_id=last_request_id)
                self._emit_log({
                    'event': 'network_error',
                    'method': method,
                    'path': path,
                    'status_code': None,
                    'duration_ms': round((time.perf_counter() - attempt_start) * 1000, 2),
                    'attempt': attempt + 1,
                    'request_id': api_err.request_id,
                    'error_code': api_err.code,
                    'has_body': body is not None,
                    'query_keys': sorted((params or {}).keys()),
                }, logger_override=logger)
                if attempt + 1 < attempts:
                    time.sleep(effective_backoff * (2 ** attempt))
                    continue
                raise api_err
        if last_exc:
            if isinstance(last_exc, urllib.error.HTTPError):
                raise self._build_api_error_from_http_error(last_exc)
            if isinstance(last_exc, urllib.error.URLError):
                raise self._build_api_error_from_url_error(last_exc, request_id=last_request_id)
            raise GreenlightApiError(status_code=None, code='REQUEST_FAILED', message=str(last_exc), request_id=last_request_id)
        raise RuntimeError('Request failed without explicit exception')

    def get_agents(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentListResponse:
        return self._request('GET', '/api/agents', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentDetailResponse:
        path = f"/api/agents/{agent_id}"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_activity(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentActivityResponse:
        path = f"/api/agents/{agent_id}/activity"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_calibration_latest(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentLatestCalibrationResponse:
        path = f"/api/agents/{agent_id}/calibration/latest"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_golden_sets(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentGoldenSetListResponse:
        path = f"/api/agents/{agent_id}/golden-sets"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_latest(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentLatestResponse:
        path = f"/api/agents/{agent_id}/latest"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_launch_decisions(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> LaunchDecisionListResponse:
        path = f"/api/agents/{agent_id}/launch-decisions"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_launch_gate(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> LaunchGateResponse:
        path = f"/api/agents/{agent_id}/launch-gate"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_patterns(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> IssuePatternListResponse:
        path = f"/api/agents/{agent_id}/patterns"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_patterns_by_pattern_id_history(self, *, agent_id: str, pattern_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> PatternHistoryResponse:
        path = f"/api/agents/{agent_id}/patterns/{pattern_id}/history"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_readiness(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentReadinessResponse:
        path = f"/api/agents/{agent_id}/readiness"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_slo_policy(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentSloPolicyResponse:
        path = f"/api/agents/{agent_id}/slo-policy"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_by_agent_id_slo_status(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentSloStatusResponse:
        path = f"/api/agents/{agent_id}/slo-status"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_calibration_runs_by_calibration_id(self, *, calibration_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> CalibrationRunResponse:
        path = f"/api/calibration/runs/{calibration_id}"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_eval_compare(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> EvalRunComparisonResponse:
        return self._request('GET', '/api/eval/compare', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_eval_runs_by_run_id(self, *, run_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> EvalRunResponse:
        path = f"/api/eval/runs/{run_id}"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_eval_runs_by_run_id_results(self, *, run_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> EvalRunResultsResponse:
        path = f"/api/eval/runs/{run_id}/results"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_eval_runs_by_run_id_summary(self, *, run_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> EvalRunSummaryResponse:
        path = f"/api/eval/runs/{run_id}/summary"
        return self._request('GET', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_system_api_keys(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> ApiKeyListResponse:
        return self._request('GET', '/api/system/api-keys', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_system_audit_logs(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> ApiAuditLogListResponse:
        return self._request('GET', '/api/system/audit-logs', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def patch_agents_by_agent_id_patterns_by_pattern_id(self, *, agent_id: str, pattern_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[IssuePatternUpdateRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> IssuePatternUpdateResponse:
        path = f"/api/agents/{agent_id}/patterns/{pattern_id}"
        return self._request('PATCH', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def patch_agents_by_agent_id_slo_violations_by_violation_id_resolve(self, *, agent_id: str, violation_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> SloViolationResolveResponse:
        path = f"/api/agents/{agent_id}/slo-violations/{violation_id}/resolve"
        return self._request('PATCH', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_agents(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[AgentCreateRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentDetailResponse:
        return self._request('POST', '/api/agents', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_agents_by_agent_id_launch_decision(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[LaunchDecisionCreateRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> LaunchDecisionCreateResponse:
        path = f"/api/agents/{agent_id}/launch-decision"
        return self._request('POST', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_agents_by_agent_id_patterns(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[IssuePatternCreateRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> IssuePatternResponse:
        path = f"/api/agents/{agent_id}/patterns"
        return self._request('POST', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_agents_by_agent_id_readiness(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[LaunchReadinessUpsertRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentReadinessResponse:
        path = f"/api/agents/{agent_id}/readiness"
        return self._request('POST', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_agents_by_agent_id_slo_policy(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[SloPolicyUpsertRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> AgentSloPolicyResponse:
        path = f"/api/agents/{agent_id}/slo-policy"
        return self._request('POST', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_calibration_runs(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[CalibrationRunCreateRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> CalibrationRunResponse:
        return self._request('POST', '/api/calibration/runs', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_eval_runs(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[EvalRunCreateRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> EvalRunCreateResponse:
        return self._request('POST', '/api/eval/runs', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_eval_runs_by_run_id_execute(self, *, run_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> EvalRunExecuteResponse:
        path = f"/api/eval/runs/{run_id}/execute"
        return self._request('POST', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_golden_sets_upload(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[GoldenSetUploadRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> GoldenSetUploadResponse:
        return self._request('POST', '/api/golden-sets/upload', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_system_api_keys(self, *, params: Optional[Dict[str, Any]] = None, body: Optional[ApiKeyCreateRequest] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> ApiKeyCreateResponse:
        return self._request('POST', '/api/system/api-keys', params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def post_system_api_keys_by_key_id_revoke(self, *, key_id: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> ApiKeyRevokeResponse:
        path = f"/api/system/api-keys/{key_id}/revoke"
        return self._request('POST', path, params=params, body=body, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)

    def get_agents_all(self, *, params: Optional[Dict[str, Any]] = None, page_size: int = 200, max_pages: int = 100, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[AgentListItem]:
        items: List[AgentListItem] = []
        base_params = dict(params or {})
        offset = int(base_params.get('offset', 0) or 0)
        for _ in range(max_pages):
            page_params = dict(base_params)
            page_params['limit'] = page_size
            page_params['offset'] = offset
            page = self.get_agents(params=page_params, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)
            data = page.get('data', {}) if isinstance(page, dict) else {}
            page_items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                break
            items.extend(page_items)
            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)
            try:
                page_count = int(raw_count)
            except Exception:
                page_count = len(page_items)
            if page_count <= 0 or page_count < page_size:
                break
            offset += page_count
        return items

    def get_agents_by_agent_id_activity_all(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, page_size: int = 200, max_pages: int = 100, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[ActivityEventItem]:
        items: List[ActivityEventItem] = []
        base_params = dict(params or {})
        offset = int(base_params.get('offset', 0) or 0)
        for _ in range(max_pages):
            page_params = dict(base_params)
            page_params['limit'] = page_size
            page_params['offset'] = offset
            page = self.get_agents_by_agent_id_activity(agent_id=agent_id, params=page_params, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)
            data = page.get('data', {}) if isinstance(page, dict) else {}
            page_items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                break
            items.extend(page_items)
            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)
            try:
                page_count = int(raw_count)
            except Exception:
                page_count = len(page_items)
            if page_count <= 0 or page_count < page_size:
                break
            offset += page_count
        return items

    def get_agents_by_agent_id_golden_sets_all(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, page_size: int = 200, max_pages: int = 100, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[AgentGoldenSetItem]:
        items: List[AgentGoldenSetItem] = []
        base_params = dict(params or {})
        offset = int(base_params.get('offset', 0) or 0)
        for _ in range(max_pages):
            page_params = dict(base_params)
            page_params['limit'] = page_size
            page_params['offset'] = offset
            page = self.get_agents_by_agent_id_golden_sets(agent_id=agent_id, params=page_params, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)
            data = page.get('data', {}) if isinstance(page, dict) else {}
            page_items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                break
            items.extend(page_items)
            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)
            try:
                page_count = int(raw_count)
            except Exception:
                page_count = len(page_items)
            if page_count <= 0 or page_count < page_size:
                break
            offset += page_count
        return items

    def get_agents_by_agent_id_launch_decisions_all(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, page_size: int = 200, max_pages: int = 100, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[LaunchDecisionItem]:
        items: List[LaunchDecisionItem] = []
        base_params = dict(params or {})
        offset = int(base_params.get('offset', 0) or 0)
        for _ in range(max_pages):
            page_params = dict(base_params)
            page_params['limit'] = page_size
            page_params['offset'] = offset
            page = self.get_agents_by_agent_id_launch_decisions(agent_id=agent_id, params=page_params, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)
            data = page.get('data', {}) if isinstance(page, dict) else {}
            page_items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                break
            items.extend(page_items)
            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)
            try:
                page_count = int(raw_count)
            except Exception:
                page_count = len(page_items)
            if page_count <= 0 or page_count < page_size:
                break
            offset += page_count
        return items

    def get_agents_by_agent_id_patterns_all(self, *, agent_id: str, params: Optional[Dict[str, Any]] = None, page_size: int = 200, max_pages: int = 100, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[IssuePatternItem]:
        items: List[IssuePatternItem] = []
        base_params = dict(params or {})
        offset = int(base_params.get('offset', 0) or 0)
        for _ in range(max_pages):
            page_params = dict(base_params)
            page_params['limit'] = page_size
            page_params['offset'] = offset
            page = self.get_agents_by_agent_id_patterns(agent_id=agent_id, params=page_params, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)
            data = page.get('data', {}) if isinstance(page, dict) else {}
            page_items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                break
            items.extend(page_items)
            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)
            try:
                page_count = int(raw_count)
            except Exception:
                page_count = len(page_items)
            if page_count <= 0 or page_count < page_size:
                break
            offset += page_count
        return items

    def get_eval_runs_by_run_id_results_all(self, *, run_id: str, params: Optional[Dict[str, Any]] = None, page_size: int = 200, max_pages: int = 100, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[EvalRunResultDetailItem]:
        items: List[EvalRunResultDetailItem] = []
        base_params = dict(params or {})
        offset = int(base_params.get('offset', 0) or 0)
        for _ in range(max_pages):
            page_params = dict(base_params)
            page_params['limit'] = page_size
            page_params['offset'] = offset
            page = self.get_eval_runs_by_run_id_results(run_id=run_id, params=page_params, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)
            data = page.get('data', {}) if isinstance(page, dict) else {}
            page_items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                break
            items.extend(page_items)
            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)
            try:
                page_count = int(raw_count)
            except Exception:
                page_count = len(page_items)
            if page_count <= 0 or page_count < page_size:
                break
            offset += page_count
        return items

    def get_system_api_keys_all(self, *, params: Optional[Dict[str, Any]] = None, page_size: int = 200, max_pages: int = 100, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[ApiKeyListItem]:
        items: List[ApiKeyListItem] = []
        base_params = dict(params or {})
        offset = int(base_params.get('offset', 0) or 0)
        for _ in range(max_pages):
            page_params = dict(base_params)
            page_params['limit'] = page_size
            page_params['offset'] = offset
            page = self.get_system_api_keys(params=page_params, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)
            data = page.get('data', {}) if isinstance(page, dict) else {}
            page_items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                break
            items.extend(page_items)
            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)
            try:
                page_count = int(raw_count)
            except Exception:
                page_count = len(page_items)
            if page_count <= 0 or page_count < page_size:
                break
            offset += page_count
        return items

    def get_system_audit_logs_all(self, *, params: Optional[Dict[str, Any]] = None, page_size: int = 200, max_pages: int = 100, timeout: Optional[int] = None, max_retries: Optional[int] = None, backoff_base_seconds: Optional[float] = None, logger: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[ApiAuditLogItem]:
        items: List[ApiAuditLogItem] = []
        base_params = dict(params or {})
        offset = int(base_params.get('offset', 0) or 0)
        for _ in range(max_pages):
            page_params = dict(base_params)
            page_params['limit'] = page_size
            page_params['offset'] = offset
            page = self.get_system_audit_logs(params=page_params, timeout=timeout, max_retries=max_retries, backoff_base_seconds=backoff_base_seconds, logger=logger)
            data = page.get('data', {}) if isinstance(page, dict) else {}
            page_items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                break
            items.extend(page_items)
            raw_count = data.get('count', len(page_items)) if isinstance(data, dict) else len(page_items)
            try:
                page_count = int(raw_count)
            except Exception:
                page_count = len(page_items)
            if page_count <= 0 or page_count < page_size:
                break
            offset += page_count
        return items
