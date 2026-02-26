// Generated client baseline for Greenlight API. Do not edit by hand.

export type QueryParams = Record<string, string | number | boolean | null | undefined>;
export type RequestLogEvent = {
  event: 'http_request' | 'http_error' | 'network_error';
  method: string;
  path: string;
  statusCode?: number;
  durationMs: number;
  attempt: number;
  requestId?: string;
  errorCode?: string;
  hasBody: boolean;
  queryKeys: string[];
};
export type RequestLogger = (event: RequestLogEvent) => void | Promise<void>;
export interface RequestOptions { timeoutMs?: number; maxRetries?: number; backoffBaseMs?: number; logger?: RequestLogger }
export class GreenlightApiError extends Error {
  constructor(
    public readonly statusCode: number | undefined,
    public readonly code: string,
    public readonly requestId: string | undefined,
    public readonly details: unknown,
    message: string,
  ) {
    super(message);
    this.name = 'GreenlightApiError';
  }
}

export type ApiResponse<T = unknown> = {
  ok: boolean;
  data?: T;
  error?: { code?: string; message?: string; details?: unknown };
};

export interface ActivityEventItem {
  id: string;
  org_id: string;
  agent_id: string;
  event_type: string;
  severity: "info" | "warning" | "error";
  title: string;
  details: string | unknown;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface AgentActivityData {
  agent_id: string;
  items: ActivityEventItem[];
  count: number;
  total_count: number;
  limit: number;
  offset: number;
}

export interface AgentActivityResponse {
  ok: boolean;
  data: AgentActivityData;
}

export interface AgentCreateRequest {
  org_id: string;
  name: string;
  description?: string | unknown;
  agent_type: "search_retrieval" | "document_generator" | "dashboard_assistant" | "triage_classification" | "analysis";
  status?: "backlog" | "build" | "testing" | "production" | "retired";
  model?: string | unknown;
  api_endpoint?: string | unknown;
  owner_user_id?: string | unknown;
  eval_profile_id?: string | unknown;
}

export interface AgentDetailResponse {
  ok: boolean;
  data: AgentListItem;
}

export interface AgentGoldenSetItem {
  id: string;
  org_id: string;
  agent_id: string;
  name: string;
  description: string | unknown;
  generation_method: string;
  case_count: number;
  created_at: string;
}

export interface AgentGoldenSetListData {
  items: AgentGoldenSetItem[];
  count: number;
  limit: number;
  offset: number;
}

export interface AgentGoldenSetListResponse {
  ok: boolean;
  data: AgentGoldenSetListData;
}

export interface AgentLatestCalibrationData {
  agent_id: string;
  latest_calibration: CalibrationRunData | unknown;
}

export interface AgentLatestCalibrationResponse {
  ok: boolean;
  data: AgentLatestCalibrationData;
}

export interface AgentLatestData {
  agent_id: string;
  latest_run: AgentLatestRunSummary | unknown;
}

export interface AgentLatestResponse {
  ok: boolean;
  data: AgentLatestData;
}

export interface AgentLatestRunSummary {
  run_id: string;
  run_name: string;
  run_type: string;
  run_status: string;
  created_at: string;
  completed_at: string | unknown;
  total_results: number;
  answer_yes_count: number;
  answer_partially_count: number;
  answer_no_count: number;
  source_yes_count: number;
  source_partially_count: number;
  source_no_count: number;
  quality_good_count: number;
  quality_average_count: number;
  quality_not_good_count: number;
  answer_yes_rate: number;
  source_yes_rate: number;
  quality_good_rate: number;
}

export interface AgentListData {
  items: AgentListItem[];
  count: number;
  limit: number;
  offset: number;
}

export interface AgentListItem {
  id: string;
  org_id: string;
  name: string;
  description: string | unknown;
  agent_type: string;
  status: string;
  model: string | unknown;
  api_endpoint: string | unknown;
  owner_user_id: string | unknown;
  eval_profile_id: string | unknown;
  created_at: string;
  updated_at: string;
}

export interface AgentListResponse {
  ok: boolean;
  data: AgentListData;
}

export interface AgentReadinessData {
  agent_id: string;
  readiness: LaunchReadinessData | unknown;
}

export interface AgentReadinessResponse {
  ok: boolean;
  data: AgentReadinessData;
}

export interface AgentSloPolicyData {
  agent_id: string;
  slo_policy: SloPolicyData | unknown;
}

export interface AgentSloPolicyResponse {
  ok: boolean;
  data: AgentSloPolicyData;
}

export interface AgentSloStatusData {
  agent_id: string;
  slo_status: string;
  open_violation_count: number;
  recent_violations: SloViolationItem[];
}

export interface AgentSloStatusResponse {
  ok: boolean;
  data: AgentSloStatusData;
}

export interface ApiAuditLogItem {
  id: string;
  request_id: string;
  api_key_id: string | unknown;
  org_id: string | unknown;
  method: string;
  path: string;
  status_code: number;
  latency_ms: number;
  error_code: string | unknown;
  created_at: string;
}

export interface ApiAuditLogListData {
  items: ApiAuditLogItem[];
  count: number;
  total_count: number;
  limit: number;
  offset: number;
}

export interface ApiAuditLogListResponse {
  ok: boolean;
  data: ApiAuditLogListData;
}

export interface ApiKeyCreateData {
  id: string;
  org_id: string | unknown;
  name: string;
  role: "admin" | "member" | "viewer";
  key_prefix: string;
  status: string;
  expires_at: string | unknown;
  created_at: string;
  api_key: string;
}

export interface ApiKeyCreateRequest {
  name: string;
  org_id?: string | unknown;
  expires_at?: string | unknown;
  role?: "admin" | "member" | "viewer";
}

export interface ApiKeyCreateResponse {
  ok: boolean;
  data: ApiKeyCreateData;
}

export interface ApiKeyListData {
  items: ApiKeyListItem[];
  count: number;
  total_count: number;
  limit: number;
  offset: number;
}

export interface ApiKeyListItem {
  id: string;
  org_id: string | unknown;
  name: string;
  role: "admin" | "member" | "viewer";
  key_prefix: string;
  status: string;
  expires_at: string | unknown;
  last_used_at: string | unknown;
  created_at: string;
}

export interface ApiKeyListResponse {
  ok: boolean;
  data: ApiKeyListData;
}

export interface ApiKeyRevokeData {
  id: string;
  status: string;
}

export interface ApiKeyRevokeResponse {
  ok: boolean;
  data: ApiKeyRevokeData;
}

export interface CalibrationCaseComparison {
  case_id?: string | unknown;
  human_label: string;
  judge_label: string;
  is_clean?: boolean;
  notes?: string | unknown;
}

export interface CalibrationRunCreateRequest {
  org_id: string;
  agent_id: string;
  prompt_version: string;
  judge_model: string;
  per_case_comparison: CalibrationCaseComparison[];
}

export interface CalibrationRunData {
  id: string;
  org_id: string;
  agent_id: string;
  prompt_version: string;
  judge_model: string;
  overall_agreement: number;
  clean_agreement: number | unknown;
  per_case_comparison: Record<string, unknown>[];
  created_at: string;
}

export interface CalibrationRunResponse {
  ok: boolean;
  data: CalibrationRunData;
}

export interface EvalRunComparisonData {
  baseline_run_id: string;
  candidate_run_id: string;
  agent_id: string;
  baseline_summary: EvalRunSummaryData;
  candidate_summary: EvalRunSummaryData;
  total_compared_cases: number;
  regression_count: number;
  regressions: EvalRunRegressionItem[];
  answer_yes_rate_delta: number;
  source_yes_rate_delta: number;
  quality_good_rate_delta: number;
  auto_pattern?: Record<string, unknown> | unknown;
  notification?: Record<string, unknown> | unknown;
  slo?: Record<string, unknown> | unknown;
  remediation?: Record<string, unknown> | unknown;
}

export interface EvalRunComparisonResponse {
  ok: boolean;
  data: EvalRunComparisonData;
}

export interface EvalRunCreateData {
  run_id: string;
  status: "pending" | "running" | "completed" | "failed";
  created_at: string;
}

export interface EvalRunCreateRequest {
  org_id: string;
  agent_id: string;
  golden_set_id?: string | unknown;
  name: string;
  type: "eval" | "regression" | "ab_comparison" | "calibration";
  config?: Record<string, unknown>;
  design_context?: Record<string, unknown>;
}

export interface EvalRunCreateResponse {
  ok: boolean;
  data: EvalRunCreateData;
}

export interface EvalRunData {
  id: string;
  org_id: string;
  agent_id: string;
  golden_set_id: string | unknown;
  name: string;
  type: "eval" | "regression" | "ab_comparison" | "calibration";
  status: "pending" | "running" | "completed" | "failed";
  config: Record<string, unknown>;
  design_context: Record<string, unknown>;
  created_at: string;
  started_at: string | unknown;
  completed_at: string | unknown;
  failure_reason: string | unknown;
  result_count: number;
  results?: EvalRunResultItem[] | unknown;
}

export interface EvalRunExecuteData {
  run_id: string;
  status: "pending" | "running" | "completed" | "failed";
  case_count: number;
  completed_at: string;
  slo_status?: string | unknown;
  slo_violations?: Record<string, unknown>[];
}

export interface EvalRunExecuteResponse {
  ok: boolean;
  data: EvalRunExecuteData;
}

export interface EvalRunRegressionItem {
  case_id: string;
  evaluation_mode: string;
  metric: string;
  baseline_value: string;
  candidate_value: string;
}

export interface EvalRunResponse {
  ok: boolean;
  data: EvalRunData;
}

export interface EvalRunResultDetailItem {
  id: string;
  eval_run_id: string;
  case_id: string | unknown;
  agent_id: string;
  evaluation_mode: string;
  actual_response: string | unknown;
  actual_sources: string | unknown;
  answer_correct: string | unknown;
  answer_issues: string[];
  source_correct: string | unknown;
  source_issues: string[];
  response_quality: string | unknown;
  quality_issues: string[];
  criteria_results: unknown;
  dimension_scores: Record<string, unknown> | unknown;
  overall_score: string | unknown;
  reasoning: string | unknown;
  tester: string | unknown;
  search_mode: string | unknown;
  eval_date: string | unknown;
  notes: string | unknown;
  match_type: string;
  matched_case_id: string | unknown;
  created_at: string;
}

export interface EvalRunResultItem {
  id: string;
  case_id: string | unknown;
  evaluation_mode: string;
  match_type: string;
  answer_correct: string | unknown;
  source_correct: string | unknown;
  response_quality: string | unknown;
  overall_score: string | unknown;
  created_at: string;
}

export interface EvalRunResultsData {
  items: EvalRunResultDetailItem[];
  count: number;
  total_count: number;
  limit: number;
  offset: number;
}

export interface EvalRunResultsResponse {
  ok: boolean;
  data: EvalRunResultsData;
}

export interface EvalRunSummaryData {
  run_id: string;
  status: "pending" | "running" | "completed" | "failed";
  total_results: number;
  answer_yes_count: number;
  answer_partially_count: number;
  answer_no_count: number;
  source_yes_count: number;
  source_partially_count: number;
  source_no_count: number;
  quality_good_count: number;
  quality_average_count: number;
  quality_not_good_count: number;
  answer_yes_rate: number;
  source_yes_rate: number;
  quality_good_rate: number;
  created_at: string;
  completed_at: string | unknown;
}

export interface EvalRunSummaryResponse {
  ok: boolean;
  data: EvalRunSummaryData;
}

export interface GoldenSetCaseUpload {
  input: string;
  expected_output?: string | unknown;
  acceptable_sources?: string | unknown;
  evaluation_mode?: "answer" | "criteria";
  evaluation_criteria?: unknown;
  difficulty: "easy" | "medium" | "hard";
  capability: "retrieval" | "synthesis" | "reasoning" | "extraction";
  scenario_type: "straightforward" | "cross_reference" | "contradiction" | "version_conflict" | "authority" | "temporal" | "entity_ambiguity" | "dense_technical";
  domain?: string | unknown;
  verification_status?: "unverified" | "verified" | "disputed";
  verified_by?: string | unknown;
  verified_date?: string | unknown;
}

export interface GoldenSetUploadData {
  golden_set_id: string;
  name: string;
  case_count: number;
  case_ids: string[];
  created_at: string;
}

export interface GoldenSetUploadRequest {
  org_id: string;
  agent_id: string;
  name: string;
  description?: string | unknown;
  generation_method: "documents" | "prd_schema" | "data_fixtures" | "manual" | "clone" | "prod_logs";
  source_files?: unknown[];
  cases: GoldenSetCaseUpload[];
}

export interface GoldenSetUploadResponse {
  ok: boolean;
  data: GoldenSetUploadData;
}

export interface HTTPValidationError {
  detail?: ValidationError[];
}

export interface HealthData {
  status: string;
}

export interface HealthResponse {
  ok: boolean;
  data: HealthData;
}

export interface IssuePatternCreateRequest {
  title: string;
  primary_tag: string;
  related_tags?: string[];
  status?: "detected" | "diagnosed" | "assigned" | "in_progress" | "fixed" | "verifying" | "resolved" | "regressed" | "wont_fix";
  priority?: "critical" | "high" | "medium" | "low";
  root_cause?: string | unknown;
  root_cause_type?: "retrieval" | "prompt" | "data" | "model" | "config" | unknown;
  suggested_fix?: string | unknown;
  owner?: string | unknown;
  linked_case_ids?: string[];
  history?: unknown[];
  status_history?: unknown[];
  fix_notes?: unknown[];
  verification_result?: Record<string, unknown>;
  resolved_date?: string | unknown;
}

export interface IssuePatternDataWithNotification {
  id: string;
  org_id: string;
  agent_id: string;
  title: string;
  primary_tag: string;
  related_tags: string[];
  status: "detected" | "diagnosed" | "assigned" | "in_progress" | "fixed" | "verifying" | "resolved" | "regressed" | "wont_fix";
  priority: "critical" | "high" | "medium" | "low";
  root_cause: string | unknown;
  root_cause_type: string | unknown;
  suggested_fix: string | unknown;
  owner: string | unknown;
  linked_case_ids: string[];
  created_at: string;
  updated_at: string;
  resolved_date: string | unknown;
  notification?: Record<string, unknown> | unknown;
}

export interface IssuePatternItem {
  id: string;
  org_id: string;
  agent_id: string;
  title: string;
  primary_tag: string;
  related_tags: string[];
  status: "detected" | "diagnosed" | "assigned" | "in_progress" | "fixed" | "verifying" | "resolved" | "regressed" | "wont_fix";
  priority: "critical" | "high" | "medium" | "low";
  root_cause: string | unknown;
  root_cause_type: string | unknown;
  suggested_fix: string | unknown;
  owner: string | unknown;
  linked_case_ids: string[];
  created_at: string;
  updated_at: string;
  resolved_date: string | unknown;
}

export interface IssuePatternListData {
  items: IssuePatternItem[];
  count: number;
  limit: number;
  offset: number;
}

export interface IssuePatternListResponse {
  ok: boolean;
  data: IssuePatternListData;
}

export interface IssuePatternResponse {
  ok: boolean;
  data: IssuePatternItem;
}

export interface IssuePatternUpdateRequest {
  status?: "detected" | "diagnosed" | "assigned" | "in_progress" | "fixed" | "verifying" | "resolved" | "regressed" | "wont_fix" | unknown;
  priority?: "critical" | "high" | "medium" | "low" | unknown;
  root_cause?: string | unknown;
  root_cause_type?: "retrieval" | "prompt" | "data" | "model" | "config" | unknown;
  suggested_fix?: string | unknown;
  owner?: string | unknown;
  related_tags?: string[] | unknown;
  linked_case_ids?: string[] | unknown;
  verification_result?: Record<string, unknown> | unknown;
  resolved_date?: string | unknown;
  status_note?: string | unknown;
  force?: boolean;
}

export interface IssuePatternUpdateResponse {
  ok: boolean;
  data: IssuePatternDataWithNotification;
}

export interface LaunchDecisionCreateData {
  agent_id: string;
  decision: LaunchDecisionItem;
  gate: Record<string, unknown>;
}

export interface LaunchDecisionCreateRequest {
  decision: "go" | "no_go" | "deferred";
  reason?: string | unknown;
}

export interface LaunchDecisionCreateResponse {
  ok: boolean;
  data: LaunchDecisionCreateData;
}

export interface LaunchDecisionItem {
  id: string;
  org_id: string;
  agent_id: string;
  decision: "go" | "no_go" | "deferred";
  reason: string | unknown;
  blockers: unknown[];
  decided_by_api_key_id: string | unknown;
  decided_at: string;
  notification?: Record<string, unknown> | unknown;
}

export interface LaunchDecisionListData {
  agent_id: string;
  items: LaunchDecisionItem[];
  count: number;
  limit: number;
  offset: number;
}

export interface LaunchDecisionListResponse {
  ok: boolean;
  data: LaunchDecisionListData;
}

export interface LaunchGateData {
  agent_id: string;
  can_launch: boolean;
  blockers: string[];
  latest_run_id: string | unknown;
  latest_run_status: string | unknown;
  active_critical_issues: number;
  open_slo_violations: number;
  readiness_pending_items: number;
}

export interface LaunchGateResponse {
  ok: boolean;
  data: LaunchGateData;
}

export interface LaunchReadinessData {
  id: string;
  org_id: string;
  agent_id: string;
  items: unknown[];
  thresholds: Record<string, unknown>;
  decision: string | unknown;
  decision_notes: string | unknown;
  decision_date: string | unknown;
  created_at: string;
  updated_at: string;
}

export interface LaunchReadinessUpsertRequest {
  items?: unknown[];
  thresholds?: Record<string, unknown>;
  decision?: "go" | "no_go" | "deferred" | unknown;
  decision_notes?: string | unknown;
  decision_date?: string | unknown;
}

export interface PatternHistoryData {
  pattern_id: string;
  agent_id: string;
  status: string;
  status_history: unknown[];
  updated_at: string;
}

export interface PatternHistoryResponse {
  ok: boolean;
  data: PatternHistoryData;
}

export interface SloPolicyData {
  id: string;
  org_id: string;
  agent_id: string;
  min_answer_yes_rate: number | unknown;
  min_source_yes_rate: number | unknown;
  min_quality_good_rate: number | unknown;
  max_run_duration_ms: number | unknown;
  max_regression_count: number | unknown;
  created_at: string;
  updated_at: string;
}

export interface SloPolicyUpsertRequest {
  min_answer_yes_rate?: number | unknown;
  min_source_yes_rate?: number | unknown;
  min_quality_good_rate?: number | unknown;
  max_run_duration_ms?: number | unknown;
  max_regression_count?: number | unknown;
}

export interface SloViolationItem {
  id: string;
  org_id: string;
  agent_id: string;
  policy_id: string | unknown;
  source: "run_execute" | "run_compare";
  source_ref_id: string | unknown;
  metric: string;
  actual_value: number;
  expected_value: number;
  comparator: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface SloViolationResolveData {
  agent_id: string;
  violation_id: string;
  status: string;
}

export interface SloViolationResolveResponse {
  ok: boolean;
  data: SloViolationResolveData;
}

export interface ValidationError {
  loc: (string | number)[];
  msg: string;
  type: string;
}

export class GreenlightClient {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly maxRetries = 3,
    private readonly backoffBaseMs = 250,
    private readonly timeoutMs = 30000,
    private readonly logger?: RequestLogger,
  ) {}

  private shouldRetryStatus(status: number): boolean {
    return status === 429 || (status >= 500 && status < 600);
  }

  private async sleepBackoff(attempt: number): Promise<void> {
    const delay = this.backoffBaseMs * (2 ** attempt);
    await new Promise((resolve) => setTimeout(resolve, delay));
  }

  private async request<T>(method: string, path: string, query?: QueryParams, body?: unknown, requestOptions?: RequestOptions): Promise<T> {
    const url = new URL(`${this.baseUrl.replace(/\/$/, "")}${path}`);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }
    const effectiveRetries = requestOptions?.maxRetries ?? this.maxRetries;
    const effectiveBackoff = requestOptions?.backoffBaseMs ?? this.backoffBaseMs;
    const effectiveTimeout = requestOptions?.timeoutMs ?? this.timeoutMs;
    const logger = requestOptions?.logger ?? this.logger;
    const queryKeys = Object.keys(query ?? {}).sort();
    const hasBody = body !== undefined;
    const attempts = Math.max(effectiveRetries, 0) + 1;
    let lastError: unknown = undefined;
    let lastRequestId: string | undefined = undefined;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        const attemptStart = performance.now();
        const controller = new AbortController();
        const timeoutHandle = setTimeout(() => controller.abort(), effectiveTimeout);
        const resp = await fetch(url.toString(), {
          method,
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "Content-Type": "application/json",
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
        clearTimeout(timeoutHandle);
        if (!resp.ok) {
          const txt = await resp.text();
          let code = 'HTTP_ERROR';
          let message = `HTTP ${resp.status}`;
          let details: unknown = undefined;
          try {
            const parsed = txt ? JSON.parse(txt) : null;
            if (parsed && typeof parsed === 'object') {
              const err = (parsed as any).error;
              if (err && typeof err === 'object') {
                code = String((err as any).code ?? code);
                message = String((err as any).message ?? message);
                details = (err as any).details;
              }
            }
          } catch {
            message = txt || message;
          }
          const apiErr = new GreenlightApiError(
            resp.status,
            code,
            resp.headers.get('x-request-id') ?? undefined,
            details,
            message,
          );
          lastRequestId = apiErr.requestId ?? lastRequestId;
          if (attempt + 1 < attempts && this.shouldRetryStatus(resp.status)) {
            if (logger) {
              await Promise.resolve(logger({ event: 'http_error', method, path, statusCode: resp.status, durationMs: Math.round((performance.now() - attemptStart) * 100) / 100, attempt: attempt + 1, requestId: apiErr.requestId, errorCode: apiErr.code, hasBody, queryKeys }));
            }
            await new Promise((resolve) => setTimeout(resolve, effectiveBackoff * (2 ** attempt)));
            continue;
          }
          if (logger) {
            await Promise.resolve(logger({ event: 'http_error', method, path, statusCode: resp.status, durationMs: Math.round((performance.now() - attemptStart) * 100) / 100, attempt: attempt + 1, requestId: apiErr.requestId, errorCode: apiErr.code, hasBody, queryKeys }));
          }
          throw apiErr;
        }
        const text = await resp.text();
        const successRequestId = resp.headers.get('x-request-id') ?? undefined;
        lastRequestId = successRequestId ?? lastRequestId;
        if (logger) {
          await Promise.resolve(logger({ event: 'http_request', method, path, statusCode: resp.status, durationMs: Math.round((performance.now() - attemptStart) * 100) / 100, attempt: attempt + 1, requestId: successRequestId, hasBody, queryKeys }));
        }
        return (text ? JSON.parse(text) : { ok: false, error: { code: 'EMPTY_RESPONSE', message: 'Empty response body' } }) as T;
      } catch (err) {
        if (err instanceof GreenlightApiError) {
          lastError = err;
          if (attempt + 1 < attempts && err.statusCode !== undefined && this.shouldRetryStatus(err.statusCode)) {
            await new Promise((resolve) => setTimeout(resolve, effectiveBackoff * (2 ** attempt)));
            continue;
          }
          throw err;
        }
        const isAbort = err instanceof DOMException && err.name === 'AbortError';
        const networkErr = new GreenlightApiError(
          undefined,
          isAbort ? 'TIMEOUT' : 'NETWORK_ERROR',
          lastRequestId,
          undefined,
          err instanceof Error ? err.message : String(err),
        );
        lastError = networkErr;
        if (logger) {
          await Promise.resolve(logger({ event: 'network_error', method, path, durationMs: 0, attempt: attempt + 1, requestId: networkErr.requestId, errorCode: networkErr.code, hasBody, queryKeys }));
        }
        if (attempt + 1 < attempts) {
          await new Promise((resolve) => setTimeout(resolve, effectiveBackoff * (2 ** attempt)));
          continue;
        }
        throw networkErr;
      }
    }
    throw (lastError instanceof Error ? lastError : new GreenlightApiError(undefined, 'REQUEST_FAILED', lastRequestId, undefined, 'Request failed'));
  }

  async get_agents(args: { query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentListResponse> {
    return this.request<AgentListResponse>('GET', '/api/agents', args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentDetailResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}`;
    return this.request<AgentDetailResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_activity(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentActivityResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/activity`;
    return this.request<AgentActivityResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_calibration_latest(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentLatestCalibrationResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/calibration/latest`;
    return this.request<AgentLatestCalibrationResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_golden_sets(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentGoldenSetListResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/golden-sets`;
    return this.request<AgentGoldenSetListResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_latest(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentLatestResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/latest`;
    return this.request<AgentLatestResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_launch_decisions(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<LaunchDecisionListResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/launch-decisions`;
    return this.request<LaunchDecisionListResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_launch_gate(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<LaunchGateResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/launch-gate`;
    return this.request<LaunchGateResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_patterns(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<IssuePatternListResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/patterns`;
    return this.request<IssuePatternListResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_patterns_by_pattern_id_history(args: { agent_id: string; pattern_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<PatternHistoryResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/patterns/${encodeURIComponent(String(args.pattern_id))}/history`;
    return this.request<PatternHistoryResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_readiness(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentReadinessResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/readiness`;
    return this.request<AgentReadinessResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_slo_policy(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentSloPolicyResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/slo-policy`;
    return this.request<AgentSloPolicyResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_by_agent_id_slo_status(args: { agent_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<AgentSloStatusResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/slo-status`;
    return this.request<AgentSloStatusResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_calibration_runs_by_calibration_id(args: { calibration_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<CalibrationRunResponse> {
    const path = `/api/calibration/runs/${encodeURIComponent(String(args.calibration_id))}`;
    return this.request<CalibrationRunResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_eval_compare(args: { query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<EvalRunComparisonResponse> {
    return this.request<EvalRunComparisonResponse>('GET', '/api/eval/compare', args.query, args.body, args.requestOptions);
  }

  async get_eval_runs_by_run_id(args: { run_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<EvalRunResponse> {
    const path = `/api/eval/runs/${encodeURIComponent(String(args.run_id))}`;
    return this.request<EvalRunResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_eval_runs_by_run_id_results(args: { run_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<EvalRunResultsResponse> {
    const path = `/api/eval/runs/${encodeURIComponent(String(args.run_id))}/results`;
    return this.request<EvalRunResultsResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_eval_runs_by_run_id_summary(args: { run_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<EvalRunSummaryResponse> {
    const path = `/api/eval/runs/${encodeURIComponent(String(args.run_id))}/summary`;
    return this.request<EvalRunSummaryResponse>('GET', path, args.query, args.body, args.requestOptions);
  }

  async get_system_api_keys(args: { query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<ApiKeyListResponse> {
    return this.request<ApiKeyListResponse>('GET', '/api/system/api-keys', args.query, args.body, args.requestOptions);
  }

  async get_system_audit_logs(args: { query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<ApiAuditLogListResponse> {
    return this.request<ApiAuditLogListResponse>('GET', '/api/system/audit-logs', args.query, args.body, args.requestOptions);
  }

  async patch_agents_by_agent_id_patterns_by_pattern_id(args: { agent_id: string; pattern_id: string; query?: QueryParams; body?: IssuePatternUpdateRequest; requestOptions?: RequestOptions; }): Promise<IssuePatternUpdateResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/patterns/${encodeURIComponent(String(args.pattern_id))}`;
    return this.request<IssuePatternUpdateResponse>('PATCH', path, args.query, args.body, args.requestOptions);
  }

  async patch_agents_by_agent_id_slo_violations_by_violation_id_resolve(args: { agent_id: string; violation_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<SloViolationResolveResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/slo-violations/${encodeURIComponent(String(args.violation_id))}/resolve`;
    return this.request<SloViolationResolveResponse>('PATCH', path, args.query, args.body, args.requestOptions);
  }

  async post_agents(args: { query?: QueryParams; body?: AgentCreateRequest; requestOptions?: RequestOptions; }): Promise<AgentDetailResponse> {
    return this.request<AgentDetailResponse>('POST', '/api/agents', args.query, args.body, args.requestOptions);
  }

  async post_agents_by_agent_id_launch_decision(args: { agent_id: string; query?: QueryParams; body?: LaunchDecisionCreateRequest; requestOptions?: RequestOptions; }): Promise<LaunchDecisionCreateResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/launch-decision`;
    return this.request<LaunchDecisionCreateResponse>('POST', path, args.query, args.body, args.requestOptions);
  }

  async post_agents_by_agent_id_patterns(args: { agent_id: string; query?: QueryParams; body?: IssuePatternCreateRequest; requestOptions?: RequestOptions; }): Promise<IssuePatternResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/patterns`;
    return this.request<IssuePatternResponse>('POST', path, args.query, args.body, args.requestOptions);
  }

  async post_agents_by_agent_id_readiness(args: { agent_id: string; query?: QueryParams; body?: LaunchReadinessUpsertRequest; requestOptions?: RequestOptions; }): Promise<AgentReadinessResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/readiness`;
    return this.request<AgentReadinessResponse>('POST', path, args.query, args.body, args.requestOptions);
  }

  async post_agents_by_agent_id_slo_policy(args: { agent_id: string; query?: QueryParams; body?: SloPolicyUpsertRequest; requestOptions?: RequestOptions; }): Promise<AgentSloPolicyResponse> {
    const path = `/api/agents/${encodeURIComponent(String(args.agent_id))}/slo-policy`;
    return this.request<AgentSloPolicyResponse>('POST', path, args.query, args.body, args.requestOptions);
  }

  async post_calibration_runs(args: { query?: QueryParams; body?: CalibrationRunCreateRequest; requestOptions?: RequestOptions; }): Promise<CalibrationRunResponse> {
    return this.request<CalibrationRunResponse>('POST', '/api/calibration/runs', args.query, args.body, args.requestOptions);
  }

  async post_eval_runs(args: { query?: QueryParams; body?: EvalRunCreateRequest; requestOptions?: RequestOptions; }): Promise<EvalRunCreateResponse> {
    return this.request<EvalRunCreateResponse>('POST', '/api/eval/runs', args.query, args.body, args.requestOptions);
  }

  async post_eval_runs_by_run_id_execute(args: { run_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<EvalRunExecuteResponse> {
    const path = `/api/eval/runs/${encodeURIComponent(String(args.run_id))}/execute`;
    return this.request<EvalRunExecuteResponse>('POST', path, args.query, args.body, args.requestOptions);
  }

  async post_golden_sets_upload(args: { query?: QueryParams; body?: GoldenSetUploadRequest; requestOptions?: RequestOptions; }): Promise<GoldenSetUploadResponse> {
    return this.request<GoldenSetUploadResponse>('POST', '/api/golden-sets/upload', args.query, args.body, args.requestOptions);
  }

  async post_system_api_keys(args: { query?: QueryParams; body?: ApiKeyCreateRequest; requestOptions?: RequestOptions; }): Promise<ApiKeyCreateResponse> {
    return this.request<ApiKeyCreateResponse>('POST', '/api/system/api-keys', args.query, args.body, args.requestOptions);
  }

  async post_system_api_keys_by_key_id_revoke(args: { key_id: string; query?: QueryParams; body?: Record<string, unknown>; requestOptions?: RequestOptions; }): Promise<ApiKeyRevokeResponse> {
    const path = `/api/system/api-keys/${encodeURIComponent(String(args.key_id))}/revoke`;
    return this.request<ApiKeyRevokeResponse>('POST', path, args.query, args.body, args.requestOptions);
  }

  async get_agents_all(args: { query?: QueryParams; pageSize?: number; maxPages?: number; requestOptions?: RequestOptions; } = {}): Promise<AgentListItem[]> {
    const items: AgentListItem[] = [];
    const pageSize = args.pageSize ?? 200;
    const maxPages = args.maxPages ?? 100;
    const baseQuery: QueryParams = { ...(args.query ?? {}) };
    let offset = Number(baseQuery.offset ?? 0);
    for (let i = 0; i < maxPages; i += 1) {
      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };
      const page = await this.get_agents({query, requestOptions: args.requestOptions });
      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];
      items.push(...(pageItems as AgentListItem[]));
      const rawCount = page?.data?.count ?? pageItems.length;
      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;
      if (pageCount <= 0 || pageCount < pageSize) break;
      offset += pageCount;
    }
    return items;
  }

  async get_agents_by_agent_id_activity_all(args: { agent_id: string; query?: QueryParams; pageSize?: number; maxPages?: number; requestOptions?: RequestOptions; } = {}): Promise<ActivityEventItem[]> {
    const items: ActivityEventItem[] = [];
    const pageSize = args.pageSize ?? 200;
    const maxPages = args.maxPages ?? 100;
    const baseQuery: QueryParams = { ...(args.query ?? {}) };
    let offset = Number(baseQuery.offset ?? 0);
    for (let i = 0; i < maxPages; i += 1) {
      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };
      const page = await this.get_agents_by_agent_id_activity({agent_id: args.agent_id, query, requestOptions: args.requestOptions });
      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];
      items.push(...(pageItems as ActivityEventItem[]));
      const rawCount = page?.data?.count ?? pageItems.length;
      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;
      if (pageCount <= 0 || pageCount < pageSize) break;
      offset += pageCount;
    }
    return items;
  }

  async get_agents_by_agent_id_golden_sets_all(args: { agent_id: string; query?: QueryParams; pageSize?: number; maxPages?: number; requestOptions?: RequestOptions; } = {}): Promise<AgentGoldenSetItem[]> {
    const items: AgentGoldenSetItem[] = [];
    const pageSize = args.pageSize ?? 200;
    const maxPages = args.maxPages ?? 100;
    const baseQuery: QueryParams = { ...(args.query ?? {}) };
    let offset = Number(baseQuery.offset ?? 0);
    for (let i = 0; i < maxPages; i += 1) {
      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };
      const page = await this.get_agents_by_agent_id_golden_sets({agent_id: args.agent_id, query, requestOptions: args.requestOptions });
      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];
      items.push(...(pageItems as AgentGoldenSetItem[]));
      const rawCount = page?.data?.count ?? pageItems.length;
      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;
      if (pageCount <= 0 || pageCount < pageSize) break;
      offset += pageCount;
    }
    return items;
  }

  async get_agents_by_agent_id_launch_decisions_all(args: { agent_id: string; query?: QueryParams; pageSize?: number; maxPages?: number; requestOptions?: RequestOptions; } = {}): Promise<LaunchDecisionItem[]> {
    const items: LaunchDecisionItem[] = [];
    const pageSize = args.pageSize ?? 200;
    const maxPages = args.maxPages ?? 100;
    const baseQuery: QueryParams = { ...(args.query ?? {}) };
    let offset = Number(baseQuery.offset ?? 0);
    for (let i = 0; i < maxPages; i += 1) {
      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };
      const page = await this.get_agents_by_agent_id_launch_decisions({agent_id: args.agent_id, query, requestOptions: args.requestOptions });
      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];
      items.push(...(pageItems as LaunchDecisionItem[]));
      const rawCount = page?.data?.count ?? pageItems.length;
      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;
      if (pageCount <= 0 || pageCount < pageSize) break;
      offset += pageCount;
    }
    return items;
  }

  async get_agents_by_agent_id_patterns_all(args: { agent_id: string; query?: QueryParams; pageSize?: number; maxPages?: number; requestOptions?: RequestOptions; } = {}): Promise<IssuePatternItem[]> {
    const items: IssuePatternItem[] = [];
    const pageSize = args.pageSize ?? 200;
    const maxPages = args.maxPages ?? 100;
    const baseQuery: QueryParams = { ...(args.query ?? {}) };
    let offset = Number(baseQuery.offset ?? 0);
    for (let i = 0; i < maxPages; i += 1) {
      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };
      const page = await this.get_agents_by_agent_id_patterns({agent_id: args.agent_id, query, requestOptions: args.requestOptions });
      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];
      items.push(...(pageItems as IssuePatternItem[]));
      const rawCount = page?.data?.count ?? pageItems.length;
      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;
      if (pageCount <= 0 || pageCount < pageSize) break;
      offset += pageCount;
    }
    return items;
  }

  async get_eval_runs_by_run_id_results_all(args: { run_id: string; query?: QueryParams; pageSize?: number; maxPages?: number; requestOptions?: RequestOptions; } = {}): Promise<EvalRunResultDetailItem[]> {
    const items: EvalRunResultDetailItem[] = [];
    const pageSize = args.pageSize ?? 200;
    const maxPages = args.maxPages ?? 100;
    const baseQuery: QueryParams = { ...(args.query ?? {}) };
    let offset = Number(baseQuery.offset ?? 0);
    for (let i = 0; i < maxPages; i += 1) {
      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };
      const page = await this.get_eval_runs_by_run_id_results({run_id: args.run_id, query, requestOptions: args.requestOptions });
      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];
      items.push(...(pageItems as EvalRunResultDetailItem[]));
      const rawCount = page?.data?.count ?? pageItems.length;
      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;
      if (pageCount <= 0 || pageCount < pageSize) break;
      offset += pageCount;
    }
    return items;
  }

  async get_system_api_keys_all(args: { query?: QueryParams; pageSize?: number; maxPages?: number; requestOptions?: RequestOptions; } = {}): Promise<ApiKeyListItem[]> {
    const items: ApiKeyListItem[] = [];
    const pageSize = args.pageSize ?? 200;
    const maxPages = args.maxPages ?? 100;
    const baseQuery: QueryParams = { ...(args.query ?? {}) };
    let offset = Number(baseQuery.offset ?? 0);
    for (let i = 0; i < maxPages; i += 1) {
      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };
      const page = await this.get_system_api_keys({query, requestOptions: args.requestOptions });
      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];
      items.push(...(pageItems as ApiKeyListItem[]));
      const rawCount = page?.data?.count ?? pageItems.length;
      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;
      if (pageCount <= 0 || pageCount < pageSize) break;
      offset += pageCount;
    }
    return items;
  }

  async get_system_audit_logs_all(args: { query?: QueryParams; pageSize?: number; maxPages?: number; requestOptions?: RequestOptions; } = {}): Promise<ApiAuditLogItem[]> {
    const items: ApiAuditLogItem[] = [];
    const pageSize = args.pageSize ?? 200;
    const maxPages = args.maxPages ?? 100;
    const baseQuery: QueryParams = { ...(args.query ?? {}) };
    let offset = Number(baseQuery.offset ?? 0);
    for (let i = 0; i < maxPages; i += 1) {
      const query: QueryParams = { ...baseQuery, limit: pageSize, offset };
      const page = await this.get_system_audit_logs({query, requestOptions: args.requestOptions });
      const pageItems = Array.isArray(page?.data?.items) ? page.data.items : [];
      items.push(...(pageItems as ApiAuditLogItem[]));
      const rawCount = page?.data?.count ?? pageItems.length;
      const pageCount = Number.isFinite(Number(rawCount)) ? Number(rawCount) : pageItems.length;
      if (pageCount <= 0 || pageCount < pageSize) break;
      offset += pageCount;
    }
    return items;
  }
}
