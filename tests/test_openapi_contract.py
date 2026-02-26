from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from src.api.main import app


client = TestClient(app)


def test_openapi_has_bearer_auth_scheme() -> None:
    schema = client.get("/openapi.json").json()
    bearer = schema["components"]["securitySchemes"]["BearerAuth"]

    assert bearer["type"] == "http"
    assert bearer["scheme"] == "bearer"


def test_openapi_eval_run_endpoint_is_tagged_and_secured() -> None:
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/eval/runs"]["post"]
    list_operation = schema["paths"]["/api/eval/runs"]["get"]

    assert operation.get("tags") == ["Evaluation"]
    assert operation.get("security") == [{"BearerAuth": []}]
    assert operation.get("operationId") == "post_eval_runs"
    assert list_operation.get("tags") == ["Evaluation"]
    assert list_operation.get("security") == [{"BearerAuth": []}]
    assert list_operation.get("operationId") == "get_eval_runs"


def test_openapi_health_endpoint_is_not_secured() -> None:
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/health"]["get"]

    assert operation.get("tags") == ["System"]
    assert "security" not in operation


def test_openapi_operation_ids_are_unique() -> None:
    schema = client.get("/openapi.json").json()
    operation_ids = []

    for methods in schema.get("paths", {}).values():
        for method, operation in methods.items():
            if method in {"get", "post", "put", "patch", "delete"}:
                op_id = operation.get("operationId")
                assert op_id
                operation_ids.append(op_id)

    assert len(operation_ids) == len(set(operation_ids))


def test_openapi_eval_run_response_uses_typed_envelope_ref() -> None:
    schema = client.get("/openapi.json").json()
    op = schema["paths"]["/api/eval/runs"]["post"]
    list_op = schema["paths"]["/api/eval/runs"]["get"]
    artifacts_op = schema["paths"]["/api/eval/runs/{run_id}/artifacts"]["get"]
    review_queue_op = schema["paths"]["/api/eval/runs/{run_id}/review-queue"]["get"]
    review_mutation_op = schema["paths"]["/api/eval/runs/{run_id}/results/{result_id}/review"]["patch"]
    response_schema = op["responses"]["202"]["content"]["application/json"]["schema"]
    list_schema = list_op["responses"]["200"]["content"]["application/json"]["schema"]
    artifacts_schema = artifacts_op["responses"]["200"]["content"]["application/json"]["schema"]
    review_queue_schema = review_queue_op["responses"]["200"]["content"]["application/json"]["schema"]
    review_mutation_schema = review_mutation_op["responses"]["200"]["content"]["application/json"]["schema"]

    assert response_schema["$ref"] == "#/components/schemas/EvalRunCreateResponse"
    assert list_schema["$ref"] == "#/components/schemas/EvalRunListResponse"
    assert artifacts_schema["$ref"] == "#/components/schemas/EvalRunArtifactsResponse"
    assert review_queue_schema["$ref"] == "#/components/schemas/EvalRunReviewQueueResponse"
    assert review_mutation_schema["$ref"] == "#/components/schemas/EvalRunResultReviewResponse"


def test_openapi_all_api_operations_use_ref_response_schema() -> None:
    schema = client.get("/openapi.json").json()

    for path, methods in schema.get("paths", {}).items():
        if not path.startswith("/api/"):
            continue
        for method, operation in methods.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            responses = operation.get("responses", {})
            response = responses.get("200") or responses.get("201") or responses.get("202") or responses.get("default")
            assert response is not None, f"Missing success/default response for {method.upper()} {path}"
            response_schema = response.get("content", {}).get("application/json", {}).get("schema")
            assert isinstance(response_schema, dict) and "$ref" in response_schema, (
                f"Expected $ref response schema for {method.upper()} {path}, got {response_schema}"
            )


def test_mutating_api_routes_require_member_or_admin() -> None:
    violations = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        methods = {m for m in route.methods or set() if m in {"POST", "PATCH", "PUT", "DELETE"}}
        if not methods or not route.path.startswith("/api/"):
            continue
        dep_names = {
            getattr(dep.call, "__name__", str(dep.call))
            for dep in route.dependant.dependencies
            if dep.call is not None
        }
        if "require_member" in dep_names or "require_admin" in dep_names:
            continue
        violations.append(f"{','.join(sorted(methods))} {route.path} deps={sorted(dep_names)}")

    assert not violations, "Mutating routes must require member/admin:\\n" + "\\n".join(violations)


def test_openapi_queue_admin_mutations_have_idempotency_header() -> None:
    schema = client.get("/openapi.json").json()
    admin_queue_ops = [
        ("/api/system/queue/jobs/{job_id}/retry", "post"),
        ("/api/system/queue/jobs/{job_id}/cancel", "post"),
        ("/api/system/queue/jobs/failed/replay", "post"),
        ("/api/system/queue/jobs/reap-stale", "post"),
        ("/api/system/queue/jobs/prune", "post"),
        ("/api/system/queue/maintenance/run", "post"),
        ("/api/system/queue/maintenance/reap-stale-runs", "post"),
        ("/api/system/queue/maintenance/schedule-summary/notify", "post"),
        ("/api/system/contracts/drift/trigger-summary/notify", "post"),
        ("/api/system/contracts/drift/schedule-run", "post"),
    ]
    for path, method in admin_queue_ops:
        operation = schema["paths"][path][method]
        params = operation.get("parameters", [])
        header = next(
            (p for p in params if p.get("in") == "header" and str(p.get("name", "")).lower() == "idempotency-key"),
            None,
        )
        assert header is not None, f"Missing Idempotency-Key header param in {method.upper()} {path}"
        assert header.get("required") is True


def test_openapi_queue_admin_endpoints_tag_security_and_responses() -> None:
    schema = client.get("/openapi.json").json()
    checks = [
        ("/api/system/queue/jobs/{job_id}/retry", "post", "#/components/schemas/QueueJobRetryResponse"),
        ("/api/system/queue/jobs/{job_id}/cancel", "post", "#/components/schemas/QueueJobCancelResponse"),
        ("/api/system/queue/jobs/failed/replay", "post", "#/components/schemas/QueueJobsReplayResponse"),
        ("/api/system/queue/jobs/reap-stale", "post", "#/components/schemas/QueueJobsReapStaleResponse"),
        ("/api/system/queue/jobs/prune", "post", "#/components/schemas/QueueJobsPruneResponse"),
        ("/api/system/queue/maintenance/run", "post", "#/components/schemas/QueueMaintenanceRunResponse"),
        ("/api/system/queue/maintenance/reap-stale-runs", "post", "#/components/schemas/QueueMaintenanceReapStaleResponse"),
        ("/api/system/queue/maintenance/schedule-trigger", "post", "#/components/schemas/QueueMaintenanceScheduleTriggerResponse"),
        ("/api/system/queue/maintenance/schedule-summary/notify", "post", "#/components/schemas/QueueMaintenanceScheduleNotifyResponse"),
    ]
    for path, method, expected_ref in checks:
        operation = schema["paths"][path][method]
        assert operation.get("tags") == ["System"]
        assert operation.get("security") == [{"BearerAuth": []}]
        response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        assert response_schema["$ref"] == expected_ref


def test_openapi_queue_maintenance_policy_endpoints_contract() -> None:
    schema = client.get("/openapi.json").json()
    get_op = schema["paths"]["/api/system/queue/maintenance-policy"]["get"]
    post_op = schema["paths"]["/api/system/queue/maintenance-policy"]["post"]

    assert get_op.get("tags") == ["System"]
    assert get_op.get("security") == [{"BearerAuth": []}]
    get_schema = get_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert get_schema["$ref"] == "#/components/schemas/QueueMaintenancePolicyResponse"

    assert post_op.get("tags") == ["System"]
    assert post_op.get("security") == [{"BearerAuth": []}]
    post_schema = post_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert post_schema["$ref"] == "#/components/schemas/QueueMaintenancePolicyResponse"


def test_openapi_contract_drift_policy_endpoints_contract() -> None:
    schema = client.get("/openapi.json").json()
    get_op = schema["paths"]["/api/system/contracts/drift-policy"]["get"]
    post_op = schema["paths"]["/api/system/contracts/drift-policy"]["post"]
    trigger_op = schema["paths"]["/api/system/contracts/drift/trigger"]["post"]
    notify_op = schema["paths"]["/api/system/contracts/drift/trigger-summary/notify"]["post"]
    delivery_op = schema["paths"]["/api/system/contracts/drift/trigger-alert-delivery"]["get"]
    schedule_run_op = schema["paths"]["/api/system/contracts/drift/schedule-run"]["post"]

    assert get_op.get("tags") == ["System"]
    assert get_op.get("security") == [{"BearerAuth": []}]
    get_schema = get_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert get_schema["$ref"] == "#/components/schemas/ContractDriftPolicyResponse"

    assert post_op.get("tags") == ["System"]
    assert post_op.get("security") == [{"BearerAuth": []}]
    post_schema = post_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert post_schema["$ref"] == "#/components/schemas/ContractDriftPolicyResponse"

    assert trigger_op.get("tags") == ["System"]
    assert trigger_op.get("security") == [{"BearerAuth": []}]
    trigger_params = trigger_op.get("parameters", [])
    idem_header = next(
        (p for p in trigger_params if p.get("in") == "header" and str(p.get("name", "")).lower() == "idempotency-key"),
        None,
    )
    assert idem_header is not None
    assert idem_header.get("required") is True
    trigger_schema = trigger_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert trigger_schema["$ref"] == "#/components/schemas/ContractDriftTriggerResponse"

    summary_op = schema["paths"]["/api/system/contracts/drift/trigger-summary"]["get"]
    assert summary_op.get("tags") == ["System"]
    assert summary_op.get("security") == [{"BearerAuth": []}]
    summary_schema = summary_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert summary_schema["$ref"] == "#/components/schemas/ContractDriftTriggerSummaryResponse"

    assert notify_op.get("tags") == ["System"]
    assert notify_op.get("security") == [{"BearerAuth": []}]
    notify_params = notify_op.get("parameters", [])
    notify_idem_header = next(
        (p for p in notify_params if p.get("in") == "header" and str(p.get("name", "")).lower() == "idempotency-key"),
        None,
    )
    assert notify_idem_header is not None
    assert notify_idem_header.get("required") is True
    notify_schema = notify_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert notify_schema["$ref"] == "#/components/schemas/ContractDriftTriggerNotifyResponse"

    assert delivery_op.get("tags") == ["System"]
    assert delivery_op.get("security") == [{"BearerAuth": []}]
    delivery_schema = delivery_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert delivery_schema["$ref"] == "#/components/schemas/ContractDriftTriggerAlertDeliveryResponse"

    assert schedule_run_op.get("tags") == ["System"]
    assert schedule_run_op.get("security") == [{"BearerAuth": []}]
    schedule_run_params = schedule_run_op.get("parameters", [])
    schedule_run_idem_header = next(
        (p for p in schedule_run_params if p.get("in") == "header" and str(p.get("name", "")).lower() == "idempotency-key"),
        None,
    )
    assert schedule_run_idem_header is not None
    assert schedule_run_idem_header.get("required") is True
    schedule_run_schema = schedule_run_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert schedule_run_schema["$ref"] == "#/components/schemas/ContractDriftScheduleRunResponse"


def test_openapi_queue_maintenance_runs_endpoints_contract() -> None:
    schema = client.get("/openapi.json").json()
    list_op = schema["paths"]["/api/system/queue/maintenance/runs"]["get"]
    detail_op = schema["paths"]["/api/system/queue/maintenance/runs/{run_id}"]["get"]
    metrics_op = schema["paths"]["/api/system/queue/maintenance/metrics"]["get"]
    trigger_op = schema["paths"]["/api/system/queue/maintenance/schedule-trigger"]["post"]
    summary_op = schema["paths"]["/api/system/queue/maintenance/schedule-summary"]["get"]
    notify_op = schema["paths"]["/api/system/queue/maintenance/schedule-summary/notify"]["post"]
    delivery_op = schema["paths"]["/api/system/queue/maintenance/schedule-alert-delivery"]["get"]

    assert list_op.get("tags") == ["System"]
    assert list_op.get("security") == [{"BearerAuth": []}]
    list_schema = list_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert list_schema["$ref"] == "#/components/schemas/QueueMaintenanceRunListResponse"

    assert detail_op.get("tags") == ["System"]
    assert detail_op.get("security") == [{"BearerAuth": []}]
    detail_schema = detail_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert detail_schema["$ref"] == "#/components/schemas/QueueMaintenanceRunDetailResponse"

    assert metrics_op.get("tags") == ["System"]
    assert metrics_op.get("security") == [{"BearerAuth": []}]
    metrics_schema = metrics_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert metrics_schema["$ref"] == "#/components/schemas/QueueMaintenanceMetricsResponse"

    assert trigger_op.get("tags") == ["System"]
    assert trigger_op.get("security") == [{"BearerAuth": []}]
    trigger_schema = trigger_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert trigger_schema["$ref"] == "#/components/schemas/QueueMaintenanceScheduleTriggerResponse"

    assert summary_op.get("tags") == ["System"]
    assert summary_op.get("security") == [{"BearerAuth": []}]
    summary_schema = summary_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert summary_schema["$ref"] == "#/components/schemas/QueueMaintenanceScheduleSummaryResponse"

    assert notify_op.get("tags") == ["System"]
    assert notify_op.get("security") == [{"BearerAuth": []}]
    notify_schema = notify_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert notify_schema["$ref"] == "#/components/schemas/QueueMaintenanceScheduleNotifyResponse"

    assert delivery_op.get("tags") == ["System"]
    assert delivery_op.get("security") == [{"BearerAuth": []}]
    delivery_schema = delivery_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert delivery_schema["$ref"] == "#/components/schemas/QueueMaintenanceScheduleAlertDeliveryResponse"


def test_openapi_contract_upgrade_endpoints_contract() -> None:
    schema = client.get("/openapi.json").json()
    preview_op = schema["paths"]["/api/contracts/upgrade-preview"]["post"]
    apply_op = schema["paths"]["/api/contracts/apply-upgrade"]["post"]

    assert preview_op.get("tags") == ["Guardrails"]
    assert preview_op.get("security") == [{"BearerAuth": []}]
    preview_schema = preview_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert preview_schema["$ref"] == "#/components/schemas/ContractUpgradePreviewResponse"

    assert apply_op.get("tags") == ["Guardrails"]
    assert apply_op.get("security") == [{"BearerAuth": []}]
    apply_schema = apply_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert apply_schema["$ref"] == "#/components/schemas/ContractUpgradeApplyResponse"


def test_openapi_contract_drift_endpoint_contract() -> None:
    schema = client.get("/openapi.json").json()
    drift_op = schema["paths"]["/api/contracts/drift"]["get"]

    assert drift_op.get("tags") == ["Guardrails"]
    assert drift_op.get("security") == [{"BearerAuth": []}]
    drift_schema = drift_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert drift_schema["$ref"] == "#/components/schemas/ContractDriftResponse"


def test_openapi_contract_drift_promote_endpoint_contract() -> None:
    schema = client.get("/openapi.json").json()
    op = schema["paths"]["/api/contracts/drift/promote-patterns"]["post"]

    assert op.get("tags") == ["Guardrails"]
    assert op.get("security") == [{"BearerAuth": []}]
    response_schema = op["responses"]["200"]["content"]["application/json"]["schema"]
    assert response_schema["$ref"] == "#/components/schemas/ContractDriftPromotePatternsResponse"


def test_openapi_agent_health_and_portfolio_contract() -> None:
    schema = client.get("/openapi.json").json()
    health_op = schema["paths"]["/api/agents/{agent_id}/health"]["get"]
    trend_op = schema["paths"]["/api/agents/{agent_id}/score-trend"]["get"]
    portfolio_op = schema["paths"]["/api/orgs/{org_id}/portfolio-health"]["get"]
    cal_gate_op = schema["paths"]["/api/agents/{agent_id}/calibration-gate-status"]["get"]
    gs_gate_op = schema["paths"]["/api/golden-sets/{golden_set_id}/quality-gate-status"]["get"]
    gate_defs_op = schema["paths"]["/api/gate-definitions"]["get"]
    gate_defs_create_op = schema["paths"]["/api/gate-definitions"]["post"]
    gate_bindings_op = schema["paths"]["/api/agents/{agent_id}/gate-bindings"]["get"]
    gate_bindings_upsert_op = schema["paths"]["/api/agents/{agent_id}/gate-bindings"]["post"]
    evaluator_defs_op = schema["paths"]["/api/evaluator-definitions"]["get"]
    evaluator_defs_create_op = schema["paths"]["/api/evaluator-definitions"]["post"]
    evaluator_bindings_op = schema["paths"]["/api/agents/{agent_id}/evaluator-bindings"]["get"]
    evaluator_bindings_upsert_op = schema["paths"]["/api/agents/{agent_id}/evaluator-bindings"]["post"]
    run_type_defs_op = schema["paths"]["/api/run-type-definitions"]["get"]
    run_type_defs_create_op = schema["paths"]["/api/run-type-definitions"]["post"]
    run_type_bindings_op = schema["paths"]["/api/agents/{agent_id}/run-type-bindings"]["get"]
    run_type_bindings_upsert_op = schema["paths"]["/api/agents/{agent_id}/run-type-bindings"]["post"]
    contract_status_op = schema["paths"]["/api/agents/{agent_id}/contract-status"]["get"]

    assert health_op.get("tags") == ["Agents"]
    assert health_op.get("security") == [{"BearerAuth": []}]
    health_schema = health_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert health_schema["$ref"] == "#/components/schemas/AgentHealthResponse"

    assert trend_op.get("tags") == ["Agents"]
    assert trend_op.get("security") == [{"BearerAuth": []}]
    trend_schema = trend_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert trend_schema["$ref"] == "#/components/schemas/AgentScoreTrendResponse"

    assert portfolio_op.get("tags") == ["Agents"]
    assert portfolio_op.get("security") == [{"BearerAuth": []}]
    portfolio_schema = portfolio_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert portfolio_schema["$ref"] == "#/components/schemas/PortfolioHealthResponse"

    assert cal_gate_op.get("tags") == ["Agents"]
    assert cal_gate_op.get("security") == [{"BearerAuth": []}]
    cal_gate_schema = cal_gate_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert cal_gate_schema["$ref"] == "#/components/schemas/CalibrationGateStatusResponse"

    assert gs_gate_op.get("tags") == ["Golden Sets"]
    assert gs_gate_op.get("security") == [{"BearerAuth": []}]
    gs_gate_schema = gs_gate_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert gs_gate_schema["$ref"] == "#/components/schemas/GoldenSetQualityGateStatusResponse"

    assert gate_defs_op.get("tags") == ["Guardrails"]
    assert gate_defs_op.get("security") == [{"BearerAuth": []}]
    gate_defs_schema = gate_defs_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert gate_defs_schema["$ref"] == "#/components/schemas/GateDefinitionListResponse"

    assert gate_defs_create_op.get("tags") == ["Guardrails"]
    assert gate_defs_create_op.get("security") == [{"BearerAuth": []}]
    gate_defs_create_schema = gate_defs_create_op["responses"]["201"]["content"]["application/json"]["schema"]
    assert gate_defs_create_schema["$ref"] == "#/components/schemas/GateDefinitionCreateResponse"

    assert gate_bindings_op.get("tags") == ["Guardrails"]
    assert gate_bindings_op.get("security") == [{"BearerAuth": []}]
    gate_bindings_schema = gate_bindings_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert gate_bindings_schema["$ref"] == "#/components/schemas/AgentGateBindingListResponse"

    assert gate_bindings_upsert_op.get("tags") == ["Guardrails"]
    assert gate_bindings_upsert_op.get("security") == [{"BearerAuth": []}]
    gate_bindings_upsert_schema = gate_bindings_upsert_op["responses"]["201"]["content"]["application/json"]["schema"]
    assert gate_bindings_upsert_schema["$ref"] == "#/components/schemas/AgentGateBindingUpsertResponse"

    assert evaluator_defs_op.get("tags") == ["Evaluation"]
    assert evaluator_defs_op.get("security") == [{"BearerAuth": []}]
    evaluator_defs_schema = evaluator_defs_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert evaluator_defs_schema["$ref"] == "#/components/schemas/EvaluatorDefinitionListResponse"

    assert evaluator_defs_create_op.get("tags") == ["Evaluation"]
    assert evaluator_defs_create_op.get("security") == [{"BearerAuth": []}]
    evaluator_defs_create_schema = evaluator_defs_create_op["responses"]["201"]["content"]["application/json"]["schema"]
    assert evaluator_defs_create_schema["$ref"] == "#/components/schemas/EvaluatorDefinitionCreateResponse"

    assert evaluator_bindings_op.get("tags") == ["Evaluation"]
    assert evaluator_bindings_op.get("security") == [{"BearerAuth": []}]
    evaluator_bindings_schema = evaluator_bindings_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert evaluator_bindings_schema["$ref"] == "#/components/schemas/AgentEvaluatorBindingListResponse"

    assert evaluator_bindings_upsert_op.get("tags") == ["Evaluation"]
    assert evaluator_bindings_upsert_op.get("security") == [{"BearerAuth": []}]
    evaluator_bindings_upsert_schema = evaluator_bindings_upsert_op["responses"]["201"]["content"]["application/json"]["schema"]
    assert evaluator_bindings_upsert_schema["$ref"] == "#/components/schemas/AgentEvaluatorBindingUpsertResponse"

    assert run_type_defs_op.get("tags") == ["Evaluation"]
    assert run_type_defs_op.get("security") == [{"BearerAuth": []}]
    run_type_defs_schema = run_type_defs_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert run_type_defs_schema["$ref"] == "#/components/schemas/RunTypeDefinitionListResponse"

    assert run_type_defs_create_op.get("tags") == ["Evaluation"]
    assert run_type_defs_create_op.get("security") == [{"BearerAuth": []}]
    run_type_defs_create_schema = run_type_defs_create_op["responses"]["201"]["content"]["application/json"]["schema"]
    assert run_type_defs_create_schema["$ref"] == "#/components/schemas/RunTypeDefinitionCreateResponse"

    assert run_type_bindings_op.get("tags") == ["Evaluation"]
    assert run_type_bindings_op.get("security") == [{"BearerAuth": []}]
    run_type_bindings_schema = run_type_bindings_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert run_type_bindings_schema["$ref"] == "#/components/schemas/AgentRunTypeBindingListResponse"

    assert run_type_bindings_upsert_op.get("tags") == ["Evaluation"]
    assert run_type_bindings_upsert_op.get("security") == [{"BearerAuth": []}]
    run_type_bindings_upsert_schema = run_type_bindings_upsert_op["responses"]["201"]["content"]["application/json"]["schema"]
    assert run_type_bindings_upsert_schema["$ref"] == "#/components/schemas/AgentRunTypeBindingUpsertResponse"

    assert contract_status_op.get("tags") == ["Agents"]
    assert contract_status_op.get("security") == [{"BearerAuth": []}]
    contract_status_schema = contract_status_op["responses"]["200"]["content"]["application/json"]["schema"]
    assert contract_status_schema["$ref"] == "#/components/schemas/AgentContractStatusResponse"
