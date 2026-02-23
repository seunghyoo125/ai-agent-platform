begin;

-- Built-in eval profiles (global scope): org_id is null, is_builtin = true.
-- Idempotent inserts keyed by (name, agent_type, is_builtin).

insert into public.eval_profiles (
  org_id, name, agent_type, default_eval_mode, dimensions, is_builtin
)
select
  null,
  'Search/Retrieval',
  'search_retrieval'::public.agent_type,
  'answer'::public.eval_mode,
  '[
    {
      "id": "answer_correctness",
      "name": "Answer Correctness",
      "scale": ["yes", "partially", "no"],
      "description": "Does the response directly and correctly answer the query?",
      "issue_tags": ["incorrect_fact","partial_answer","missing_key_point","misinterpreted_query","hallucination","unsupported_claim","outdated_information"]
    },
    {
      "id": "source_correctness",
      "name": "Source Correctness",
      "scale": ["yes", "partially", "no"],
      "description": "Are sources authoritative, relevant, and correctly cited?",
      "issue_tags": ["wrong_source","missing_source","weak_authority","broken_citation","citation_mismatch","insufficient_evidence"]
    },
    {
      "id": "response_quality",
      "name": "Response Quality",
      "scale": ["good", "average", "not_good"],
      "description": "Is the response clear, concise, and useful to the user?",
      "issue_tags": ["too_verbose","too_brief","poor_structure","unclear_language","irrelevant_detail","not_actionable","tone_mismatch"]
    }
  ]'::jsonb,
  true
where not exists (
  select 1
  from public.eval_profiles p
  where p.name = 'Search/Retrieval'
    and p.agent_type = 'search_retrieval'::public.agent_type
    and p.is_builtin = true
);

insert into public.eval_profiles (
  org_id, name, agent_type, default_eval_mode, dimensions, is_builtin
)
select
  null,
  'Document Generator',
  'document_generator'::public.agent_type,
  'criteria'::public.eval_mode,
  '[
    {
      "id": "completeness",
      "name": "Completeness",
      "scale": ["good", "average", "not_good"],
      "description": "Does the output cover required sections and scope?",
      "issue_tags": ["missing_section","missing_requirement","incomplete_argument","insufficient_detail","coverage_gap"]
    },
    {
      "id": "accuracy",
      "name": "Accuracy",
      "scale": ["good", "average", "not_good"],
      "description": "Are facts and statements correct and consistent?",
      "issue_tags": ["incorrect_fact","inconsistent_claim","unsupported_statement","fabricated_detail","outdated_information"]
    },
    {
      "id": "format_compliance",
      "name": "Format Compliance",
      "scale": ["good", "average", "not_good"],
      "description": "Does the output follow required template and structure?",
      "issue_tags": ["wrong_format","missing_heading","schema_violation","style_violation","formatting_error"]
    },
    {
      "id": "actionability",
      "name": "Actionability",
      "scale": ["good", "average", "not_good"],
      "description": "Can the reader take clear next actions from this output?",
      "issue_tags": ["vague_recommendation","missing_next_step","unclear_owner","no_prioritization","low_decision_value"]
    }
  ]'::jsonb,
  true
where not exists (
  select 1
  from public.eval_profiles p
  where p.name = 'Document Generator'
    and p.agent_type = 'document_generator'::public.agent_type
    and p.is_builtin = true
);

insert into public.eval_profiles (
  org_id, name, agent_type, default_eval_mode, dimensions, is_builtin
)
select
  null,
  'Dashboard/Analytics',
  'dashboard_assistant'::public.agent_type,
  'answer'::public.eval_mode,
  '[
    {
      "id": "data_accuracy",
      "name": "Data Accuracy",
      "scale": ["yes", "partially", "no"],
      "description": "Are reported values and labels accurate?",
      "issue_tags": ["wrong_value","wrong_label","aggregation_error","dimension_mismatch"]
    },
    {
      "id": "freshness",
      "name": "Freshness",
      "scale": ["yes", "partially", "no"],
      "description": "Is data current enough for intended use?",
      "issue_tags": ["stale_data","unknown_timestamp","lagging_refresh","freshness_not_disclosed"]
    },
    {
      "id": "calculation_correctness",
      "name": "Calculation Correctness",
      "scale": ["yes", "partially", "no"],
      "description": "Are derived metrics and calculations correct?",
      "issue_tags": ["formula_error","unit_error","baseline_error","percentage_error"]
    },
    {
      "id": "presentation_quality",
      "name": "Presentation Quality",
      "scale": ["good", "average", "not_good"],
      "description": "Is insight presentation clear and decision-useful?",
      "issue_tags": ["unclear_chart","misleading_visual","no_key_takeaway","poor_layout"]
    }
  ]'::jsonb,
  true
where not exists (
  select 1
  from public.eval_profiles p
  where p.name = 'Dashboard/Analytics'
    and p.agent_type = 'dashboard_assistant'::public.agent_type
    and p.is_builtin = true
);

insert into public.eval_profiles (
  org_id, name, agent_type, default_eval_mode, dimensions, is_builtin
)
select
  null,
  'Triage/Classification',
  'triage_classification'::public.agent_type,
  'answer'::public.eval_mode,
  '[
    {
      "id": "classification_correctness",
      "name": "Classification Correctness",
      "scale": ["yes", "partially", "no"],
      "description": "Is the case assigned to the correct class/category?",
      "issue_tags": ["wrong_class","ambiguous_class","insufficient_basis"]
    },
    {
      "id": "priority_correctness",
      "name": "Priority Correctness",
      "scale": ["yes", "partially", "no"],
      "description": "Is the urgency/priority level correctly assigned?",
      "issue_tags": ["over_prioritized","under_prioritized","missing_justification"]
    },
    {
      "id": "routing_correctness",
      "name": "Routing Correctness",
      "scale": ["yes", "partially", "no"],
      "description": "Is the item routed to the correct owner/queue?",
      "issue_tags": ["wrong_owner","wrong_queue","missing_route"]
    },
    {
      "id": "completeness",
      "name": "Completeness",
      "scale": ["good", "average", "not_good"],
      "description": "Is triage output complete and usable without rework?",
      "issue_tags": ["missing_field","missing_context","unclear_reasoning","insufficient_detail"]
    }
  ]'::jsonb,
  true
where not exists (
  select 1
  from public.eval_profiles p
  where p.name = 'Triage/Classification'
    and p.agent_type = 'triage_classification'::public.agent_type
    and p.is_builtin = true
);

insert into public.eval_profiles (
  org_id, name, agent_type, default_eval_mode, dimensions, is_builtin
)
select
  null,
  'Analysis',
  'analysis'::public.agent_type,
  'criteria'::public.eval_mode,
  '[
    {
      "id": "accuracy",
      "name": "Accuracy",
      "scale": ["good", "average", "not_good"],
      "description": "Are findings and claims factually correct?",
      "issue_tags": ["incorrect_fact","unsupported_claim","misstated_context","outdated_information"]
    },
    {
      "id": "evidence_quality",
      "name": "Evidence Quality",
      "scale": ["good", "average", "not_good"],
      "description": "Does analysis provide sufficient, relevant evidence?",
      "issue_tags": ["insufficient_evidence","irrelevant_evidence","weak_source","citation_gap"]
    },
    {
      "id": "completeness",
      "name": "Completeness",
      "scale": ["good", "average", "not_good"],
      "description": "Does analysis cover major factors and edge conditions?",
      "issue_tags": ["missing_dimension","missing_risk","missing_counterpoint","shallow_analysis"]
    },
    {
      "id": "actionability",
      "name": "Actionability",
      "scale": ["good", "average", "not_good"],
      "description": "Are recommendations specific and usable for decisions?",
      "issue_tags": ["vague_recommendation","no_next_step","no_owner","no_prioritization"]
    }
  ]'::jsonb,
  true
where not exists (
  select 1
  from public.eval_profiles p
  where p.name = 'Analysis'
    and p.agent_type = 'analysis'::public.agent_type
    and p.is_builtin = true
);

commit;
