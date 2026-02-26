begin;

alter table public.gate_definitions
  add column if not exists contract_version text not null default '1.0.0';
alter table public.gate_definitions
  drop constraint if exists gate_definitions_contract_version_semver;
alter table public.gate_definitions
  add constraint gate_definitions_contract_version_semver
  check (contract_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$');

alter table public.agent_gate_bindings
  add column if not exists definition_contract_version text not null default '1.0.0';
alter table public.agent_gate_bindings
  drop constraint if exists agent_gate_bindings_definition_contract_version_semver;
alter table public.agent_gate_bindings
  add constraint agent_gate_bindings_definition_contract_version_semver
  check (definition_contract_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$');

alter table public.evaluator_definitions
  add column if not exists contract_version text not null default '1.0.0';
alter table public.evaluator_definitions
  drop constraint if exists evaluator_definitions_contract_version_semver;
alter table public.evaluator_definitions
  add constraint evaluator_definitions_contract_version_semver
  check (contract_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$');

alter table public.agent_evaluator_bindings
  add column if not exists definition_contract_version text not null default '1.0.0';
alter table public.agent_evaluator_bindings
  drop constraint if exists agent_evaluator_bindings_definition_contract_version_semver;
alter table public.agent_evaluator_bindings
  add constraint agent_evaluator_bindings_definition_contract_version_semver
  check (definition_contract_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$');

alter table public.run_type_definitions
  add column if not exists contract_version text not null default '1.0.0';
alter table public.run_type_definitions
  drop constraint if exists run_type_definitions_contract_version_semver;
alter table public.run_type_definitions
  add constraint run_type_definitions_contract_version_semver
  check (contract_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$');

alter table public.agent_run_type_bindings
  add column if not exists definition_contract_version text not null default '1.0.0';
alter table public.agent_run_type_bindings
  drop constraint if exists agent_run_type_bindings_definition_contract_version_semver;
alter table public.agent_run_type_bindings
  add constraint agent_run_type_bindings_definition_contract_version_semver
  check (definition_contract_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$');

update public.agent_gate_bindings b
set definition_contract_version = d.contract_version
from public.gate_definitions d
where d.id = b.gate_definition_id
  and (b.definition_contract_version is null or b.definition_contract_version = '1.0.0');

update public.agent_evaluator_bindings b
set definition_contract_version = d.contract_version
from public.evaluator_definitions d
where d.id = b.evaluator_definition_id
  and (b.definition_contract_version is null or b.definition_contract_version = '1.0.0');

update public.agent_run_type_bindings b
set definition_contract_version = d.contract_version
from public.run_type_definitions d
where d.id = b.run_type_definition_id
  and (b.definition_contract_version is null or b.definition_contract_version = '1.0.0');

commit;
