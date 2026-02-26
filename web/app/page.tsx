"use client";

import { useMemo, useState } from "react";

type ApiResp<T> = { ok: boolean; data?: T; error?: { code: string; message: string } };

type Agent = {
  id: string;
  name: string;
  agent_type: string;
  status: string;
};

type LaunchGate = {
  can_launch: boolean;
  blockers: string[];
  latest_run_id: string | null;
  latest_run_status: string | null;
  open_slo_violations: number;
  active_critical_issues: number;
  readiness_pending_items: number;
};

type CompareData = {
  baseline_run_id: string;
  candidate_run_id: string;
  regression_count: number;
  answer_yes_rate_delta: number;
  source_yes_rate_delta: number;
  quality_good_rate_delta: number;
};

async function apiCall<T>(
  baseUrl: string,
  apiKey: string,
  path: string
): Promise<ApiResp<T>> {
  const resp = await fetch(`${baseUrl}${path}`, {
    headers: { Authorization: `Bearer ${apiKey}` }
  });
  return (await resp.json()) as ApiResp<T>;
}

export default function Page() {
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8001/api/v1");
  const [apiKey, setApiKey] = useState("");
  const [orgId, setOrgId] = useState("23cdb862-a12f-4b6c-84ee-5cb648f9b5bb");
  const [agents, setAgents] = useState<Agent[]>([]);
  const [agentId, setAgentId] = useState("");
  const [status, setStatus] = useState<string>("");
  const [launchGate, setLaunchGate] = useState<LaunchGate | null>(null);
  const [latestRun, setLatestRun] = useState<Record<string, unknown> | null>(null);
  const [compare, setCompare] = useState<CompareData | null>(null);
  const [baselineRef, setBaselineRef] = useState("active");
  const [candidateRef, setCandidateRef] = useState("latest");

  const selectedAgent = useMemo(
    () => agents.find((a) => a.id === agentId) ?? null,
    [agents, agentId]
  );

  async function loadAgents() {
    const res = await apiCall<{ items: Agent[] }>(baseUrl, apiKey, `/agents?org_id=${encodeURIComponent(orgId)}`);
    if (!res.ok || !res.data) {
      setStatus(res.error?.message ?? "Failed to load agents");
      return;
    }
    setAgents(res.data.items || []);
    if (res.data.items?.[0]) setAgentId(res.data.items[0].id);
    setStatus(`Loaded ${res.data.items.length} agent(s).`);
  }

  async function loadGateAndLatest() {
    if (!agentId) return;
    const [gateResp, latestResp] = await Promise.all([
      apiCall<LaunchGate>(baseUrl, apiKey, `/agents/${agentId}/launch-gate`),
      apiCall<{ latest_run: Record<string, unknown> | null }>(baseUrl, apiKey, `/agents/${agentId}/latest`)
    ]);
    if (gateResp.ok && gateResp.data) setLaunchGate(gateResp.data);
    if (latestResp.ok && latestResp.data) setLatestRun(latestResp.data.latest_run);
    setStatus("Loaded launch gate + latest run.");
  }

  async function compareByRef() {
    if (!agentId) return;
    const q = new URLSearchParams({
      agent_id: agentId,
      baseline_ref: baselineRef,
      candidate_ref: candidateRef
    });
    const res = await apiCall<CompareData>(baseUrl, apiKey, `/eval/compare?${q.toString()}`);
    if (!res.ok || !res.data) {
      setStatus(res.error?.message ?? "Compare failed");
      return;
    }
    setCompare(res.data);
    setStatus("Compare completed.");
  }

  return (
    <main className="page">
      <h1 className="title">ai-agent-platform Web Shell</h1>
      <p className="sub">Agent-centric operations UI on top of current backend APIs.</p>

      <section className="grid">
        <article className="card">
          <div className="row">
            <div className="span-6">
              <label>Base URL</label>
              <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
            </div>
            <div className="span-6">
              <label>API Key</label>
              <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} type="password" />
            </div>
            <div className="span-8">
              <label>Org ID</label>
              <input value={orgId} onChange={(e) => setOrgId(e.target.value)} />
            </div>
            <div className="span-4">
              <label>&nbsp;</label>
              <button onClick={loadAgents} disabled={!apiKey || !baseUrl}>
                Load Agents
              </button>
            </div>
          </div>
          {status ? <p className="mono">{status}</p> : null}
        </article>

        <article className="card half">
          <label>Agent</label>
          <select value={agentId} onChange={(e) => setAgentId(e.target.value)}>
            <option value="">Select an agent</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.id.slice(0, 8)})
              </option>
            ))}
          </select>
          {selectedAgent ? (
            <p className="mono">
              type={selectedAgent.agent_type} status={selectedAgent.status}
            </p>
          ) : null}
          <button onClick={loadGateAndLatest} disabled={!agentId || !apiKey}>
            Load Launch Gate + Latest Run
          </button>
        </article>

        <article className="card half">
          <div className="row">
            <div className="span-6">
              <label>Baseline Ref</label>
              <input value={baselineRef} onChange={(e) => setBaselineRef(e.target.value)} />
            </div>
            <div className="span-6">
              <label>Candidate Ref</label>
              <input value={candidateRef} onChange={(e) => setCandidateRef(e.target.value)} />
            </div>
          </div>
          <button onClick={compareByRef} disabled={!agentId || !apiKey}>
            Compare by Reference
          </button>
        </article>

        <article className="card half">
          <h3>Launch Gate</h3>
          {launchGate ? (
            <>
              <span className={`pill ${launchGate.can_launch ? "good" : "bad"}`}>
                {launchGate.can_launch ? "PASS" : "BLOCKED"}
              </span>
              <pre>{JSON.stringify(launchGate, null, 2)}</pre>
            </>
          ) : (
            <p className="mono">No gate loaded.</p>
          )}
        </article>

        <article className="card half">
          <h3>Latest Run</h3>
          {latestRun ? <pre>{JSON.stringify(latestRun, null, 2)}</pre> : <p className="mono">No run loaded.</p>}
        </article>

        <article className="card">
          <h3>Compare Result</h3>
          {compare ? <pre>{JSON.stringify(compare, null, 2)}</pre> : <p className="mono">No compare run yet.</p>}
        </article>
      </section>
    </main>
  );
}
