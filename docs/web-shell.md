# Next.js Web Shell

Location:

- `/Users/seungyoo/Desktop/ai-agent-platform/web`

Purpose:

- Product-facing shell for agent operations on top of backend APIs.
- Streamlit remains the internal ops/debug console.

Run locally:

```bash
cd /Users/seungyoo/Desktop/ai-agent-platform/web
npm install
npm run dev
```

Open:

- `http://127.0.0.1:3000`

Shell currently includes:

- API connection setup
- agent loading and selection
- launch gate + latest run load
- compare-by-reference (`agent_id + baseline_ref + candidate_ref`)
