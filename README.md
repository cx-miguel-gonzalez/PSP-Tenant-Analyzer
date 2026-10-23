# PSP-Tenant-Analyzer

PSP Tool used to review a customer tenant and be able to generate a health report with some recommendations on how to improve onboarding or implementation.

A local Flask console that authenticates to a Checkmarx One tenant, syncs 8 review areas into a local SQLite cache, and surfaces a health/recommendations overview:

- Global Configurations
- Preset Management
- Scan Health
- Integrations
- Feedback Apps and Profiles
- Policies
- Project/Application Management
- Stale Projects

Every page renders from the local cache -- sync per section (or "Sync All") to refresh it. Credentials and tokens live only in memory for the life of the process; nothing is written to disk except the synced tenant data in `data/`.

## Running it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional: pre-fill tenant credentials
python app.py
```

Then open http://localhost:8888 and sign in with a Checkmarx One API key or client id/secret.

Some endpoints (SCM connections, ticketing "feedback" profiles, policy management) are best-effort against Checkmarx One's documented API surface and haven't been confirmed against a live tenant -- see the endpoint-confidence notes in `cx_client.py`. If one 404s on your tenant, that section's sync degrades to an empty state with an explanatory message instead of failing.
