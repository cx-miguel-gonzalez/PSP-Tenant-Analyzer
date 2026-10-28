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

### With Docker

```bash
cp .env.example .env   # optional: pre-fill tenant credentials
docker compose up -d --build
```

Then open http://localhost:8888. The compose file passes `.env` to the container as environment variables, and the image never includes the file. Synced tenant data is kept in the `tenant-data` volume, so it survives restarts and rebuilds. The port is published on localhost only. To reach the app from other machines, change it to `"8888:8888"` in `docker-compose.yml`.

Without compose:

```bash
docker build -t psp-tenant-analyzer .
docker run -d -p 127.0.0.1:8888:8888 --env-file .env -v tenant-data:/data psp-tenant-analyzer
```

#### With Podman

The same image runs under Podman:

```bash
podman build --format docker -t psp-tenant-analyzer .
podman run -d --name tenant-analyzer \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8888:8888 \
  --env-file .env \
  -v tenant-data:/data \
  psp-tenant-analyzer
```

- Build with `--format docker`. Podman's default OCI format drops the Dockerfile's `HEALTHCHECK`, and `podman healthcheck run tenant-analyzer` then reports none.
- `--env-file .env` is optional. Without it, you sign in through the form.
- `podman compose up -d --build` also works when the `docker-compose` binary is installed. The separate Python `podman-compose` tool may not accept the compose file's optional `.env` entry (`required: false`).

The container runs gunicorn with a single worker on purpose. Sign-ins and sync progress live in that process's memory, so don't scale it beyond one worker or replica. Set `FLASK_SECRET_KEY` if you want sessions to survive a container restart.

Some endpoints (SCM connections, ticketing "feedback" profiles, policy management) are best-effort against Checkmarx One's documented API surface and haven't been confirmed against a live tenant -- see the endpoint-confidence notes in `cx_client.py`. If one 404s on your tenant, that section's sync degrades to an empty state with an explanatory message instead of failing.
