# Safe AI Mailroom — TDS GA3

Public HTTPS endpoint for the `ga5-mailroom-action-gate/v2` propose/commit protocol.

## Deploy on Render

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Required environment variables: `OPENAI_API_KEY`, `DATABASE_URL` (PostgreSQL connection URL), optional `OPENAI_MODEL` (defaults to `gpt-4o-mini`).
- The service supports PostgreSQL through psycopg and keeps SQLite as a local-development fallback when `DATABASE_URL` is unset.
- Mailroom tables are prefixed `mailroom_` so this app can share the existing Render Postgres instance with a separate app without colliding with its tables.

## Configure the existing Render PostgreSQL instance

The workspace's free-tier limit permits only one active free Postgres instance. Use the existing instance `a2a-invoice-agent-ga3-db`, but **do not drop, rename, or alter the invoice agent's tables**. In Render Dashboard, open that database, copy its **Internal Database URL**, then open the `safe-ai-mailroom-tds-ga3` web service → Environment and add `DATABASE_URL` with that URL. Keep the value secret; do not paste it into chat or commit it to GitHub. The two apps use separate table names.

After setting `DATABASE_URL`, redeploy the web service. Existing SQLite records will not be migrated automatically; this is acceptable before grader use, but don't switch backends after graded evaluations begin unless you plan a migration.

## Test

Run `powershell -ExecutionPolicy Bypass -File .\\test-mailroom-smoke.ps1` after deployment. The test is synthetic and does not consume a graded Check/Save.
