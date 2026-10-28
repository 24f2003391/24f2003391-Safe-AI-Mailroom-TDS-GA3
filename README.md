# Safe AI Mailroom — TDS GA3

Public HTTPS endpoint for the `ga5-mailroom-action-gate/v2` propose/commit protocol.

## Active Render configuration

The current service is `safe-ai-mailroom-tds-ga3-or` in Oregon.

- Build: `pip install -r requirements.txt`
- Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check: `/health`
- Provider: Gemini OpenAI-compatible endpoint; `MODEL_PROVIDER=gemini`, `GEMINI_MODEL=gemini-3.8-flash`.
- Required secret environment variables: `GEMINI_API_KEY` and `DATABASE_URL`.
- PostgreSQL tables are prefixed `mailroom_` so the app can share the existing Render database without colliding with another app's tables.
- SQLite is used only when `DATABASE_URL` is unset (local development/tests).

Keep both secret values in Render's Environment settings. Do not paste them into chat or commit them to GitHub.

## Deployment note

The Blueprint describes the Oregon/Gemini service configuration. If you sync it in Render, confirm the service mapping before applying changes because the older Singapore service may still exist separately.

## Basic live smoke test

From PowerShell, run the inline `& { ... }` test block supplied in the project conversation. It checks health, root metadata, and rejection of an invalid profile without making a model request or committing receipts.
