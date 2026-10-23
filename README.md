# Safe AI Mailroom — TDS GA3

A FastAPI service for the `ga5-mailroom-action-gate/v2` propose/commit protocol.

## Deploy on Render

1. Push this repository to GitHub.
2. In Render, choose **New → Blueprint** and select this repository. Render reads `render.yaml`.
3. Set `OPENAI_API_KEY` in the service environment. Do not put the key in GitHub or in the submitted endpoint URL.
4. Deploy, then check `https://YOUR-SERVICE.onrender.com/health`.
5. Submit the service base URL (no credentials, query string, or fragment). The POST endpoint is `/`.

## Local run

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY="your-key"
uvicorn main:app --reload --port 8000
```

## Important implementation notes

- Request hashing uses recursively key-sorted compact UTF-8 JSON.
- Decisions are cached by canonical dossier content.
- Proposal and evaluation state, plus terminal commits, are stored in SQLite.
- Commit verifies the supplied Ed25519 signature and exact receipt scope before storing any outcomes.
- The model is asked to return one constrained JSON proposal; application code validates action schema and evidence IDs.
- No outbound email or external business action is performed. A verified accepted receipt records the grader's authorized outcome.

**Durability note:** SQLite on a free Render web service's local filesystem may be lost when the instance is replaced. For strict durable-state marks, use a persistent disk or managed PostgreSQL and adapt the storage layer before final Save. The free service filesystem is not a substitute for durable storage.
