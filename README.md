# aegisFlow

An end-to-end DevSecOps pipeline that secures a small payment microservice system from commit to deployment: custom PCI-focused Semgrep rules, policy-as-code gates, signed container images enforced at admission time, and a central findings dashboard.

> Work in progress. Phase 1 (target application) is complete. See `docs/PipeGuard_Handoff.md` for the full plan and `docs/decisions.md` for design decisions.

## The target application

Two FastAPI services and PostgreSQL, run with Docker Compose.

| Service | Port | Responsibilities |
|---|---|---|
| auth-service | 8001 | Register, login, issue JWTs (Argon2id password hashing, 30-minute tokens) |
| payment-service | 8002 | Tokenize cards, create payments, list and fetch a user's own transactions |
| postgres | internal only | Storage for both services |

## Run it

```bash
cp .env.example .env          # then set strong values for POSTGRES_PASSWORD and JWT_SECRET
docker compose up --build -d
```

Interactive API docs: <http://localhost:8001/docs> and <http://localhost:8002/docs>.

## Test it

Integration tests run over HTTP against the live stack, including an IDOR test that no scanner in the pipeline can write for us.

```bash
python -m venv .venv
.venv/Scripts/pip install -r tests/requirements.txt     # Windows
pytest
```
