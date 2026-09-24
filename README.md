# aegisFlow

An end-to-end DevSecOps pipeline that secures a small payment microservice system from commit to cluster admission: secret scanning, SAST with custom PCI-focused rules, SCA with SBOM generation, container and IaC scanning, DAST, an OPA/Rego policy gate with expiring waivers, and keyless image signing enforced at admission by Kyverno.

See `docs/PipeGuard_Handoff.md` for the original plan and `docs/decisions.md` for design decisions.

## The pipeline

One GitHub Actions workflow (`.github/workflows/pipeline.yml`), one shape throughout: every scan stage reports as SARIF and does not fail its own job. A single policy-gate job evaluates every SARIF file against `policy/gate.rego` plus `policy/waivers.yml` and is the only place that decides pass or fail. Signing and the Kyverno admission demo only run after the gate passes on a direct push to `main`.

| Stage | Tool | What it catches |
|---|---|---|
| Secret scanning | Gitleaks | Hardcoded credentials, full git history, every branch scanned on its own history |
| SAST | Semgrep (community rulesets + 3 custom rules) | SQLi, weak hashing, CORS misconfig, disabled TLS verification, PAN in logs, JWTs issued without expiry |
| SCA + SBOM | Trivy (`fs`) | Known-CVE dependencies, CycloneDX SBOM per service |
| Container scan | Trivy (`image`) | OS package CVEs baked into the built image |
| IaC scan | Checkov | Privileged pods, missing resource limits, missing NetworkPolicy, root containers |
| DAST | OWASP ZAP baseline | Missing security headers, other runtime findings — plus the same pytest integration suite used locally, including an IDOR test no scanner can write |
| Policy gate | OPA/Conftest (`policy/gate.rego`) | Aggregates every SARIF file; blocks on unwaived findings; an expired waiver fails the gate on its own |
| Signing + admission | Cosign (keyless, GitHub OIDC) + Kyverno | Images signed by digest; a `kind` cluster proves a signed image is admitted and an unsigned one is rejected |

The `vulnerable` branch seeds 12 deliberate flaws (SQLi, IDOR, hardcoded secrets, and more — see `docs/seeded-vulnerabilities.md`) and is never merged into `main`; the pipeline is expected to fail there, which is the point.

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
