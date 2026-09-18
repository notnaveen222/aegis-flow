# Seeded Vulnerabilities (`vulnerable` branch)

Each flaw is planted for one specific detector. A pipeline run on this branch must fail, and the README reports which detector fired for each row. Search the code for `SEEDED FLAW #n` to find the exact lines.

| # | Vulnerability | File | Expected detector | Severity |
|---|---|---|---|---|
| 1 | Hardcoded AWS key pair, DB password, JWT secret | `auth-service/app/config.py` | Gitleaks; custom Semgrep `hardcoded-secret-default` | Critical |
| 2 | SQL injection via f-string query | `payment-service/app/routes.py` `list_transactions` | Semgrep community `sqlalchemy-execute-raw-query`; custom `raw-sql-string-format` | High |
| 3 | Full card number (PAN) written to logs | `payment-service/app/routes.py` `tokenize_card` | Custom Semgrep `pan-in-logs` | High (PCI) |
| 4 | JWT issued without `exp` | `auth-service/app/security.py` | Custom Semgrep `jwt-missing-expiry` | High |
| 5 | `verify=False` on outbound HTTPS | `payment-service/app/notify.py` | Semgrep community `disabled-cert-validation`; custom `tls-verify-disabled` | High |
| 6 | Unsalted MD5 password hashing | `auth-service/app/security.py` | Semgrep community insecure-hash; custom `weak-password-hash` | High |
| 7 | urllib3 1.26.15 (CVE-2023-43804), requests 2.25.1 (CVE-2023-32681) | `payment-service/requirements.txt` | Trivy SCA on Syft SBOM | High |
| 8 | Stale base image `python:3.12.0-slim` (Oct 2023) | both `Dockerfile`s | Trivy image scan (OS packages) | High/Critical |
| 9 | Container runs as root | both `Dockerfile`s | Checkov `CKV_DOCKER_3` | Medium |
| 10 | Privileged pod, no resource limits | `k8s/` (added in Phase 4) | Checkov `CKV_K8S_*` | High |
| 11 | Missing security headers | both `app/main.py` | OWASP ZAP baseline | Medium |
| 12 | IDOR: any user reads any transaction | `payment-service/app/routes.py` `get_transaction` | `tests/test_payment_service.py::test_user_cannot_read_another_users_transaction` | High |

## Extra custom-rule targets (not counted in the 12)

| Pattern | File | Rule |
|---|---|---|
| `debug=True` on FastAPI | both `app/main.py` | `fastapi-debug-enabled` |
| CORS `allow_origins=["*"]` with credentials | both `app/main.py` | `cors-wildcard-origin` |

## Manual exploitation (for the demo)

```bash
# 2. SQL injection: return every user's transactions
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8002/api/v1/transactions?merchant=x'%20OR%20'1'%3D'1"

# 12. IDOR: read transaction 1 as any authenticated user
curl -H "Authorization: Bearer $OTHER_USER_TOKEN" http://localhost:8002/api/v1/transactions/1

# 3. PAN in logs
docker compose logs payment-service | grep tokenized

# 4. Token without expiry
python -c "import jwt,sys; print(jwt.decode(sys.argv[1], options={'verify_signature': False}))" "$TOKEN"
```

## Branch policy

`vulnerable` is never merged into `main`. It is rebased on `main` only when the clean app changes in a way the seeded flaws depend on.
