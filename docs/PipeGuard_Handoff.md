# PipeGuard: Project Handoff Doc

## Context for the assistant reading this
I'm a B.Tech CSE (Cyber Security specialization) student at VIT, applying to the **American Express Enterprise Technology Services InfoSecurity hiring event** (online assessment, then 2 virtual interview rounds). I want to build one strong, resume-worthy DevSecOps project and **understand every part of it well enough to defend it in an interview**.

**How I want you to help:**
- Build this with me phase by phase, not all at once.
- For every tool or config, explain *what it does* and *why it exists* before or after writing it.
- Point out likely interview questions as we go.
- Prefer free, open-source tools that run locally or on GitHub's free tier.

---

## 1. Project summary
**PipeGuard** is an end-to-end DevSecOps pipeline that secures a small payment microservice system from commit to deployment. It includes custom PCI-focused code rules, policy-as-code security gates, signed container images enforced at deploy time, and a central findings dashboard.

**Why it fits Amex:** Amex is a payments company that ships software as containers on Kubernetes at large scale. This project shows application security, supply-chain security, cloud-native security, and payments-domain awareness together.

---

## 2. Tech stack
| Layer | Choice |
|---|---|
| App | Python FastAPI (2 services) + PostgreSQL |
| Containers | Docker, docker-compose |
| CI/CD | GitHub Actions |
| Local Kubernetes | kind (or minikube) |
| Secrets scanning | Gitleaks (pre-commit + CI) |
| SAST | Semgrep with custom rules |
| SBOM | Syft (CycloneDX format) |
| SCA / vuln scan | Grype and/or Trivy |
| IaC scanning | Checkov |
| Container scan | Trivy |
| DAST | OWASP ZAP (baseline/API scan) |
| Policy gate | OPA / Rego via Conftest |
| Image signing | Cosign (Sigstore) |
| Admission control | Kyverno |
| Results format | SARIF |
| Dashboard | DefectDojo (Docker) + GitHub Code Scanning |

---

## 3. Architecture (flow)
```
Developer commit
   │
   ├─ pre-commit hook: Gitleaks (blocks secrets locally)
   ▼
Pull Request → GitHub Actions pipeline
   ├─ Stage 1: Secrets scan (Gitleaks, full history)
   ├─ Stage 2: SAST (Semgrep + custom PCI rules)
   ├─ Stage 3: Build Docker images
   ├─ Stage 4: SBOM (Syft) → SCA (Grype/Trivy)
   ├─ Stage 5: IaC scan (Checkov on Dockerfiles, K8s YAML, Terraform)
   ├─ Stage 6: Container image scan (Trivy)
   ├─ Stage 7: DAST (spin up app via docker-compose → OWASP ZAP)
   ├─ Stage 8: Normalize all results → SARIF
   ├─ Stage 9: Policy gate (Conftest/OPA + waiver file) → PASS / FAIL
   └─ Stage 10 (on pass): Sign image with Cosign → push to registry
   │
   ├─ SARIF → GitHub Code Scanning (inline PR comments)
   └─ Findings → DefectDojo (tracking over time)
   ▼
Kubernetes (kind) + Kyverno
   └─ Admission policy: reject any image NOT signed by the pipeline
```

---

## 4. The target app
Two FastAPI services, running with Docker and Postgres:

**auth-service:** register, login, issue JWT.
**payment-service:** create payment, tokenize card, list my transactions, get transaction by ID.

### Deliberately seeded vulnerabilities
Each one must be caught by a specific stage. This table goes in the README.

| # | Vulnerability | Where | Caught by |
|---|---|---|---|
| 1 | Hardcoded API key / DB password | config file | Gitleaks |
| 2 | SQL injection (string-formatted query) | payment-service | Semgrep |
| 3 | Full card number (PAN) written to logs | payment-service | Custom Semgrep rule |
| 4 | JWT created without expiry | auth-service | Custom Semgrep rule |
| 5 | `verify=False` on HTTPS requests | payment-service | Custom Semgrep rule |
| 6 | Weak password hashing (MD5) | auth-service | Semgrep |
| 7 | Outdated library with known CVE | requirements.txt | Grype / Trivy (SCA) |
| 8 | Vulnerable OS package in base image | Dockerfile | Trivy (image) |
| 9 | Container runs as root | Dockerfile | Checkov |
| 10 | Privileged / no resource limits | K8s manifest | Checkov |
| 11 | Missing security headers | running app | OWASP ZAP |
| 12 | Broken access control (IDOR: user can read another user's transaction) | payment-service | Custom test / ZAP + manual |

Keep a `vulnerable` branch and a `fixed` branch to demo before/after.

---

## 5. Pipeline stages in detail

**Secrets (Gitleaks):** Runs as a pre-commit hook and in CI over the full git history. Detects secrets via regex patterns and entropy checks.

**SAST (Semgrep):** Uses community rulesets plus **8+ custom rules** in `security/semgrep-rules/`. Custom rule ideas: PAN patterns in logging calls, JWT without `exp`, TLS verification disabled, raw SQL string formatting, debug mode enabled, CORS set to `*`, secrets read from code instead of env, MD5/SHA1 for passwords.

**SBOM + SCA:** Syft generates a CycloneDX SBOM from each image (store it as a build artifact). Grype/Trivy checks the SBOM for known CVEs.

**IaC (Checkov):** Scans Dockerfiles, `k8s/` manifests, and any Terraform.

**Container scan (Trivy):** Scans built images, including OS packages.

**DAST (OWASP ZAP):** CI starts the full stack with docker-compose, waits for health checks, runs a ZAP baseline/API scan against the OpenAPI spec, then tears it down.

**SARIF normalization:** Every tool outputs SARIF (natively or via conversion). Upload to GitHub Code Scanning so findings appear on the PR.

---

## 6. Policy-as-code gate (Conftest / OPA)
Policies live in `security/policies/*.rego`. Rules:
- FAIL on any critical or high finding.
- FAIL on any detected secret, with no waivers allowed.
- FAIL on any PAN-in-logs finding, with no waivers allowed (PCI).
- WARN on medium findings.
- ALLOW waivers from `security/waivers.yaml` only if each waiver has: finding ID, reason, owner, and an **expiry date**. Expired waivers are ignored, so the build fails again.

This mirrors how enterprises handle accepted risk.

---

## 7. Signing and deploy-time enforcement
- On pass, the pipeline signs the image with **Cosign** (keyless via GitHub OIDC, or a key pair stored in GitHub Secrets).
- Deploy to **kind** with **Kyverno** installed.
- Kyverno policy: only allow images from our registry that carry a valid Cosign signature. Unsigned or tampered images are rejected.
- Demo: try deploying an unsigned image and show the rejection.

**Key interview point:** Scanning proves the image *was* safe; signing proves the image running is *the same one* that was scanned. Kyverno enforces that even if someone bypasses CI.

---

## 8. Dashboard (DefectDojo)
- Run DefectDojo locally with Docker.
- A CI step imports each tool's results via the DefectDojo API.
- Track status per finding: open, fixed, false positive, risk accepted.
- Screenshot the dashboard for the README.

---

## 9. Metrics to report
- Findings caught per stage
- Seeded vulnerabilities detected (target: 12/12)
- False-positive rate of custom Semgrep rules
- Pipeline run time
- Time from detection to fix (from the vulnerable → fixed branch)

---

## 10. Suggested repo structure
```
pipeguard/
├── services/
│   ├── auth-service/
│   └── payment-service/
├── docker-compose.yml
├── k8s/
│   ├── deployments/
│   └── kyverno-policies/
├── security/
│   ├── semgrep-rules/
│   ├── policies/          # Rego for Conftest
│   ├── waivers.yaml
│   └── zap/
├── .github/workflows/
│   └── pipeguard.yml
├── .pre-commit-config.yaml
├── docs/
│   ├── architecture.png
│   └── threat-model.md
└── README.md
```

---

## 11. Build phases (each one works on its own)
1. **App:** Two FastAPI services + Postgres + docker-compose, with seeded vulns.
2. **Secrets + SAST:** Gitleaks pre-commit and CI; Semgrep with custom rules.
3. **SBOM + SCA + container scan:** Syft, Grype/Trivy.
4. **IaC:** K8s manifests + Checkov.
5. **Policy gate:** Conftest + Rego + waiver file.
6. **DAST:** Ephemeral app in CI + ZAP.
7. **Signing + Kyverno:** Cosign, kind cluster, admission policy.
8. **Dashboard + metrics:** SARIF → GitHub, DefectDojo import, README.

---

## 12. README deliverables
- Architecture diagram
- STRIDE threat model for the payment service (`docs/threat-model.md`)
- Seeded-vulnerability table with the catching stage
- Before/after pipeline results
- Short demo video: a PR getting blocked, then an unsigned image rejected by Kyverno

---

## 13. Resume bullet (fill in real numbers at the end)
*Built PipeGuard, a DevSecOps pipeline for a payment microservice integrating SAST, SCA, IaC, container, and DAST scanning with OPA policy-as-code gates and Cosign image signing enforced via Kyverno; wrote [N] custom Semgrep rules for PCI-sensitive patterns, detecting [X/12] seeded vulnerabilities before deployment.*

---

## 14. Interview questions I should be able to answer
- Why sign images if you already scanned them?
- SAST vs DAST vs SCA: what does each catch that the others miss?
- Why scan full git history for secrets? What do you do if a secret leaks?
- What's an SBOM and how would it help during something like Log4Shell?
- Why policy-as-code instead of hardcoded thresholds? Why do waivers need expiry?
- How do you handle false positives without developers ignoring the tool?
- What happens if someone deploys directly to the cluster, bypassing CI?
- What is IDOR and why didn't most scanners catch it?
- How does PCI DSS relate to tokenization and card numbers in logs?
- Why run DAST in an ephemeral environment instead of production?

---

## 15. Glossary (quick reference)
- **Gitleaks:** Finds secrets in code and git history using regex + entropy.
- **SAST:** Analyzes source code without running it.
- **SCA:** Checks third-party libraries for known CVEs.
- **SBOM:** Ingredients list of all software components and versions.
- **Syft:** Generates SBOMs.
- **Trivy / Grype:** Vulnerability scanners for images and dependencies.
- **IaC:** Infrastructure defined as code files; Checkov scans them.
- **DAST:** Attacks the running app from outside.
- **OPA / Rego / Conftest:** Policy language and tool to evaluate data against rules.
- **Cosign:** Signs and verifies container images.
- **Kyverno:** Kubernetes admission controller enforcing policies at deploy time.
- **SARIF:** Standard JSON format for security findings.
- **DefectDojo:** Open-source vulnerability management dashboard.
- **Docker's role here:** Images are needed for scanning, signing, and Kyverno enforcement; docker-compose gives DAST a reproducible running app; it matches how enterprises ship software.
