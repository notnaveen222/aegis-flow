# aegisFlow: Design Decisions

Decisions made before Phase 1 (18 Sep 2026). Each records the choice, the alternative rejected, and the reason.

| # | Decision | Rejected | Why |
|---|---|---|---|
| 1 | Trivy for both SCA and image scanning | Grype alongside Trivy | One scanner covers dependencies, OS packages, and SBOM input. Two overlapping scanners produce duplicate findings with no extra coverage. Trivy emits SARIF natively. |
| 2 | Cosign keyless signing via GitHub OIDC, images pushed to GHCR | Long-lived key pair in GitHub Secrets | No private key to store, leak, or rotate. Signature is bound to the exact workflow identity, so Kyverno can verify *who* signed, not just *that* it was signed. Signatures are recorded in the Rekor transparency log. |
| 3 | DefectDojo runs locally in Docker; CI imports via a tunnel URL held in a secret; import step skips gracefully when the secret is absent | Manual import only; cloud-hosted DefectDojo | Manual import is not real integration. Free-tier VMs lack the RAM DefectDojo needs. Graceful skip means the pipeline never fails because the laptop is off. GitHub Code Scanning is the always-on dashboard. |
| 4 | `main` holds the fixed app; a `vulnerable` branch holds the 12 seeded flaws and is never merged | Two evolving `vulnerable`/`fixed` branches | Two long-lived branches drift and double the maintenance. Pipeline history on each branch is the before/after evidence. |
| 5 | Develop on native Windows with Docker Desktop; WSL2 only if a tool requires it | WSL2 for everything | Most tools run as containers, so host OS matters little. Fewer moving parts. |
| 6 | IDOR is caught by a dedicated pytest in CI, documented as a scanner blind spot | Rely on ZAP to find it | IDOR is a business-logic flaw. SAST, SCA, and DAST have no model of resource ownership. Logic flaws need tests written by someone who understands the logic. |
| 7 | Scope locked to exactly the tools on the resume (Gitleaks, Semgrep, Trivy, Checkov, ZAP, OPA/Conftest, Cosign, Kyverno); Syft and DefectDojo dropped | Building everything in the original handoff plan | Every claimed tool has to be built and explainable before an interview. Trivy already generates SBOMs natively, so Syft was redundant once decision #1 picked Trivy alone. DefectDojo (decision #3) was never built — supersedes that row below; GitHub code scanning is the findings dashboard that actually exists. |

**Superseded:** Decision #3 (DefectDojo) was made before decision #7 locked scope to the resume. DefectDojo does not exist in this repo; every SARIF-producing stage uploads directly to GitHub code scanning instead.
