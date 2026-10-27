# Security Policy & Zero-Trust Threat Model (`blockstate`)

## 1. Zero-Trust Architectural Guarantees

Blockstate is built specifically for high-assurance, regulated enterprise deployments where autonomous LLM actions pose unacceptable operational or legal risk:

1. **Physical Tool Isolation (`AD-3`):** Unpermitted tools do not exist in the model's prompt schema or the runtime's `MappingProxyType` dispatch table. Prompt injection cannot invoke a tool that is physically absent from the active `@Stage` memory boundary.
2. **Zero Dynamic Code Execution & Declarative Control Grammar (`AD-4`):** Blockstate never calls `eval()`, `exec()`, or dynamic string imports. To respect Rice's Theorem, all control flow must be expressed through the static **Declarative Control Grammar (DCG)** (`@Stage`, `@Transition`, `@Guard`). `blockstate check` and `blockstate verify` inspect Python source code strictly via `ast.parse` without executing user code and immediately terminate builds with `[Blockstate E014]` if dynamic reflection (such as `getattr(self, dynamic_state)()`) or non-static transition destinations are detected.
3. **Tokenised PII Boundary (`AD-7`):** `PIIVault.sanitise()` strips sensitive identifiers (National Insurance Numbers, NHS Numbers, SSNs, Postcodes, Credit Cards, Emails, Phone Numbers) at ingress, replacing them with HMAC-keyed session tokens (`<VAULT:TYPE_NN>`). Raw PII is encrypted at rest via AES-256-GCM inside `SessionCheckpoint.vault_map` and never enters LLM prompts, OpenTelemetry spans, or `.blockstate/traces.jsonl`.
4. **Tamper-Evident Audit Chain (`AD-8`):** Every turn produces a deterministic RFC 8785 JCS canonical JSON record chained via SHA-256 (`prev_record_hash`) in `TurnLedger`.
5. **Pre-Commit Secret & PII Gate (`AD-13`):** All contributors must run the repository's `.pre-commit-config.yaml` hooks (`gitleaks`, `detect-secrets`, `blockstate-pii-guard`, and `.env` blocker).

## 2. Supply-Chain Hygiene Note (`litellm`)

In accordance with our supply-chain verification gate (`AD-12`), the optional `blockstate[litellm]` extra explicitly pins `litellm>=1.106.0,<1.107.0` to exclude the yanked `1.107.0` upstream release, and `pip-audit` runs continuously in CI.

## 3. Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

- **Email:** `security@blockstate.dev` (or via GitHub Private Vulnerability Reporting in the Security tab).
- **SLA:** We acknowledge receipt within **24 hours**, provide a triage assessment within **72 hours**, and coordinate embargoed patches and CVE disclosures for verified findings.
