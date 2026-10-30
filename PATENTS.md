# Statutory Patent Notice & Commercial Patent Licensing (`PATENTS.md`)

## 1. United Kingdom Patent Pending Notice

Notice is hereby given in accordance with **Section 62(1) of the United Kingdom Patents Act 1977** (and **35 U.S.C. § 287** virtual patent marking provisions) that the **Blockstate (`blockstate`)** software runtime, compiler, and architecture are the subject of a pending patent application filed with the **United Kingdom Intellectual Property Office (UKIPO)**:

- **Jurisdiction**: United Kingdom (UKIPO) with international Paris Convention priority rights reserved
- **Official Publication Title**: *Process execution control system*
- **Priority Filing Date**: 28 October 2026
- **Status**: **UK Patent Pending** (Application and Form PF2 Official Search Request filed)

---

## 2. Scope of Patented Architecture

The pending patent application covers the core computer-implemented system, method, and enclave execution architecture implemented in this repository, including:

1. **Compile-Time Declarative Control Grammar (DCG) AST Verification**: Static abstract syntax tree extraction of stage methods and transition directives, rejecting dynamic `getattr` reflection and non-literal transition targets (`BLK-AST-014`).
2. **Lengauer-Tarjan Dominator Tree Precursor Verification**: Compile-time calculation of reflexive dominator sets over the extracted statechart control-flow graph to mathematically verify that mandatory precursor stages (such as identity verification or regulatory disclosure) strictly dominate privileged target stages, with breadth-first counterexample bypass path synthesis on violation (`BLK-AST-002`).
3. **Stage-Scoped Ephemeral `MappingProxyType` Tool Gatekeeping**: Runtime construction of read-only memory-proxy dispatch tables and filtered outbound tool schemas scoped exclusively to the active stage whitelist (`BLK-SEC-001`), with deep-frozen `ReadOnlySessionView` context injection and selective `Detokenise[T]` volatile memory parameter unwrapping.
4. **Two-Tier Memory Isolation & Bounded Pushdown Automaton (`TaskStack`)**: Stack-isolated digression `TaskFrame` suspension and resumption with depth-bounded circuit breakers (`BLK-SEC-003`) and locked dot-separated leaf-path mutation guards (`BLK-SEC-002`).
5. **Progressive Leaf-Path Schema Hydration & Volatile Detokenisation**: Recursive `PartialSlotModel` synthesis (`UNSET` union relaxation), per-leaf validation (`BLK-VAL-002` / `BLK-VAL-003`), and scoped volatile-memory detokenisation during field-validator execution without persistent plaintext storage.
6. **Cryptographic Vault (`PIIVault`), Revision-Bound AEAD & Hash-Chained Ledger**: Deterministic checksum-verified PII detection (including Luhn modulo-10 and NHS Modulus-11 check digits), keyed `HMAC-SHA256` session deduplication, `AES-256-GCM` token-map encryption bound to `session_id:schema_version:revision_id` Associated Authenticated Data (AAD), and RFC 8785 JSON Canonicalisation Scheme (JCS) SHA-256 hash-chained `TurnLedgerRecord` persistence with local Write-Ahead Log (`.blockstate/wal/ledger.wal`) recovery.

---

## 3. How Patent Licensing Works for Users & Contributors

Blockstate separates **open developer exploration** from **commercial production monetisation** (see [`LICENSE`](LICENSE)):

| Usage Scenario | Copyright & Patent Status | Fee / Agreement Required |
| :--- | :--- | :--- |
| **Local Development, Academic Research & Open-Source CI (`blockstate verify`)** | Covered by the conditional Community & Evaluation covenant in [`LICENSE`](LICENSE) Section 1 | **Free (£0)** |
| **90-Day Internal Enterprise Prototyping & Security Auditing** | Covered by the time-bounded Evaluation licence in [`LICENSE`](LICENSE) Section 1(c) | **Free (£0)** |
| **Commercial Production Deployment (FinTech, InsurTech, HealthTech, Telco, Enterprise)** | Requires a Commercial Enterprise & Patent Licence under [`LICENSE`](LICENSE) Section 2 | **Commercial Subscription / Node Licence** |
| **Managed Cloud Hosting, SaaS Embedding, or Compliance-as-a-Service** | Requires an OEM / Commercial Patent Licence under [`LICENSE`](LICENSE) Section 2(b) | **Commercial OEM Agreement** |

For commercial production licensing, enterprise architecture pilots, or OEM partnerships, please open an inquiry via the repository issue tracker or contact the maintainer directly.
