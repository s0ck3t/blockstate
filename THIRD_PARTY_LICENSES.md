# Third-Party Subcomponent Licences & Supply-Chain Governance

**Blockstate (`blockstate`)** is engineered for regulated enterprise environments (banking, insurance, healthcare, telecommunications, and public sector). To guarantee zero copyleft contamination and full intellectual property clarity, every direct and optional subcomponent is strictly audited and enforced in Continuous Integration under **Architecture Decision `AD-12`**.

---

## 1. Enterprise Licence Policy & CI Enforcement

1. **Permissive-Only Runtime Allowlist:** All core runtime dependencies and optional v1 production extras (`postgres`, `sqlite`, `sql`, `s3`, `models`, `litellm`, `onnx`, `local`, `otel`) must be distributed under OSI-approved permissive licences:
   - `MIT`
   - `Apache-2.0`
   - `BSD-2-Clause` / `BSD-3-Clause`
   - `PSF-2.0` (Python Software Foundation License)
   - `ISC`
2. **Strict Copyleft Prohibition:** Packages licensed under `GPL-*`, `AGPL-*`, `LGPL-*`, `SSPL`, or `EUPL` are strictly prohibited anywhere in the runtime dependency tree.
3. **Automated CI Verification & SBOM Generation:**
   - Every Pull Request runs `pip-licenses --allow-only="MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;Python-2.0;ISC"` against the production environment.
   - Every release generates a cryptographically attested **CycloneDX v1.6 Software Bill of Materials (`sbom.cdx.json`)** via `cyclonedx-py` and runs `pip-audit` against the OSV/GitHub Advisory Database.

---

## 2. Core Runtime Subcomponents (`pip install blockstate`)

The core kernel (`blockstate.core`, `blockstate.compiler`, `blockstate.security`, `blockstate.ports`, `blockstate.cli`) and the built-in `InMemoryStorageBackend` maintain a minimal footprint (`<= 40MB` resident RAM) with zero cloud or database driver bloat.

| Subcomponent | Version Constraint | SPDX Licence | Purpose in Blockstate | Upstream Source |
| :--- | :--- | :--- | :--- | :--- |
| **Python Standard Library** (`ast`, `asyncio`, `hashlib`, `hmac`, `types`) | `>=3.12,<3.15` | `PSF-2.0` | Static DCG AST extraction, async event loop, SHA-256 hash chaining, `InMemoryStorageBackend`, immutable `MappingProxyType` dispatch tables | [python/cpython](https://github.com/python/cpython) |
| **pydantic** (`pydantic` + `pydantic-core`) | `>=2.14.1,<3.0` | `MIT` | `PartialSlotModel` recursive metaclass, strict schema validation, frozen wire envelopes | [pydantic/pydantic](https://github.com/pydantic/pydantic) |
| **pydantic-settings** | `>=2.16.1,<3.0` | `MIT` | 12-Factor `BlockstateSettings` configuration loading & `SecretStr` credential masking | [pydantic/pydantic-settings](https://github.com/pydantic/pydantic-settings) |
| **cryptography** | `>=50.0.2,<51.0` | `Apache-2.0` OR `BSD-3-Clause` | AES-256-GCM encryption at rest with AAD binding for `SessionCheckpoint.vault_map` in `PIIVault` | [pyca/cryptography](https://github.com/pyca/cryptography) |
| **typer** | `>=0.27.3,<1.0` | `MIT` | CLI command routing (`blockstate check`, `verify`, `trace`, `export`) | [fastapi/typer](https://github.com/fastapi/typer) |
| **rich** | `>=15.0.0,<16.0` | `MIT` | Terminal trace replay tables (`blockstate trace`) & compiler diagnostics | [Textualize/rich](https://github.com/Textualize/rich) |

---

## 3. Optional Version 1 Production Adapter Subcomponents (`blockstate[...]`)

Optional extras are completely isolated inside `blockstate.adapters.*` (`AD-1`) and are only installed when explicitly requested by the deploying enterprise. Under **Version 1 Storage Slicing (`AD-9`)**, `StorageBackend` (`src/blockstate/ports/storage.py`) ships with three canonical v1 backends:
1. **`InMemoryStorageBackend`** (stdlib — zero extra dependencies, for hermetic unit testing and CI/CD).
2. **`SQLiteStorageBackend`** (`PRAGMA journal_mode=WAL` via `aiosqlite`, for zero-dependency local development and edge deployments).
3. **`PostgresStorageBackend`** (`SQLAlchemy[asyncio]` + `asyncpg`, for cloud production workloads).

| Extra Group | Subcomponent | Version Constraint | SPDX Licence | Purpose in Blockstate | Upstream Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `models` | **pydantic-ai-slim** | `>=2.61.0,<3.0` | `MIT` | Type-safe Pass 1 structured slot extraction & Pass 2 response generation | [pydantic/pydantic-ai](https://github.com/pydantic/pydantic-ai) |
| `litellm` | **litellm** | `>=1.106.0,<1.107.0` | `MIT` | Enterprise multi-provider LLM gateway adapter *(Note: strictly pinned `<1.107.0` to exclude yanked v1.107.0)* | [BerriAI/litellm](https://github.com/BerriAI/litellm) |
| `onnx` / `local` | **onnxruntime** | `>=1.31.0,<2.0` | `MIT` | Sub-50ms local CPU/GPU System-1 intent & slot classification (`IntentClassifier`) | [microsoft/onnxruntime](https://github.com/microsoft/onnxruntime) |
| `onnx` / `local` | **tokenizers** | `>=0.23.0,<1.0` | `Apache-2.0` | Fast Rust-backed subword tokenisation for local ModernBERT / ONNX classifiers | [huggingface/tokenizers](https://github.com/huggingface/tokenizers) |
| `otel` | **opentelemetry-api** | `>=1.45.1,<2.0` | `Apache-2.0` | OpenTelemetry GenAI 1.30 semantic convention span instrumentation | [open-telemetry/opentelemetry-python](https://github.com/open-telemetry/opentelemetry-python) |
| `otel` | **opentelemetry-sdk** | `>=1.45.1,<2.0` | `Apache-2.0` | OpenTelemetry span processors and OTLP telemetry export | [open-telemetry/opentelemetry-python](https://github.com/open-telemetry/opentelemetry-python) |
| `sqlite` / `local` | **aiosqlite** | `>=0.22.1,<1.0` | `MIT` | Canonical v1 local `SQLiteStorageBackend` driver with `PRAGMA journal_mode=WAL` | [omnilib/aiosqlite](https://github.com/omnilib/aiosqlite) |
| `postgres` / `sql` | **SQLAlchemy** | `>=2.1.6,<3.0` | `MIT` | Canonical v1 async relational abstraction (`SQLAlchemy[asyncio]`) for `PostgresStorageBackend` | [sqlalchemy/sqlalchemy](https://github.com/sqlalchemy/sqlalchemy) |
| `postgres` | **asyncpg** | `>=0.32.0,<1.0` | `Apache-2.0` | Canonical v1 high-throughput async PostgreSQL JSONB driver for `PostgresStorageBackend` and `PostgresLedgerSink` | [MagicStack/asyncpg](https://github.com/MagicStack/asyncpg) |
| `s3` | **aioboto3** / **botocore** | `>=15.5.0,<16.0` / `>=1.43.0` | `Apache-2.0` | Asynchronous S3 WORM / Object-Lock archival sink for `TurnLedger` (`S3LedgerSink`) | [terrycain/aioboto3](https://github.com/terrycain/aioboto3) |

### Deferred v1.2+ StorageBackend SPI Adapters

To prevent v1 storage adapter sprawl while preserving enterprise extensibility, **Redis** (`redis-py`, `MIT`), **Microsoft SQL Server** (`aioodbc`, `MIT`), and **AWS DynamoDB** (`aioboto3`, `Apache-2.0`) state storage drivers are formally **deferred to v1.2+** behind the async `StorageBackend` SPI (`src/blockstate/ports/storage.py`). Custom or v1.2+ `StorageBackend` plugins are verified against the identical `StorageBackendContractSuite` (`StateStoreContractSuite`) and permissive licence gates.

---

## 4. Transitive Runtime Dependencies

All transitive dependencies pulled by core packages and optional extras have been audited for permissive licence compatibility:

| Transitive Package | Pulled By | SPDX Licence |
| :--- | :--- | :--- |
| `annotated-types` | `pydantic` | `MIT` |
| `typing-extensions` | `pydantic`, `SQLAlchemy`, `typer` | `PSF-2.0` |
| `cffi` / `pycparser` | `cryptography` | `MIT` / `BSD-3-Clause` |
| `click` | `typer` | `BSD-3-Clause` |
| `markdown-it-py` / `mdurl` | `rich` | `MIT` |
| `pygments` | `rich` | `BSD-2-Clause` |
| `greenlet` | `SQLAlchemy` | `MIT` |
| `httpx` / `httpcore` / `anyio` / `sniffio` | `pydantic-ai-slim`, `litellm` | `BSD-3-Clause` / `MIT` |

---

## 5. Development, Testing & Security Tooling (Non-Runtime)

These packages are used exclusively during local development and CI/CD execution (`[dependency-groups.dev]`). None are bundled into or imported by the distributed `blockstate` wheel.

| Tool | Version Constraint | SPDX Licence | Role in Architecture & CI |
| :--- | :--- | :--- | :--- |
| **uv** & **hatchling** | `>=0.13.6` / `>=1.27.0` | `MIT` / `Apache-2.0` | Deterministic package/lockfile management (`uv.lock`) and PEP 621 wheel builder |
| **pytest** | `>=9.1.1,<10.0` | `MIT` | Unit, boundary, integration, and `ContractSuite` test runner |
| **pytest-asyncio** | `>=1.4.0,<2.0` | `Apache-2.0` | Async test coroutine execution |
| **pytest-cov** / **coverage** | `>=7.1.0` / `>=7.8.0` | `MIT` / `Apache-2.0` | Line and branch coverage gate enforcement (`>=95%` core, `>=90%` overall) |
| **hypothesis** | `>=6.170.0,<7.0` | `MPL-2.0` | Property-based fuzzing for `PartialSlotModel` & Lengauer-Tarjan graphs *(Dev-only; never distributed)* |
| **ruff** | `>=0.17.0,<1.0` | `MIT` | Ultra-fast Rust linter and code formatter |
| **mypy** | `>=2.4.0,<3.0` | `MIT` | Strict PEP 695 / PEP 561 static type verification (`mypy --strict`) |
| **pyright** | `>=1.1.414,<2.0` | `MIT` | Secondary static type checker verifying IDE and protocol inference |
| **import-linter** | `>=2.15.1,<3.0` | `BSD-3-Clause` | Enforces Hexagonal Architecture (`AD-1`) forbidden-import boundaries |
| **gitleaks** | `>=8.30.1` | `MIT` | Pre-commit and CI cryptographic secret scanner |
| **detect-secrets** | `>=1.5.0` | `Apache-2.0` | Pre-commit high-entropy credential and DSN scanner |
| **pip-licenses** | `>=5.5.5` | `MIT` | Automated SPDX licence compliance verification |
| **cyclonedx-bom** | `>=7.5.0,<8.0` | `Apache-2.0` | CycloneDX SBOM generation (`sbom.cdx.json`) |
| **bandit** & **pip-audit** | `>=1.9.4` / `>=2.10.1` | `Apache-2.0` | Python SAST analysis and CVE dependency vulnerability auditing |
