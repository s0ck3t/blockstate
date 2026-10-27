"""Blockstate settings and configuration management.

Provides hardened 12-factor configuration loading via Pydantic BaseSettings
with automated SecretStr masking for sensitive credentials and connection strings.
"""

from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class BlockstateSettings(BaseSettings):
    """Enterprise 12-factor configuration settings for Blockstate runtime."""

    model_config = SettingsConfigDict(
        env_prefix="BLOCKSTATE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # 1. Core Runtime & Execution Environment
    env: Literal["development", "testing", "staging", "production"] | str = "development"
    app_name: str = "blockstate-enterprise-agent"
    log_level: str = "INFO"
    log_json: bool = False
    default_max_turns: int | None = 5
    max_slot_nesting_depth: int = 8
    max_task_stack_depth: int = 6

    # 2. Zero-Trust PIIVault & Cryptographic Key Management
    pii_vault_enabled: bool = True
    vault_secret_key: SecretStr = Field(default_factory=lambda: SecretStr(""))
    vault_fallback_keys: SecretStr = Field(default_factory=lambda: SecretStr(""))
    vault_hmac_pepper: SecretStr = Field(default_factory=lambda: SecretStr(""))
    pii_detector_profile: str = "uk_fca_gdpr"

    # 3. Version 1 StorageBackend SPI & Session Leasing
    storage_backend: Literal["memory", "sqlite", "postgres"] | str = "sqlite"
    sqlite_dsn: str = "sqlite+aiosqlite:///./.blockstate/state.db"
    sqlite_journal_mode: str = "WAL"
    postgres_dsn: SecretStr = Field(default_factory=lambda: SecretStr(""))
    postgres_pool_size: int = 20
    postgres_max_overflow: int = 10
    database_port: int | None = None

    # Distributed Lease & Concurrency Control
    lease_wait_timeout_ms: int = 2000
    lease_ttl_ms: int = 30000
    lease_heartbeat_ms: int = 10000

    # 4. Tamper-Evident TurnLedger & Graceful WAL Drain
    ledger_sinks: str = "file"
    ledger_wal_dir: str = "./.blockstate/wal"
    ledger_buffer_max_size: int = 10000
    ledger_shutdown_drain_seconds: int = 10

    # S3 Immutable Audit Sink
    ledger_s3_bucket: str | None = None
    ledger_s3_region: str = "eu-west-2"
    ledger_s3_prefix: str = "blockstate/turn-ledger/"
    aws_access_key_id: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        validation_alias=AliasChoices("BLOCKSTATE_AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"),
    )
    aws_secret_access_key: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        validation_alias=AliasChoices("BLOCKSTATE_AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"),
    )

    # 5. Two-Pass Model Layer
    pass1_backend: str = "onnx_local"
    pass1_timeout_ms: int = 100
    onnx_model_path: str = "./models/modernbert-intent-slot-quantized.onnx"

    pass2_backend: str = "pydantic_ai"
    pass2_model: str = "anthropic:claude-3-5-haiku-latest"
    pass2_timeout_ms: int = 5000

    litellm_base_url: str | None = None
    litellm_api_key: SecretStr = Field(default_factory=lambda: SecretStr(""))
    openai_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        validation_alias=AliasChoices("BLOCKSTATE_OPENAI_API_KEY", "OPENAI_API_KEY"),
    )
    anthropic_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        validation_alias=AliasChoices("BLOCKSTATE_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )

    # 6. Observability
    otel_enabled: bool = False
    otel_service_name: str = "blockstate-agent-runtime"
    otel_exporter_otlp_endpoint: str = Field(
        default="http://localhost:4317",
        validation_alias=AliasChoices(
            "BLOCKSTATE_OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"
        ),
    )
    local_trace_enabled: bool = True
    local_trace_file: str = "./.blockstate/traces.jsonl"
