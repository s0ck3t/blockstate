"""Unit tests for Blockstate configuration and 12-factor settings boundary."""

import pytest
from pydantic import SecretStr, ValidationError

from blockstate.config import BlockstateSettings


def test_default_settings_initialisation() -> None:
    """Verify default settings initialise with expected baseline attributes."""
    settings = BlockstateSettings()

    assert settings.env == "development"
    assert settings.app_name == "blockstate-enterprise-agent"
    assert settings.log_level == "INFO"
    assert settings.log_json is False
    assert settings.default_max_turns == 5
    assert settings.max_slot_nesting_depth == 8
    assert settings.max_task_stack_depth == 6
    assert settings.storage_backend == "sqlite"
    assert settings.sqlite_journal_mode == "WAL"
    assert settings.lease_wait_timeout_ms == 2000
    assert settings.lease_ttl_ms == 30000
    assert settings.lease_heartbeat_ms == 10000
    assert settings.pii_vault_enabled is True
    assert settings.pii_detector_profile == "uk_fca_gdpr"
    assert settings.pass1_backend == "onnx_local"
    assert settings.pass2_backend == "pydantic_ai"


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify settings initialise correctly from BLOCKSTATE_ environment variables."""
    monkeypatch.setenv("BLOCKSTATE_ENV", "production")
    monkeypatch.setenv("BLOCKSTATE_APP_NAME", "custom-agent")
    monkeypatch.setenv("BLOCKSTATE_VAULT_SECRET_KEY", "super_secret_vault_key_123")
    monkeypatch.setenv("BLOCKSTATE_STORAGE_BACKEND", "postgres")
    monkeypatch.setenv("BLOCKSTATE_POSTGRES_POOL_SIZE", "35")
    monkeypatch.setenv("BLOCKSTATE_DATABASE_PORT", "5432")

    settings = BlockstateSettings()

    assert settings.env == "production"
    assert settings.app_name == "custom-agent"
    assert settings.storage_backend == "postgres"
    assert settings.postgres_pool_size == 35
    assert settings.database_port == 5432

    # Verify SecretStr masking behaviour
    assert isinstance(settings.vault_secret_key, SecretStr)
    assert settings.vault_secret_key.get_secret_value() == "super_secret_vault_key_123"
    assert str(settings.vault_secret_key) == "**********"
    assert "super_secret_vault_key_123" not in repr(settings.vault_secret_key)
    assert "super_secret_vault_key_123" not in str(settings)


def test_settings_aliased_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify third-party provider credentials load via standard environment aliases."""
    monkeypatch.setenv("OPENAI_API_KEY", "mock-openai-key-value")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "mock-anthropic-key-value")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock-aws-key-id")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock-aws-secret-access-key")

    settings = BlockstateSettings()

    assert settings.openai_api_key.get_secret_value() == "mock-openai-key-value"
    assert str(settings.openai_api_key) == "**********"
    assert settings.anthropic_api_key.get_secret_value() == "mock-anthropic-key-value"
    assert str(settings.anthropic_api_key) == "**********"
    assert settings.aws_access_key_id.get_secret_value() == "mock-aws-key-id"
    assert settings.aws_secret_access_key.get_secret_value() == "mock-aws-secret-access-key"


def test_invalid_database_port_raises_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify non-integer database port produces pydantic ValidationError on initialisation."""
    monkeypatch.setenv("BLOCKSTATE_DATABASE_PORT", "not_an_int")

    with pytest.raises(ValidationError) as exc_info:
        BlockstateSettings()

    assert "database_port" in str(exc_info.value)


def test_invalid_integer_fields_raise_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify invalid numeric values raise pydantic ValidationError."""
    monkeypatch.setenv("BLOCKSTATE_MAX_TASK_STACK_DEPTH", "invalid_depth")

    with pytest.raises(ValidationError) as exc_info:
        BlockstateSettings()

    assert "max_task_stack_depth" in str(exc_info.value)


def test_custom_constructor_arguments() -> None:
    """Verify explicit keyword arguments override defaults directly."""
    custom_secret = SecretStr("custom-explicit-key")
    settings = BlockstateSettings(
        env="staging",
        vault_secret_key=custom_secret,
        default_max_turns=10,
        storage_backend="memory",
    )

    assert settings.env == "staging"
    assert settings.vault_secret_key.get_secret_value() == "custom-explicit-key"
    assert settings.default_max_turns == 10
    assert settings.storage_backend == "memory"
