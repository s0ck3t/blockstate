"""Unit tests for ToolGatekeeper, physical tool gating, and Detokenise[T] handling."""

import pytest

from blockstate.core.gatekeeper import RunContext, ToolGatekeeper
from blockstate.errors import SecurityViolationError
from blockstate.security import Detokenise, PIIVault


def sync_check_balance(account_id: str) -> dict[str, int]:
    """Check account balance."""
    return {"account_id": account_id, "balance_pence": 25000}  # type: ignore[dict-item]


async def async_fetch_profile(user_id: str) -> dict[str, str]:
    """Fetch user profile asynchronously."""
    return {"user_id": user_id, "name": "John Doe"}


def typed_tool(
    count: int,
    rate: float,
    active: bool,
    tags: list[str],
    config: dict[str, str],
    untyped: object,
    optional_note: str = "default_note",
) -> dict[str, object]:
    """Tool with diverse types."""
    return {"count": count, "rate": rate, "active": active, "tags": tags, "config": config}


def sensitive_transfer(
    account_number: Detokenise[str],
    amount: int,
    ctx: RunContext[None],
) -> str:
    """Transfer funds using detokenised account number."""
    return f"Transferred {amount} to account {account_number} in session {ctx.session_id}"


def sensitive_mapping_tool(
    payload: Detokenise[dict[str, str]],
    ctx: RunContext[None],
) -> dict[str, str]:
    """Tool receiving mapping of detokenised values."""
    return {"status": "ok", "beneficiary": payload.get("ben", "")}


def sensitive_list_tool(
    tokens: Detokenise[list[str]],
    ctx: RunContext[None],
) -> list[str]:
    """Tool receiving list of detokenised values."""
    return list(tokens)


def tool_with_tuple_and_default(
    tokens: Detokenise[tuple[str, ...]],
    default_val: int = 99,
) -> tuple[object, int]:
    """Tool receiving tuple of detokenised values and default parameter."""
    return tokens, default_val


def tool_returning_pii(user_name: str) -> str:
    """Tool returning raw sensitive information that should be re-sanitised."""
    return f"Contact {user_name} at user@example.com with NI number QQ123456C"


def tool_returning_mapping_pii() -> dict[str, str]:
    """Tool returning dictionary containing sensitive PII."""
    return {"nino": "QQ123456C", "email": "test@example.com"}


def tool_returning_integer() -> int:
    """Tool returning integer which needs no sanitisation."""
    return 42


def test_build_dispatch_table_isolation() -> None:
    """Verify ToolGatekeeper creates ephemeral MappingProxyType with whitelisted tools only."""
    gatekeeper = ToolGatekeeper()
    gatekeeper.register_tool("check_balance", sync_check_balance)
    gatekeeper.register_tools({
        "fetch_profile": async_fetch_profile,
        "sensitive_transfer": sensitive_transfer,
    })

    assert gatekeeper.get_tool("check_balance") is sync_check_balance
    assert gatekeeper.get_tool("non_existent") is None

    # Scoped dispatch table for stage that only allows check_balance
    table = gatekeeper.build_dispatch_table(["check_balance"])
    assert "check_balance" in table
    assert "fetch_profile" not in table
    assert "sensitive_transfer" not in table
    assert len(table) == 1

    # Attempting to mutate dispatch table raises TypeError
    with pytest.raises(TypeError):
        table["illegal_tool"] = sync_check_balance  # type: ignore[index]


def test_tool_name_validation() -> None:
    """Verify register_tool rejects empty names."""
    gatekeeper = ToolGatekeeper()
    with pytest.raises(ValueError, match="non-empty string identifier"):
        gatekeeper.register_tool("", sync_check_balance)


def test_build_tool_schema_types_and_omits_unwhitelisted() -> None:
    """Verify outbound tool schemas contain solely the tools whitelisted by the stage."""
    gatekeeper = ToolGatekeeper()
    gatekeeper.register_tool("check_balance", sync_check_balance)
    gatekeeper.register_tool("typed_tool", typed_tool)

    schemas = gatekeeper.build_tool_schema(["check_balance", "typed_tool", "unregistered_tool"])
    assert len(schemas) == 2

    typed_schema = next(s for s in schemas if s["function"]["name"] == "typed_tool")
    props = typed_schema["function"]["parameters"]["properties"]
    assert props["count"]["type"] == "integer"
    assert props["rate"]["type"] == "number"
    assert props["active"]["type"] == "boolean"
    assert props["tags"]["type"] == "array"
    assert props["config"]["type"] == "object"
    assert props["untyped"]["type"] == "string"
    assert "optional_note" in props
    assert "optional_note" not in typed_schema["function"]["parameters"]["required"]
    assert "count" in typed_schema["function"]["parameters"]["required"]


def test_invoke_whitelisted_sync_tool() -> None:
    """Verify invoking a permitted synchronous tool succeeds."""
    gatekeeper = ToolGatekeeper({"check_balance": sync_check_balance})
    result = gatekeeper.invoke_sync(
        tool_name="check_balance",
        allowed_tools=["check_balance"],
        arguments={"account_id": "ACC-999"},
    )
    assert result == {"account_id": "ACC-999", "balance_pence": 25000}


@pytest.mark.asyncio
async def test_invoke_whitelisted_async_tool() -> None:
    """Verify invoking a permitted asynchronous tool succeeds."""
    gatekeeper = ToolGatekeeper({"fetch_profile": async_fetch_profile})
    result = await gatekeeper.invoke(
        tool_name="fetch_profile",
        allowed_tools=["fetch_profile"],
        arguments={"user_id": "USR-1"},
    )
    assert result == {"user_id": "USR-1", "name": "John Doe"}


def test_invoke_unwhitelisted_tool_raises_security_violation() -> None:
    """Verify invoking an unwhitelisted tool immediately raises SecurityViolationError."""
    gatekeeper = ToolGatekeeper()
    gatekeeper.register_tool("check_balance", sync_check_balance)
    gatekeeper.register_tool("sensitive_transfer", sensitive_transfer)

    # Allowed tools list excludes sensitive_transfer
    with pytest.raises(SecurityViolationError) as exc_info:
        gatekeeper.invoke_sync(
            tool_name="sensitive_transfer",
            allowed_tools=["check_balance"],
            arguments={"account_number": "123", "amount": 10},
        )

    assert exc_info.value.code == "BLK-SEC-001"
    assert "not permitted by active stage whitelist" in str(exc_info.value)


@pytest.mark.asyncio
async def test_async_invoke_unwhitelisted_raises_security_violation() -> None:
    """Verify async invoke raises SecurityViolationError when tool unwhitelisted."""
    gatekeeper = ToolGatekeeper({"check_balance": sync_check_balance})
    with pytest.raises(SecurityViolationError):
        await gatekeeper.invoke(
            tool_name="check_balance",
            allowed_tools=[],
            arguments={},
        )


@pytest.mark.asyncio
async def test_async_invoke_unregistered_raises_security_violation() -> None:
    """Verify async invoke raises SecurityViolationError when tool not registered."""
    gatekeeper = ToolGatekeeper()
    with pytest.raises(SecurityViolationError):
        await gatekeeper.invoke(
            tool_name="not_registered",
            allowed_tools=["not_registered"],
            arguments={},
        )


def test_invoke_unregistered_tool_raises_security_violation() -> None:
    """Verify invoking a tool not registered on gatekeeper raises SecurityViolationError."""
    gatekeeper = ToolGatekeeper()
    with pytest.raises(SecurityViolationError) as exc_info:
        gatekeeper.invoke_sync(
            tool_name="unknown_action",
            allowed_tools=["unknown_action"],
            arguments={},
        )
    assert exc_info.value.code == "BLK-SEC-001"
    assert "unknown or not registered" in str(exc_info.value)


def test_invoke_sync_with_async_tool_raises_type_error() -> None:
    """Verify invoke_sync with an async tool raises TypeError directing to invoke()."""
    gatekeeper = ToolGatekeeper({"fetch_profile": async_fetch_profile})
    with pytest.raises(TypeError, match="coroutine function; use invoke"):
        gatekeeper.invoke_sync(
            tool_name="fetch_profile",
            allowed_tools=["fetch_profile"],
            arguments={"user_id": "1"},
        )


@pytest.mark.asyncio
async def test_detokenise_parameter_injection_and_context() -> None:
    """Verify ToolGatekeeper automatically detokenises Detokenise[T] arguments using PIIVault."""
    vault = PIIVault()
    sanitised = vault.sanitise_sync("Account number 12345678", session_id="test_sess")
    account_token = (
        next(iter(sanitised.vault_tokens.keys()))
        if sanitised.vault_tokens
        else "<VAULT:ACCOUNT_01>"
    )
    if account_token not in sanitised.vault_tokens:
        vault._session_tokens["test_sess"] = {account_token: "12345678"}

    gatekeeper = ToolGatekeeper({
        "sensitive_transfer": sensitive_transfer,
        "sensitive_mapping_tool": sensitive_mapping_tool,
        "sensitive_list_tool": sensitive_list_tool,
    })
    context = RunContext(deps=None, session_id="test_sess", vault=vault)
    assert context.detokenise(account_token) == "12345678"

    # Context without vault returns token unchanged
    ctx_no_vault = RunContext(deps=None, session_id="test_sess")
    assert ctx_no_vault.detokenise("<VAULT:FOO>") == "<VAULT:FOO>"

    result = await gatekeeper.invoke(
        tool_name="sensitive_transfer",
        allowed_tools=["sensitive_transfer"],
        arguments={"account_number": account_token, "amount": 500},
        context=context,
        vault=vault,
    )
    assert "Transferred 500 to account 12345678 in session test_sess" in result

    # Test mapping detokenisation
    map_res = await gatekeeper.invoke(
        tool_name="sensitive_mapping_tool",
        allowed_tools=["sensitive_mapping_tool"],
        arguments={"payload": {"ben": account_token}},
        context=context,
        vault=vault,
    )
    assert map_res["beneficiary"] == "12345678"

    # Test list detokenisation
    list_res = await gatekeeper.invoke(
        tool_name="sensitive_list_tool",
        allowed_tools=["sensitive_list_tool"],
        arguments={"tokens": [account_token]},
        context=context,
        vault=vault,
    )
    assert list_res == ["12345678"]

    # Test tuple detokenisation and default parameter
    gatekeeper.register_tool("tool_with_tuple_and_default", tool_with_tuple_and_default)
    tup_res, def_res = gatekeeper.invoke_sync(
        tool_name="tool_with_tuple_and_default",
        allowed_tools=["tool_with_tuple_and_default"],
        arguments={"tokens": (account_token,)},
        context=context,
        vault=vault,
    )
    assert tup_res == ("12345678",)
    assert def_res == 99


@pytest.mark.asyncio
async def test_tool_return_value_is_resanitised() -> None:
    """Verify ToolGatekeeper re-sanitises string and dict outputs before exiting."""
    vault = PIIVault()
    gatekeeper = ToolGatekeeper({
        "tool_returning_pii": tool_returning_pii,
        "tool_returning_mapping_pii": tool_returning_mapping_pii,
        "tool_returning_integer": tool_returning_integer,
    })
    context = RunContext(deps=None, session_id="resanitise_sess")

    result = await gatekeeper.invoke(
        tool_name="tool_returning_pii",
        allowed_tools=["tool_returning_pii"],
        arguments={"user_name": "Alice"},
        context=context,
        vault=vault,
    )

    assert "QQ123456C" not in result
    assert "user@example.com" not in result
    assert "<VAULT:" in result

    map_result = await gatekeeper.invoke(
        tool_name="tool_returning_mapping_pii",
        allowed_tools=["tool_returning_mapping_pii"],
        arguments={},
        context=context,
        vault=vault,
    )
    assert map_result["nino"] != "QQ123456C"
    assert "<VAULT:" in map_result["nino"]

    # Non-string return value without vault or with vault
    int_res = gatekeeper.invoke_sync(
        tool_name="tool_returning_integer",
        allowed_tools=["tool_returning_integer"],
        arguments={},
        vault=None,
    )
    assert int_res == 42
