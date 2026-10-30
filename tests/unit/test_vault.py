"""Unit tests for PIIVault, deterministic session tokenisation, and VaultCipher."""

from typing import Annotated
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, Field, SecretStr

from blockstate.core.types import (
    Detokenise as CoreDetokenise,
)
from blockstate.core.types import (
    Vaulted as CoreVaulted,
)
from blockstate.errors import SecurityViolationError
from blockstate.security.annotations import (
    Detokenise,
    DetokeniseMarker,
    Vaulted,
    VaultedMarker,
    get_detokenise_inner_type,
    get_vaulted_inner_type,
    is_detokenise,
    is_vaulted,
)
from blockstate.security.vault import PIIVault, VaultCipher, _derive_32byte_key


def test_vault_cipher_encryption_and_decryption_with_valid_aad() -> None:
    """Verify AES-256-GCM authenticated encryption and decryption bound to AAD."""
    cipher = VaultCipher("01234567890123456789012345678901")
    vault_map = {"<VAULT:NINO_01>": "QQ123456C", "<VAULT:CARD_01>": "4532015012345671"}

    # Encrypt with explicit AAD
    ciphertext = cipher.encrypt_vault_map(vault_map, aad="s1:1:1")
    assert isinstance(ciphertext, bytes)
    assert len(ciphertext) >= 28

    # Decrypt with matching AAD
    decrypted = cipher.decrypt_vault_map(ciphertext, aad="s1:1:1")
    assert decrypted == vault_map


@pytest.mark.patent_invariant
def test_vault_cipher_session_triple_aad_binding() -> None:
    """Verify AES-256-GCM encryption with session_id, schema_version, revision_id."""
    cipher = VaultCipher()
    vault_map = {"<VAULT:POSTCODE_01>": "SW1A 1AA"}

    ciphertext = cipher.encrypt_vault_map(
        vault_map,
        session_id="session-42",
        schema_version=1,
        revision_id=3,
    )

    decrypted = cipher.decrypt_vault_map(
        ciphertext,
        session_id="session-42",
        schema_version=1,
        revision_id=3,
    )
    assert decrypted == vault_map


@pytest.mark.patent_invariant
def test_vault_cipher_decryption_fails_with_altered_aad() -> None:
    """Verify decryption fails when AAD revision or session differs."""
    cipher = VaultCipher()
    vault_map = {"<VAULT:NINO_01>": "QQ123456C"}

    ciphertext = cipher.encrypt_vault_map(vault_map, aad="s1:1:1")

    # Tampered revision in AAD
    with pytest.raises(SecurityViolationError) as exc_info:
        cipher.decrypt_vault_map(ciphertext, aad="s1:1:2")
    assert exc_info.value.code == "BLK-SEC-001"


@pytest.mark.patent_invariant
def test_vault_cipher_decryption_fails_with_corrupted_ciphertext() -> None:
    """Verify decryption fails when ciphertext bytes or authentication tag are tampered."""
    cipher = VaultCipher()
    vault_map = {"<VAULT:NINO_01>": "QQ123456C"}

    ciphertext = cipher.encrypt_vault_map(vault_map, aad="s1:1:1")
    tampered_bytes = bytearray(ciphertext)
    tampered_bytes[15] ^= 0xFF

    with pytest.raises(SecurityViolationError) as exc_info:
        cipher.decrypt_vault_map(bytes(tampered_bytes), aad="s1:1:1")
    assert exc_info.value.code == "BLK-SEC-001"


def test_vault_cipher_decryption_fails_with_truncated_ciphertext() -> None:
    """Verify decryption fails when payload is shorter than 28 bytes."""
    cipher = VaultCipher()
    with pytest.raises(SecurityViolationError) as exc_info:
        cipher.decrypt(b"too_short", aad="s1:1:1")
    assert exc_info.value.code == "BLK-SEC-001"


def test_vault_cipher_key_rotation_and_fallback_keys() -> None:
    """Verify decryption succeeds using fallback keys when primary key has rotated."""
    old_key = "old-secret-key-for-blockstate-01"
    new_key = "new-secret-key-for-blockstate-02"

    old_cipher = VaultCipher(secret_key=old_key)
    ciphertext = old_cipher.encrypt_vault_map(
        {"<VAULT:NINO_01>": "QQ123456C"},
        aad="s1:1:1",
    )

    # New cipher with new primary key and old key in fallbacks
    rotated_cipher = VaultCipher(secret_key=new_key, fallback_keys=[old_key])
    decrypted = rotated_cipher.decrypt_vault_map(ciphertext, aad="s1:1:1")
    assert decrypted == {"<VAULT:NINO_01>": "QQ123456C"}


def test_vault_cipher_multiple_fallback_keys_skipping_invalid() -> None:
    """Verify decryption iterates through multiple fallback keys until finding a valid one."""
    k1 = "secret-key-initial-00000000000001"
    k2 = "secret-key-wrong-fb-00000000000002"
    k3 = "secret-key-target-fb-0000000000003"

    encrypt_cipher = VaultCipher(secret_key=k3)
    ct = encrypt_cipher.encrypt_vault_map({"<VAULT:CARD_01>": "1234"}, aad="s:1:0")

    # Decrypt cipher with k1 as primary, k2 and k3 as fallbacks
    decrypt_cipher = VaultCipher(secret_key=k1, fallback_keys=[k2, k3])
    res = decrypt_cipher.decrypt_vault_map(ct, aad="s:1:0")
    assert res == {"<VAULT:CARD_01>": "1234"}


def test_vault_cipher_key_formats_hex_and_secretstr() -> None:
    """Verify VaultCipher derives keys from 64-char hex strings and SecretStr."""
    hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    cipher = VaultCipher(secret_key=SecretStr(hex_key))
    ct = cipher.encrypt(b"hello", aad="aad")
    assert cipher.decrypt(ct, aad="aad") == b"hello"


def test_derive_32byte_key_invalid_hex_falls_back_to_encode() -> None:
    """Verify 64-char non-hex string gracefully falls back to SHA-256 hash."""
    invalid_hex = "z" * 64
    derived = _derive_32byte_key(invalid_hex)
    assert len(derived) == 32


def test_vault_cipher_fallback_keys_formats() -> None:
    """Verify fallback keys supplied as comma-separated string, bytes, or SecretStr."""
    # Comma-separated string
    c1 = VaultCipher(fallback_keys="key_one, key_two")
    assert "fallback_count=2" in repr(c1)

    # Raw bytes
    c2 = VaultCipher(fallback_keys=b"01234567890123456789012345678901")
    assert "fallback_count=1" in repr(c2)

    # SecretStr
    c3 = VaultCipher(fallback_keys=SecretStr("fb_key1, fb_key2, fb_key3"))
    assert "fallback_count=3" in repr(c3)


def test_vault_cipher_fallback_keys_from_settings() -> None:
    """Verify fallback keys loaded from BlockstateSettings."""
    with patch.dict(
        "os.environ",
        {"BLOCKSTATE_VAULT_FALLBACK_KEYS": "env_fb1, env_fb2"},
    ):
        cipher = VaultCipher()
        assert "fallback_count=2" in repr(cipher)


def test_vault_cipher_decrypt_vault_map_non_dict_and_invalid_json() -> None:
    """Verify decrypt_vault_map raises SecurityViolationError for non-dictionary or invalid JSON."""
    cipher = VaultCipher()

    # Valid encrypted JSON, but a JSON list instead of a dict
    ct_list = cipher.encrypt(b"[1, 2, 3]", aad="aad")
    with pytest.raises(SecurityViolationError) as exc1:
        cipher.decrypt_vault_map(ct_list, aad="aad")
    assert "not a valid JSON dictionary" in str(exc1.value)

    # Valid encrypted ciphertext, but not JSON
    ct_not_json = cipher.encrypt(b"not json payload at all", aad="aad")
    with pytest.raises(SecurityViolationError) as exc2:
        cipher.decrypt_vault_map(ct_not_json, aad="aad")
    assert "contains malformed JSON" in str(exc2.value)


def test_vault_cipher_safe_repr() -> None:
    """Verify VaultCipher repr does not leak secret keys."""
    cipher = VaultCipher(secret_key="top-secret-super-key")
    repr_str = repr(cipher)
    assert "top-secret-super-key" not in repr_str
    assert "VaultCipher" in repr_str


def test_pii_vault_safe_repr() -> None:
    """Verify PIIVault repr never leaks plaintext PII values."""
    vault = PIIVault()
    vault.sanitise_sync("My NINo is QQ123456C", session_id="s1")
    repr_str = repr(vault)
    assert "QQ123456C" not in repr_str
    assert "PIIVault" in repr_str


def test_pii_vault_constructor_variants() -> None:
    """Verify PIIVault constructor with custom cipher and various pepper types."""
    custom_cipher = VaultCipher()
    v1 = PIIVault(cipher=custom_cipher)
    assert v1.cipher is custom_cipher

    # Pepper as SecretStr
    v2 = PIIVault(hmac_pepper=SecretStr("custom-pepper-secret"))
    assert repr(v2).startswith("PIIVault")

    # Pepper as raw bytes
    v3 = PIIVault(hmac_pepper=b"custom-raw-pepper-bytes")
    assert repr(v3).startswith("PIIVault")


@pytest.mark.patent_invariant
def test_pii_vault_sanitise_and_detokenise_matrix_scenarios() -> None:
    """Verify table scenarios from specification intent contract."""
    vault = PIIVault()

    # 1. Ingress text with UK NINo
    p1 = vault.sanitise_sync("My NINo is QQ123456C", session_id="s1")
    assert p1.sanitised_text == "My NINo is <VAULT:NINO_01>"
    assert p1.vault_tokens == {"<VAULT:NINO_01>": "QQ123456C"}

    # 2. Repeated PII within session
    p2 = vault.sanitise_sync("Repeating QQ123456C here", session_id="s1")
    assert p2.sanitised_text == "Repeating <VAULT:NINO_01> here"
    assert p2.vault_tokens == {"<VAULT:NINO_01>": "QQ123456C"}

    # 3. Ingress text with Luhn-valid card
    p3 = vault.sanitise_sync("Card 4532015012345671", session_id="s1")
    assert p3.sanitised_text == "Card <VAULT:CARD_01>"

    # 4. Ingress text with invalid Luhn card (left unmasked)
    p4 = vault.sanitise_sync("Non-card numeric 4532015012345672", session_id="s1")
    assert "<VAULT:CARD" not in p4.sanitised_text
    assert "4532015012345672" in p4.sanitised_text

    # 5. Ingress text with NHS number
    p5 = vault.sanitise_sync("NHS 987 654 3210", session_id="s1")
    assert p5.sanitised_text == "NHS <VAULT:NHS_01>"

    # 6. Detokenise text with valid vault map
    restored = vault.detokenise("Hello <VAULT:NAME_01>", {"<VAULT:NAME_01>": "Alice"})
    assert restored == "Hello Alice"

    # 7. Detokenise text with unknown token
    untouched = vault.detokenise("<VAULT:UNKNOWN_99>", {})
    assert untouched == "<VAULT:UNKNOWN_99>"


def test_pii_vault_seed_existing_vault_map() -> None:
    """Verify seeding an existing vault map preserves tokens and advances counters."""
    vault = PIIVault()
    existing_map = {
        "<VAULT:NINO_01>": "QQ123456C",
        "<VAULT:NAME_01>": "Alice",
        "<NON_STANDARD_TOKEN>": "custom-val",
    }
    vault.seed_vault_map("s1", existing_map)

    # Reusing existing NINo
    p1 = vault.sanitise_sync("Confirm QQ123456C", session_id="s1")
    assert p1.sanitised_text == "Confirm <VAULT:NINO_01>"

    # Introducing a new NINo
    p2 = vault.sanitise_sync("New NINo AB123456C", session_id="s1")
    assert p2.sanitised_text == "New NINo <VAULT:NINO_02>"


def test_pii_vault_sanitise_sync_pre_existing_tokens_without_new_pii() -> None:
    """Verify sanitise_sync captures pre-existing mapped tokens when text has no new PII."""
    vault = PIIVault()
    vault.seed_vault_map("s1", {"<VAULT:NINO_01>": "QQ123456C"})

    payload = vault.sanitise_sync("Text with existing <VAULT:NINO_01> token", session_id="s1")
    assert payload.sanitised_text == "Text with existing <VAULT:NINO_01> token"
    assert payload.vault_tokens == {"<VAULT:NINO_01>": "QQ123456C"}


def test_pii_vault_clear_session() -> None:
    """Verify clearing a session purges all in-memory token state."""
    vault = PIIVault()
    vault.sanitise_sync("NINo QQ123456C", session_id="s1")
    assert "<VAULT:NINO_01>" in vault.get_session_map("s1")

    vault.clear_session("s1")
    assert len(vault.get_session_map("s1")) == 0
    # Clearing a non-existent session is a safe no-op
    vault.clear_session("non-existent-session")


def test_pii_vault_detokenise_session_lookup() -> None:
    """Verify detokenise resolves tokens from active session without explicit vault map."""
    vault = PIIVault()
    vault.sanitise_sync("My NINo is QQ123456C", session_id="session-x")

    text = "Restoring <VAULT:NINO_01>"
    res = vault.detokenise(text, session_id="session-x")
    assert res == "Restoring QQ123456C"

    # Empty text detokenisation
    assert vault.detokenise("") == ""

    # Multi-session without session_id preserves token if ambiguous
    vault.sanitise_sync("Another NINo AB123456C", session_id="session-y")
    assert vault.detokenise("<VAULT:UNKNOWN_77>") == "<VAULT:UNKNOWN_77>"


def test_pii_vault_detokenise_mapping() -> None:
    """Verify detokenise_mapping recursively restores tokens across nested structures."""
    vault = PIIVault()
    vault_map = {"<VAULT:NINO_01>": "QQ123456C", "<VAULT:NAME_01>": "Alice"}

    data = {
        "user": "<VAULT:NAME_01>",
        "details": {
            "nino": "<VAULT:NINO_01>",
            "age": 35,
        },
        "list_items": ["<VAULT:NAME_01>", 100],
        "tuple_items": ("<VAULT:NINO_01>", False),
    }

    restored = vault.detokenise_mapping(data, vault_map=vault_map)
    assert restored["user"] == "Alice"
    assert restored["details"]["nino"] == "QQ123456C"
    assert restored["details"]["age"] == 35
    assert restored["list_items"] == ["Alice", 100]
    assert restored["tuple_items"] == ("QQ123456C", False)


def test_pii_vault_encrypt_decrypt_delegation() -> None:
    """Verify PIIVault encrypt_vault_map and decrypt_vault_map delegate to cipher."""
    vault = PIIVault()
    vault_map = {"<VAULT:NINO_01>": "QQ123456C"}

    ct = vault.encrypt_vault_map(vault_map, session_id="s1", schema_version=1, revision_id=1)
    res = vault.decrypt_vault_map(ct, session_id="s1", schema_version=1, revision_id=1)
    assert res == vault_map


def test_vaulted_and_detokenise_annotations() -> None:
    """Verify Vaulted[T] and Detokenise[T] type inspection and metadata markers."""
    v_str = Vaulted[str]
    d_int = Detokenise[int]

    assert is_vaulted(v_str) is True
    assert is_vaulted(str) is False
    assert is_vaulted(VaultedMarker()) is True
    assert is_vaulted(Vaulted) is True

    # Marker methods
    v_marker = VaultedMarker()
    assert repr(v_marker) == "VaultedMarker()"
    assert hash(v_marker) == hash("VaultedMarker")
    assert v_marker == VaultedMarker()
    assert v_marker != "other"

    d_marker = DetokeniseMarker()
    assert repr(d_marker) == "DetokeniseMarker()"
    assert hash(d_marker) == hash("DetokeniseMarker")
    assert d_marker == DetokeniseMarker()
    assert d_marker != "other"

    assert is_detokenise(d_int) is True
    assert is_detokenise(int) is False
    assert is_detokenise(DetokeniseMarker()) is True
    assert is_detokenise(Detokenise) is True

    # Subclass check branches
    class CustomVaultMarker(VaultedMarker):
        pass

    class CustomDetokMarker(DetokeniseMarker):
        pass

    assert is_vaulted(Annotated[str, VaultedMarker]) is True
    assert is_vaulted(Annotated[str, CustomVaultMarker()]) is True
    assert is_detokenise(Annotated[str, DetokeniseMarker]) is True
    assert is_detokenise(Annotated[str, CustomDetokMarker()]) is True

    assert get_vaulted_inner_type(v_str) is str
    assert get_vaulted_inner_type(str) is str
    assert get_vaulted_inner_type(Vaulted) is not None

    assert get_detokenise_inner_type(d_int) is int
    assert get_detokenise_inner_type(int) is int
    assert get_detokenise_inner_type(Detokenise) is not None

    # Core types export equivalence
    assert CoreVaulted is Vaulted
    assert CoreDetokenise is Detokenise

    # Indirect type alias wrapping
    type IndirVault = Vaulted[str]
    type IndirDetok = Detokenise[int]
    type IndirVaultRaw = Vaulted  # type: ignore[type-arg]
    type IndirDetokRaw = Detokenise  # type: ignore[type-arg]

    assert is_vaulted(IndirVault) is True
    assert is_detokenise(IndirDetok) is True
    assert get_vaulted_inner_type(IndirVaultRaw) is not None
    assert get_detokenise_inner_type(IndirDetokRaw) is not None


def test_vault_cipher_decrypt_unexpected_exception() -> None:
    """Verify decrypt wraps unexpected internal exceptions in SecurityViolationError."""
    cipher = VaultCipher()
    payload = cipher.encrypt(b"test", aad="aad")
    with patch.object(AESGCM, "decrypt", side_effect=ValueError("internal decryption crash")):
        with pytest.raises(SecurityViolationError) as exc:
            cipher.decrypt(payload, aad="aad")
        assert "invalid ciphertext payload" in str(exc.value)


def test_pii_vault_sanitise_sync_with_vault_map_arg() -> None:
    """Verify sanitise_sync correctly seeds vault_map argument."""
    vault = PIIVault()
    payload = vault.sanitise_sync(
        "NINo is QQ123456C",
        session_id="s1",
        vault_map={"<VAULT:NINO_01>": "QQ123456C"},
    )
    assert payload.sanitised_text == "NINo is <VAULT:NINO_01>"


def test_vaulted_annotation_in_pydantic_model() -> None:
    """Verify Pydantic BaseModel with Vaulted[T] field handles token assignment."""

    class CustomerKYC(BaseModel):
        postcode: Vaulted[str] = Field(description="UK customer postcode")
        account_id: int

    model = CustomerKYC(postcode="<VAULT:POSTCODE_01>", account_id=102)
    assert model.postcode == "<VAULT:POSTCODE_01>"
    assert model.account_id == 102
    assert is_vaulted(CustomerKYC.model_fields["postcode"].annotation) is True


def test_vaulted_and_detokenise_union_and_optional_annotations() -> None:
    """Verify Union and Optional type inspection with Vaulted[T] and Detokenise[T]."""
    from typing import Optional, Union

    # Vaulted union and optional forms
    v_pep604 = Vaulted[str] | None
    v_typing_union = Union[Vaulted[int], None]  # noqa: UP007
    v_optional = Optional[Vaulted[float]]  # noqa: UP045
    non_vaulted_union = str | None

    assert is_vaulted(v_pep604) is True
    assert is_vaulted(v_typing_union) is True
    assert is_vaulted(v_optional) is True
    assert is_vaulted(non_vaulted_union) is False

    assert get_vaulted_inner_type(v_pep604) is str
    assert get_vaulted_inner_type(v_typing_union) is int
    assert get_vaulted_inner_type(v_optional) is float
    assert get_vaulted_inner_type(non_vaulted_union) == non_vaulted_union

    # Detokenise union and optional forms
    d_pep604 = Detokenise[str] | None
    d_typing_union = Union[Detokenise[int], None]  # noqa: UP007
    d_optional = Optional[Detokenise[float]]  # noqa: UP045
    non_detok_union = int | None

    assert is_detokenise(d_pep604) is True
    assert is_detokenise(d_typing_union) is True
    assert is_detokenise(d_optional) is True
    assert is_detokenise(non_detok_union) is False

    assert get_detokenise_inner_type(d_pep604) is str
    assert get_detokenise_inner_type(d_typing_union) is int
    assert get_detokenise_inner_type(d_optional) is float
    assert get_detokenise_inner_type(non_detok_union) == non_detok_union


def test_vault_cipher_decrypt_vault_map_non_utf8_payload() -> None:
    """Verify decrypt_vault_map raises SecurityViolationError when plaintext is not valid UTF-8."""
    cipher = VaultCipher()
    invalid_utf8_plaintext = b"\x80\x81\xff\xfe"
    ct = cipher.encrypt(invalid_utf8_plaintext, aad="s:1:0")

    with pytest.raises(SecurityViolationError) as exc_info:
        cipher.decrypt_vault_map(ct, aad="s:1:0")
    assert exc_info.value.code == "BLK-SEC-001"
    assert "malformed JSON or invalid encoding" in str(exc_info.value)


def test_pii_vault_detokenise_omitted_session_id_leaves_tokens_unmapped() -> None:
    """Verify omitting session_id without vault_map leaves tokens unmapped even with 1 session."""
    vault = PIIVault()
    vault.sanitise_sync("User NINo is QQ123456C", session_id="session-single")

    token_text = "Restoring <VAULT:NINO_01>"
    # Calling detokenise with explicit session_id restores the token
    assert vault.detokenise(token_text, session_id="session-single") == "Restoring QQ123456C"

    # Calling detokenise without session_id and without vault_map must NOT restore token
    assert vault.detokenise(token_text) == token_text

    # Passing explicit vault_map still restores regardless of session_id
    assert (
        vault.detokenise(token_text, vault_map={"<VAULT:NINO_01>": "QQ123456C"})
        == "Restoring QQ123456C"
    )


def test_vault_cipher_operational_settings_secret_key_round_trip() -> None:
    """Verify operational BLOCKSTATE_VAULT_SECRET_KEY encryption/decryption round trip."""
    test_key = "op-secret-key-32-chars-long-0123"
    with patch.dict("os.environ", {"BLOCKSTATE_VAULT_SECRET_KEY": test_key}):
        cipher_sender = VaultCipher()
        cipher_receiver = VaultCipher()

        vault_map = {"<VAULT:EMAIL_01>": "alice@example.com", "<VAULT:CARD_01>": "4532015012345671"}
        ct = cipher_sender.encrypt_vault_map(
            vault_map,
            session_id="session-shared",
            schema_version=1,
            revision_id=0,
        )

        restored = cipher_receiver.decrypt_vault_map(
            ct,
            session_id="session-shared",
            schema_version=1,
            revision_id=0,
        )
        assert restored == vault_map


def test_vault_cipher_operational_fallback_key_and_whitespace_filtering() -> None:
    """Verify operational fallback key decryption and filtering of empty fallback keys."""
    old_key = "legacy-secret-key-blockstate-001"
    current_key = "current-active-secret-key-002"

    old_cipher = VaultCipher(secret_key=old_key)
    ct = old_cipher.encrypt_vault_map({"<VAULT:POSTCODE_01>": "SW1A 1AA"}, session_id="session-rot")

    # Construct new cipher with whitespace and empty fallback keys alongside the genuine old key
    new_cipher = VaultCipher(
        secret_key=current_key,
        fallback_keys=["", "   ", old_key, "  \t\n  "],
    )
    # Ensure empty and whitespace fallback keys were filtered out
    assert len(new_cipher._fallback_keys_bytes) == 1

    decrypted = new_cipher.decrypt_vault_map(ct, session_id="session-rot")
    assert decrypted == {"<VAULT:POSTCODE_01>": "SW1A 1AA"}
