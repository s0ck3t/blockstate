"""Cryptographic PIIVault boundary, AES-256-GCM AAD cipher, and tokenisation table.

Provides deterministic HMAC-SHA256 session tokenisation (<VAULT:CATEGORY_NN>)
for sensitive entities and AES-256-GCM authenticated encryption for vault maps
bound to session_id, schema_version, and revision_id Associated Authenticated Data.
"""

import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr

from blockstate.config import BlockstateSettings
from blockstate.errors import SecurityViolationError
from blockstate.ports.security import SanitisedPayload
from blockstate.security.pii_patterns import VAULT_TOKEN_PATTERN, detect_pii_spans


def _derive_32byte_key(key: str | bytes | SecretStr) -> bytes:
    """Derive an exact 32-byte key from various raw key formats."""
    raw: str | bytes = key.get_secret_value() if isinstance(key, SecretStr) else key

    if isinstance(raw, str):
        # If 64-character hexadecimal representation, decode directly
        if len(raw) == 64:
            try:
                return bytes.fromhex(raw)
            except ValueError:
                pass
        raw_bytes = raw.encode()
    else:
        raw_bytes = raw

    if len(raw_bytes) == 32:
        return raw_bytes

    return hashlib.sha256(raw_bytes).digest()


class VaultCipher:
    """AES-256-GCM cipher with Associated Authenticated Data (AAD) session binding."""

    def __init__(
        self,
        secret_key: str | bytes | SecretStr | None = None,
        *,
        fallback_keys: str | bytes | SecretStr | Sequence[str | bytes | SecretStr] | None = None,
    ) -> None:
        settings = BlockstateSettings()

        resolved_key = secret_key
        if resolved_key is None or (
            isinstance(resolved_key, SecretStr) and not resolved_key.get_secret_value()
        ) or (isinstance(resolved_key, (str, bytes)) and not resolved_key):
            cfg_key = settings.vault_secret_key.get_secret_value()
            resolved_key = cfg_key if cfg_key else os.urandom(32)

        self._key_bytes = _derive_32byte_key(resolved_key)

        resolved_fallbacks: list[bytes] = []
        if fallback_keys is not None:
            if isinstance(fallback_keys, (str, bytes, SecretStr)):
                fb_str = (
                    fallback_keys.get_secret_value()
                    if isinstance(fallback_keys, SecretStr)
                    else fallback_keys
                )
                if isinstance(fb_str, str):
                    for item in fb_str.split(","):
                        stripped = item.strip()
                        if stripped:
                            resolved_fallbacks.append(_derive_32byte_key(stripped))
                elif isinstance(fb_str, bytes):
                    stripped_b = fb_str.strip()
                    if stripped_b:
                        resolved_fallbacks.append(_derive_32byte_key(stripped_b))
            else:
                for k in fallback_keys:
                    raw_k = k.get_secret_value() if isinstance(k, SecretStr) else k
                    if isinstance(raw_k, str):
                        stripped_k = raw_k.strip()
                        if stripped_k:
                            resolved_fallbacks.append(_derive_32byte_key(stripped_k))
                    elif isinstance(raw_k, bytes):
                        stripped_bk = raw_k.strip()
                        if stripped_bk:
                            resolved_fallbacks.append(_derive_32byte_key(stripped_bk))
                    elif raw_k:
                        resolved_fallbacks.append(_derive_32byte_key(raw_k))
        else:
            cfg_fallbacks = settings.vault_fallback_keys.get_secret_value()
            if cfg_fallbacks:
                for item in cfg_fallbacks.split(","):
                    stripped = item.strip()
                    if stripped:
                        resolved_fallbacks.append(_derive_32byte_key(stripped))

        self._fallback_keys_bytes = resolved_fallbacks

    def __repr__(self) -> str:
        return (
            f"VaultCipher(algorithm='AES-256-GCM', key_length=256, "
            f"fallback_count={len(self._fallback_keys_bytes)})"
        )

    def encrypt(self, plaintext: bytes, aad: str | bytes) -> bytes:
        """Encrypt raw bytes using AES-256-GCM bound to AAD with a 12-byte random nonce."""
        aad_bytes = aad.encode() if isinstance(aad, str) else aad
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._key_bytes)
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad_bytes)
        return nonce + ciphertext_and_tag

    def decrypt(self, ciphertext: bytes, aad: str | bytes) -> bytes:
        """Decrypt ciphertext and verify the authentication tag against AAD.

        Raises SecurityViolationError (BLK-SEC-001) on authentication failure,
        tampered ciphertext, or mismatched AAD.
        """
        aad_bytes = aad.encode() if isinstance(aad, str) else aad
        if len(ciphertext) < 28:
            raise SecurityViolationError(
                "Decryption failed: ciphertext payload truncated or corrupted",
                code="BLK-SEC-001",
            )

        nonce = ciphertext[:12]
        ct_tag = ciphertext[12:]

        # Attempt decryption with primary secret key
        try:
            return AESGCM(self._key_bytes).decrypt(nonce, ct_tag, aad_bytes)
        except InvalidTag:
            # Attempt decryption with fallback rotated keys
            for fb_key in self._fallback_keys_bytes:
                try:
                    return AESGCM(fb_key).decrypt(nonce, ct_tag, aad_bytes)
                except InvalidTag:
                    continue
            raise SecurityViolationError(
                "Decryption failed: cryptographic tag mismatch or altered AAD",
                code="BLK-SEC-001",
            ) from None
        except Exception as exc:
            raise SecurityViolationError(
                "Decryption failed: invalid ciphertext payload",
                code="BLK-SEC-001",
            ) from exc

    def encrypt_vault_map(
        self,
        vault_map: Mapping[str, str],
        session_id: str | None = None,
        schema_version: int = 1,
        revision_id: int = 0,
        *,
        aad: str | bytes | None = None,
    ) -> bytes:
        """Serialise and encrypt a token mapping dictionary bound to session AAD."""
        resolved_aad: str | bytes = (
            aad if aad is not None else f"{session_id}:{schema_version}:{revision_id}"
        )
        payload = json.dumps(dict(vault_map), ensure_ascii=False, sort_keys=True).encode()
        return self.encrypt(payload, aad=resolved_aad)

    def decrypt_vault_map(
        self,
        ciphertext: bytes,
        session_id: str | None = None,
        schema_version: int = 1,
        revision_id: int = 0,
        *,
        aad: str | bytes | None = None,
    ) -> dict[str, str]:
        """Decrypt and deserialise a vault map dictionary, verifying session AAD."""
        resolved_aad: str | bytes = (
            aad if aad is not None else f"{session_id}:{schema_version}:{revision_id}"
        )
        plaintext_bytes = self.decrypt(ciphertext, aad=resolved_aad)
        try:
            data = json.loads(plaintext_bytes.decode())
            if not isinstance(data, dict):
                raise SecurityViolationError(
                    "Decrypted vault map payload is not a valid JSON dictionary",
                    code="BLK-SEC-001",
                )
            return {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SecurityViolationError(
                "Decrypted vault map payload contains malformed JSON or invalid encoding",
                code="BLK-SEC-001",
            ) from exc


class PIIVault:
    """Deterministic HMAC-SHA256 session tokenisation and AES-256-GCM vault boundary."""

    def __init__(
        self,
        cipher: VaultCipher | None = None,
        *,
        secret_key: str | bytes | SecretStr | None = None,
        hmac_pepper: str | bytes | SecretStr | None = None,
        fallback_keys: str | bytes | SecretStr | Sequence[str | bytes | SecretStr] | None = None,
    ) -> None:
        settings = BlockstateSettings()

        if cipher is not None:
            self._cipher = cipher
        else:
            self._cipher = VaultCipher(secret_key=secret_key, fallback_keys=fallback_keys)

        resolved_pepper = hmac_pepper
        if resolved_pepper is None or (
            isinstance(resolved_pepper, SecretStr) and not resolved_pepper.get_secret_value()
        ) or (isinstance(resolved_pepper, (str, bytes)) and not resolved_pepper):
            cfg_pepper = settings.vault_hmac_pepper.get_secret_value()
            resolved_pepper = cfg_pepper if cfg_pepper else "blockstate-default-pepper-v1"

        if isinstance(resolved_pepper, SecretStr):
            self._pepper = resolved_pepper.get_secret_value().encode()
        elif isinstance(resolved_pepper, str):
            self._pepper = resolved_pepper.encode()
        else:
            self._pepper = resolved_pepper

        # Internal session stores:
        # session_id -> {token: plaintext}
        self._session_tokens: dict[str, dict[str, str]] = {}
        # session_id -> {hmac_digest: token}
        self._session_digests: dict[str, dict[str, str]] = {}
        # session_id -> {category: last_counter}
        self._session_counters: dict[str, dict[str, int]] = {}

    def __repr__(self) -> str:
        # Strictly avoid leaking any plaintext values in string representation
        return f"PIIVault(active_sessions={len(self._session_tokens)})"

    @property
    def cipher(self) -> VaultCipher:
        """Access the underlying AES-256-GCM cipher."""
        return self._cipher

    def seed_vault_map(self, session_id: str, vault_map: Mapping[str, str]) -> None:
        """Seed the session token table with an existing vault mapping."""
        if session_id not in self._session_tokens:
            self._session_tokens[session_id] = {}
            self._session_digests[session_id] = {}
            self._session_counters[session_id] = {}

        token_pattern = re.compile(r"^<VAULT:([A-Z0-9_]+)_(\d+)>$")

        for token, plaintext in vault_map.items():
            self._session_tokens[session_id][token] = plaintext
            match = token_pattern.match(token)
            category = match.group(1) if match else "GENERIC"
            counter = int(match.group(2)) if match else 1

            digest = hmac.new(
                self._pepper,
                f"{session_id}:{category}:{plaintext}".encode(),
                hashlib.sha256,
            ).hexdigest()
            self._session_digests[session_id][digest] = token

            current_max = self._session_counters[session_id].get(category, 0)
            if counter > current_max:
                self._session_counters[session_id][category] = counter

    def get_session_map(self, session_id: str = "default") -> dict[str, str]:
        """Retrieve a copy of the vault token map for a given session."""
        return dict(self._session_tokens.get(session_id, {}))

    def clear_session(self, session_id: str) -> None:
        """Clear all in-memory token mappings for a given session."""
        self._session_tokens.pop(session_id, None)
        self._session_digests.pop(session_id, None)
        self._session_counters.pop(session_id, None)

    def sanitise_sync(
        self,
        text: str,
        session_id: str = "default",
        *,
        vault_map: Mapping[str, str] | None = None,
    ) -> SanitisedPayload:
        """Synchronously sanitise text by replacing sensitive entities with session tokens."""
        if vault_map:
            self.seed_vault_map(session_id, vault_map)

        if not text:
            return SanitisedPayload(sanitised_text="", vault_tokens={})

        if session_id not in self._session_tokens:
            self._session_tokens[session_id] = {}
            self._session_digests[session_id] = {}
            self._session_counters[session_id] = {}

        matches = detect_pii_spans(text)
        if not matches:
            # Check for existing vault tokens in text that are already mapped
            existing_tokens: dict[str, str] = {}
            for tok_match in VAULT_TOKEN_PATTERN.finditer(text):
                token = tok_match.group(0)
                if token in self._session_tokens[session_id]:
                    existing_tokens[token] = self._session_tokens[session_id][token]
            return SanitisedPayload(sanitised_text=text, vault_tokens=existing_tokens)

        # Replace spans in descending order of appearance so indices remain valid
        result_chars = list(text)
        delta_tokens: dict[str, str] = {}

        # First collect all tokens to be assigned
        replacements: list[tuple[int, int, str]] = []
        for match in matches:
            category = match.category.upper()
            plaintext = match.plaintext
            digest = hmac.new(
                self._pepper,
                f"{session_id}:{category}:{plaintext}".encode(),
                hashlib.sha256,
            ).hexdigest()

            if digest in self._session_digests[session_id]:
                token = self._session_digests[session_id][digest]
            else:
                next_count = self._session_counters[session_id].get(category, 0) + 1
                self._session_counters[session_id][category] = next_count
                token = f"<VAULT:{category}_{next_count:02d}>"
                self._session_digests[session_id][digest] = token
                self._session_tokens[session_id][token] = plaintext

            delta_tokens[token] = plaintext
            replacements.append((match.start, match.end, token))

        # Perform replacement from right to left
        for start, end, token in sorted(replacements, key=lambda r: r[0], reverse=True):
            result_chars[start:end] = list(token)

        sanitised_result = "".join(result_chars)

        # Also capture any other pre-existing vault tokens present in the text
        for tok_match in VAULT_TOKEN_PATTERN.finditer(sanitised_result):
            token = tok_match.group(0)
            if token in self._session_tokens[session_id]:
                delta_tokens[token] = self._session_tokens[session_id][token]

        return SanitisedPayload(
            sanitised_text=sanitised_result,
            vault_tokens=delta_tokens,
        )

    async def sanitise(
        self,
        text: str,
        session_id: str = "default",
        *,
        vault_map: Mapping[str, str] | None = None,
    ) -> SanitisedPayload:
        """Asynchronously sanitise text by replacing sensitive entities with session tokens."""
        return self.sanitise_sync(text, session_id=session_id, vault_map=vault_map)

    def sanitise_mapping_sync(
        self,
        data: Mapping[str, Any],
        session_id: str = "default",
    ) -> Mapping[str, Any]:
        """Synchronously and recursively sanitise string values in a dictionary."""
        def _recurse(val: Any) -> Any:
            if isinstance(val, str):
                return self.sanitise_sync(val, session_id=session_id).sanitised_text
            if isinstance(val, Mapping):
                return {k: _recurse(v) for k, v in val.items()}
            if isinstance(val, list):
                return [_recurse(item) for item in val]
            if isinstance(val, tuple):
                return tuple(_recurse(item) for item in val)
            return val

        return {k: _recurse(v) for k, v in data.items()}

    async def sanitise_mapping(
        self,
        data: Mapping[str, Any],
        session_id: str = "default",
    ) -> Mapping[str, Any]:
        """Asynchronously and recursively sanitise string values in a dictionary."""
        return self.sanitise_mapping_sync(data, session_id=session_id)

    def detokenise(
        self,
        text: str,
        vault_map: Mapping[str, str] | None = None,
        session_id: str | None = None,
    ) -> str:
        """Restore <VAULT:CATEGORY_NN> tokens in text to their original plaintexts.

        Tokens not found in vault_map or session storage remain untouched.
        """
        if not text:
            return ""

        lookup: dict[str, str] = {}
        if session_id and session_id in self._session_tokens:
            lookup.update(self._session_tokens[session_id])

        if vault_map:
            lookup.update(vault_map)

        def _replace_token(match: re.Match[str]) -> str:
            tok = match.group(0)
            return lookup.get(tok, tok)

        return VAULT_TOKEN_PATTERN.sub(_replace_token, text)

    def detokenise_mapping(
        self,
        data: Mapping[str, Any],
        vault_map: Mapping[str, str] | None = None,
        session_id: str | None = None,
    ) -> Mapping[str, Any]:
        """Recursively detokenise all string values in a mapping."""
        def _recurse(val: Any) -> Any:
            if isinstance(val, str):
                return self.detokenise(val, vault_map=vault_map, session_id=session_id)
            if isinstance(val, Mapping):
                return {k: _recurse(v) for k, v in val.items()}
            if isinstance(val, list):
                return [_recurse(item) for item in val]
            if isinstance(val, tuple):
                return tuple(_recurse(item) for item in val)
            return val

        return {k: _recurse(v) for k, v in data.items()}

    def encrypt_vault_map(
        self,
        vault_map: Mapping[str, str],
        session_id: str | None = None,
        schema_version: int = 1,
        revision_id: int = 0,
        *,
        aad: str | bytes | None = None,
    ) -> bytes:
        """Encrypt vault map using the configured cipher and session AAD."""
        return self._cipher.encrypt_vault_map(
            vault_map,
            session_id=session_id,
            schema_version=schema_version,
            revision_id=revision_id,
            aad=aad,
        )

    def decrypt_vault_map(
        self,
        ciphertext: bytes,
        session_id: str | None = None,
        schema_version: int = 1,
        revision_id: int = 0,
        *,
        aad: str | bytes | None = None,
    ) -> dict[str, str]:
        """Decrypt vault map using the configured cipher and verify session AAD."""
        return self._cipher.decrypt_vault_map(
            ciphertext,
            session_id=session_id,
            schema_version=schema_version,
            revision_id=revision_id,
            aad=aad,
        )


__all__: list[str] = [
    "PIIVault",
    "VaultCipher",
]
