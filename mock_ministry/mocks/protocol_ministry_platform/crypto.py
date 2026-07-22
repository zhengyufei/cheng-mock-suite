"""Self-contained ministry protocol crypto used by the strict mock server."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm2 import CryptSM2, default_ecc_table

_BLOCK_SIZE = 16


def _normalize_public_key(value: str) -> str:
    key = value.strip()
    if key.lower().startswith("04"):
        key = key[2:]
    if len(key) != 128:
        raise RuntimeError("SM2 public key must contain 128 hex characters")
    try:
        bytes.fromhex(key)
    except ValueError as exc:
        raise RuntimeError("SM2 public key must be hexadecimal") from exc
    return key


def _normalize_private_key(value: str) -> str:
    key = value.strip()
    if len(key) != 64:
        raise RuntimeError("SM2 private key must contain 64 hex characters")
    try:
        bytes.fromhex(key)
    except ValueError as exc:
        raise RuntimeError("SM2 private key must be hexadecimal") from exc
    return key


def derive_public_key(private_key: str) -> str:
    key = _normalize_private_key(private_key)
    helper = CryptSM2(private_key=key, public_key=default_ecc_table["g"], mode=1)
    return helper._kg(int(key, 16), default_ecc_table["g"])


def _load_secret(env: Mapping[str, str], value_name: str, file_name: str) -> str:
    direct = env.get(value_name, "").strip()
    path_value = env.get(file_name, "").strip()
    if direct and path_value:
        raise RuntimeError(f"configure only one of {value_name} and {file_name}")
    if direct:
        return direct
    if path_value:
        path = Path(path_value)
        if not path.is_file():
            raise RuntimeError(f"key file does not exist: {path}")
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    raise RuntimeError(f"missing required test key: {value_name} or {file_name}")


@dataclass(frozen=True)
class ProtocolKeys:
    ministry_private_key: str
    province_public_key: str
    group_public_key: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ProtocolKeys":
        source = os.environ if env is None else env
        return cls(
            ministry_private_key=_normalize_private_key(
                _load_secret(
                    source,
                    "CHENG_MOCK_MINISTRY_PRIVATE_KEY",
                    "CHENG_MOCK_MINISTRY_PRIVATE_KEY_FILE",
                )
            ),
            province_public_key=_normalize_public_key(
                _load_secret(
                    source,
                    "CHENG_MOCK_PROVINCE_PUBLIC_KEY",
                    "CHENG_MOCK_PROVINCE_PUBLIC_KEY_FILE",
                )
            ),
            group_public_key=_normalize_public_key(
                _load_secret(
                    source,
                    "CHENG_MOCK_GROUP_PUBLIC_KEY",
                    "CHENG_MOCK_GROUP_PUBLIC_KEY_FILE",
                )
            ),
        )

    @property
    def ministry_public_key(self) -> str:
        return derive_public_key(self.ministry_private_key)


def generate_protocol_sign(outer: Mapping[str, object], caller_public_key: str) -> str:
    values = {
        "ctxCode": outer.get("ctxCode"),
        "ispCode": outer.get("ispCode"),
        "orderID": outer.get("orderID"),
        "orgCode": outer.get("orgCode"),
    }
    sign_text = "&".join(f"{key}={values[key]}" for key in sorted(values) if values[key] is not None)
    return hmac.new(caller_public_key.encode("utf-8"), sign_text.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_response_sign(outer: Mapping[str, object], caller_public_key: str) -> str:
    plaintext = (
        f'{outer.get("orderID", "")}{outer.get("statusCode", "")}{outer.get("statusText", "")}'
    ).encode("utf-8")
    encrypted = CryptSM2(
        private_key="",
        public_key=_normalize_public_key(caller_public_key),
        mode=0,
    ).encrypt(plaintext)
    return base64.b64encode(encrypted).decode("ascii")


def verify_protocol_sign(payload: Mapping[str, object], outer: Mapping[str, object], caller_public_key: str) -> bool:
    signature = payload.get("sign")
    if not isinstance(signature, str) or not signature:
        return False
    return hmac.compare_digest(signature.lower(), generate_protocol_sign(outer, caller_public_key).lower())


def verify_response_sign(payload: Mapping[str, object], outer: Mapping[str, object], caller_private_key: str) -> bool:
    signature = payload.get("sign")
    if not isinstance(signature, str) or not signature:
        return False
    expected = (
        f'{outer.get("orderID", "")}{outer.get("statusCode", "")}{outer.get("statusText", "")}'
    ).encode("utf-8")
    try:
        private_key = _normalize_private_key(caller_private_key)
        encrypted = base64.b64decode(signature, validate=True)
        actual = CryptSM2(
            private_key=private_key,
            public_key=derive_public_key(private_key),
            mode=0,
        ).decrypt(encrypted)
    except (ValueError, binascii.Error, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


class Sm4Gcm:
    def __init__(self, key: bytes) -> None:
        if len(key) != _BLOCK_SIZE:
            raise ValueError("SM4 key must be 16 bytes")
        self._key = key

    @staticmethod
    def _validate_nonce(nonce: bytes) -> None:
        if len(nonce) != 12:
            raise ValueError("SM4-GCM nonce must be 12 bytes")

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        self._validate_nonce(nonce)
        encryptor = Cipher(algorithms.SM4(self._key), modes.GCM(nonce)).encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, encryptor.tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        self._validate_nonce(nonce)
        if len(tag) != _BLOCK_SIZE:
            raise ValueError("SM4-GCM authentication tag must be 16 bytes")
        decryptor = Cipher(algorithms.SM4(self._key), modes.GCM(nonce, tag)).decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        try:
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag as exc:
            raise ValueError("SM4-GCM authentication failed") from exc


def _decode_b64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{label} must be valid Base64") from exc


def _unwrap_sm4_key(value: str, private_key: str) -> bytes:
    wrapped = _decode_b64(value, "X-Enc-Key")
    candidates = [wrapped]
    try:
        text = wrapped.decode("ascii")
        if len(text) % 2 == 0:
            candidates.insert(0, bytes.fromhex(text))
    except (UnicodeDecodeError, ValueError):
        pass
    public_key = derive_public_key(private_key)
    for candidate in candidates:
        try:
            plaintext = CryptSM2(private_key=private_key, public_key=public_key, mode=1).decrypt(candidate)
        except Exception:
            continue
        if len(plaintext) == 16:
            return plaintext
        try:
            text = plaintext.decode("ascii")
            if len(text) == 32:
                return bytes.fromhex(text)
        except (UnicodeDecodeError, ValueError):
            continue
    raise ValueError("SM2 wrapped SM4 key cannot be decrypted")


def _wrap_sm4_key(key: bytes, public_key: str, *, legacy_ascii_ciphertext: bool) -> str:
    plaintext = key.hex().encode("ascii") if legacy_ascii_ciphertext else key
    wrapped = CryptSM2(private_key="", public_key=_normalize_public_key(public_key), mode=1).encrypt(plaintext)
    if legacy_ascii_ciphertext:
        wrapped = wrapped.hex().encode("ascii")
    return base64.b64encode(wrapped).decode("ascii")


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: str
    headers: dict[str, str]
    sm4_key: bytes
    nonce: bytes


class ProtocolCrypto:
    def __init__(self, keys: ProtocolKeys) -> None:
        self.keys = keys

    def decrypt_payload(self, ciphertext_b64: str, headers: Mapping[str, str]) -> bytes:
        normalized = {key.lower(): value for key, value in headers.items()}
        key = _unwrap_sm4_key(normalized.get("x-enc-key", ""), self.keys.ministry_private_key)
        nonce = _decode_b64(normalized.get("x-enc-nonce", ""), "X-Enc-Nonce")
        tag = _decode_b64(normalized.get("x-enc-auth-tag", ""), "X-Enc-Auth-Tag")
        ciphertext = _decode_b64(ciphertext_b64, "encrypted payload")
        return Sm4Gcm(key).decrypt(nonce, ciphertext, tag)

    def decrypt_file(self, ciphertext: bytes, headers: Mapping[str, str]) -> bytes:
        normalized = {key.lower(): value for key, value in headers.items()}
        key = _unwrap_sm4_key(normalized.get("x-enc-key", ""), self.keys.ministry_private_key)
        nonce = _decode_b64(normalized.get("x-enc-nonce", ""), "X-Enc-Nonce")
        tag = _decode_b64(normalized.get("x-enc-auth-tag-file", ""), "X-Enc-Auth-Tag-File")
        return Sm4Gcm(key).decrypt(nonce, ciphertext, tag)

    def encrypt_payload(
        self,
        plaintext: bytes,
        *,
        recipient_public_key: str | None = None,
        legacy_key_wrap: bool = True,
    ) -> EncryptedPayload:
        recipient = recipient_public_key or self.keys.province_public_key
        key = os.urandom(16)
        nonce = os.urandom(12)
        ciphertext, tag = Sm4Gcm(key).encrypt(nonce, plaintext)
        headers = {
            "X-Enc-Key": _wrap_sm4_key(key, recipient, legacy_ascii_ciphertext=legacy_key_wrap),
            "X-Enc-Key-G": _wrap_sm4_key(
                key,
                self.keys.group_public_key,
                legacy_ascii_ciphertext=legacy_key_wrap,
            ),
            "X-Enc-Nonce": base64.b64encode(nonce).decode("ascii"),
            "X-Enc-Auth-Tag": base64.b64encode(tag).decode("ascii"),
        }
        return EncryptedPayload(
            ciphertext=base64.b64encode(ciphertext).decode("ascii"),
            headers=headers,
            sm4_key=key,
            nonce=nonce,
        )
