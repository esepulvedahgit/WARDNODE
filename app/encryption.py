from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


class EncryptionNotConfigured(RuntimeError):
    pass


def _fernet() -> Fernet:
    key = os.environ.get("WARDNODE_SECRET_KEY")
    if not key:
        raise EncryptionNotConfigured("WARDNODE_SECRET_KEY is required to store encrypted secrets.")
    return Fernet(key.encode())


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise EncryptionNotConfigured(
            "Stored secret cannot be decrypted with current WARDNODE_SECRET_KEY."
        ) from exc
