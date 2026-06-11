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


def has_undecryptable_secrets() -> bool:
    """True si alguna fila cifrada de app_config no se puede descifrar con la clave actual."""
    from app.models import AppConfig  # import diferido — evita ciclo al boot
    for row in AppConfig.query.filter_by(encrypted=True).all():
        try:
            decrypt_secret(row.value)
        except EncryptionNotConfigured:
            return True
    return False


def reset_encrypted_secrets() -> dict:
    """Borra todos los secretos cifrados (app_config encrypted=True) y restablece el 2FA
    de todos los usuarios. Usar tras rotar WARDNODE_SECRET_KEY. Nunca expone valores.

    Devuelve: {"secrets": int, "totp": int, "keys": list[str]}
    """
    from app.models import AppConfig, User  # import diferido — evita ciclo al boot
    from app.extensions import db

    cleared_keys = [r.key for r in AppConfig.query.filter_by(encrypted=True).all()]
    n_secrets = AppConfig.query.filter_by(encrypted=True).delete(synchronize_session=False)
    n_totp = User.query.filter(User.totp_secret.isnot(None)).update(
        {"totp_secret": None, "totp_enabled": False}, synchronize_session=False
    )
    db.session.commit()
    return {"secrets": n_secrets, "totp": n_totp, "keys": cleared_keys}
