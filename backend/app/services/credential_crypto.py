from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


def _fernet() -> Fernet:
    key = get_settings().credential_encryption_key
    if not key:
        raise RuntimeError(
            "VULNFORGE_CREDENTIAL_KEY is not configured. Generate a Fernet key and place it in backend/.env."
        )
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("VULNFORGE_CREDENTIAL_KEY is not a valid Fernet key.") from exc


def encrypt_secret(secret: str) -> str:
    if not secret:
        raise ValueError("Credential secret cannot be empty.")
    return _fernet().encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Stored credential cannot be decrypted with the configured key.") from exc
