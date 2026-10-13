from cryptography.fernet import Fernet

from app.services import credential_crypto

def test_secret_round_trip(monkeypatch):
    key=Fernet.generate_key().decode()
    monkeypatch.setattr(credential_crypto, "get_settings", lambda: type("S",(),{"credential_encryption_key":key})())
    encrypted=credential_crypto.encrypt_secret("secret-value")
    assert encrypted != "secret-value"
    assert credential_crypto.decrypt_secret(encrypted)=="secret-value"
