from __future__ import annotations
import base64
import hashlib
import secrets

ROLE_ADMIN = "ADMIN"
ROLE_DOCTOR = "DOCTOR"
ROLE_NURSE = "NURSE"

ROLE_LABEL = {
    ROLE_ADMIN: "Administrator",
    ROLE_DOCTOR: "Lekarz",
    ROLE_NURSE: "Pielęgniarka",
}

def hash_password(password: str, salt_b64: str | None = None) -> tuple[str, str]:
    """Zwraca (hash_b64, salt_b64)."""
    if salt_b64 is None:
        salt = secrets.token_bytes(16)
        salt_b64 = base64.b64encode(salt).decode("ascii")
    else:
        salt = base64.b64decode(salt_b64.encode("ascii"))
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return base64.b64encode(dk).decode("ascii"), salt_b64

def verify_password(password: str, pw_hash_b64: str, salt_b64: str) -> bool:
    try:
        cand, _ = hash_password(password, salt_b64)
        return secrets.compare_digest(cand, pw_hash_b64)
    except Exception:
        return False
