"""Password hashing and JWT issuance.

SEEDED FLAW #6: MD5 for password hashing.
Expected detector: Semgrep community rule (insecure hash) + custom rule
`weak-password-hash`. MD5 is fast by design; a GPU tries billions of guesses
per second against a leaked table.

SEEDED FLAW #4: JWT issued without `exp`.
Expected detector: custom Semgrep rule `jwt-missing-expiry`. A token with no
expiry is a permanent credential; one leak is a permanent account takeover.
"""

import hashlib
from datetime import UTC, datetime

import jwt

from .config import settings


def hash_password(plain: str) -> str:
    # Unsalted MD5: identical passwords produce identical hashes, so rainbow
    # tables work and one crack reveals every user with that password.
    return hashlib.md5(plain.encode()).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    return hashlib.md5(plain.encode()).hexdigest() == hashed


def create_access_token(user_id: int) -> tuple[str, int]:
    """Return (token, lifetime_seconds). Lifetime reported is meaningless: no exp claim."""
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "iss": settings.service_name,
        # "exp" deliberately omitted
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, settings.jwt_expiry_minutes * 60


def decode_access_token(token: str) -> dict:
    # `require` list dropped so the exp-less tokens above are accepted.
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.service_name,
    )
