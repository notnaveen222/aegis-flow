"""Password hashing and JWT issuance.

Argon2id is the OWASP-recommended password hash: memory-hard, so GPU cracking
is expensive. Compare with MD5 (seeded flaw #6 on the vulnerable branch),
which is fast by design and therefore trivially brute-forced.

JWTs always carry `exp`. A token without expiry (seeded flaw #4) is valid
forever, so a single leaked token is a permanent credential.
"""

from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .config import settings

_hasher = PasswordHasher()  # argon2id with library defaults (tuned by maintainers)


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, plain)
    except VerifyMismatchError:
        return False


def create_access_token(user_id: int) -> tuple[str, int]:
    """Return (token, lifetime_seconds)."""
    lifetime = timedelta(minutes=settings.jwt_expiry_minutes)
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + lifetime,
        "iss": settings.service_name,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, int(lifetime.total_seconds())


def decode_access_token(token: str) -> dict:
    """Raises jwt.PyJWTError on any problem (bad signature, expired, wrong issuer)."""
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.service_name,
        options={"require": ["exp", "sub", "iat"]},
    )
