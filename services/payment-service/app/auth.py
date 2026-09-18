"""JWT verification dependency.

payment-service never issues tokens. It only checks that a token was issued
by auth-service, is unexpired, and extracts the user id. That id is the only
identity the rest of the service trusts: it is never taken from the request
body or a query string, which is what makes IDOR (seeded flaw #12) impossible
in the fixed version.
"""

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings

bearer = HTTPBearer(auto_error=True)


def current_user_id(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> int:
    try:
        claims = jwt.decode(
            creds.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "sub", "iat"]},
        )
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")
    return int(claims["sub"])
