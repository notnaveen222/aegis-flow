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
        # Part of SEEDED FLAW #4: the `require: ["exp", ...]` option has been
        # dropped so the exp-less tokens auth-service now issues are accepted.
        # On `main` this strict verifier is defence in depth: even if the issuer
        # forgot exp, the consumer would refuse the token.
        claims = jwt.decode(
            creds.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
        )
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")
    return int(claims["sub"])
