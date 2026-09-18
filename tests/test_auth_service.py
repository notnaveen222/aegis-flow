"""auth-service behaviour."""

import jwt

from conftest import bearer


def test_health(auth):
    r = auth.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_security_headers_present(auth):
    h = auth.get("/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert "content-security-policy" in h


def test_duplicate_email_rejected(auth, alice):
    r = auth.post("/auth/register", json={"email": alice["email"], "password": alice["password"]})
    assert r.status_code == 409


def test_short_password_rejected(auth):
    r = auth.post("/auth/register", json={"email": "weak@example.com", "password": "short"})
    assert r.status_code == 422


def test_wrong_password_and_unknown_email_give_same_error(auth, alice):
    wrong_pw = auth.post("/auth/login", json={"email": alice["email"], "password": "nope-nope-nope"})
    no_user = auth.post("/auth/login", json={"email": "ghost@example.com", "password": "whatever-whatever"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()  # no user-enumeration oracle


def test_token_has_expiry_and_issuer(alice):
    # Decode without verifying: we only inspect the claims here.
    claims = jwt.decode(alice["token"], options={"verify_signature": False})
    assert "exp" in claims
    assert claims["iss"] == "auth-service"
    assert claims["sub"].isdigit()


def test_me_returns_current_user(auth, alice):
    r = auth.get("/auth/me", headers=bearer(alice))
    assert r.status_code == 200
    assert r.json()["email"] == alice["email"]
    assert "password_hash" not in r.json()


def test_me_rejects_garbage_token(auth):
    r = auth.get("/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401
