"""Shared fixtures for integration tests.

These tests run against a live stack (docker compose up). URLs come from
environment variables so the same tests work on a laptop and in CI.
A fixture is a reusable setup function: any test that names it as a
parameter receives its return value (like dependency injection).
"""

import os
import uuid

import httpx
import pytest

AUTH_URL = os.getenv("AUTH_URL", "http://localhost:8001")
PAY_URL = os.getenv("PAY_URL", "http://localhost:8002")


@pytest.fixture(scope="session")
def auth() -> httpx.Client:
    with httpx.Client(base_url=AUTH_URL, timeout=10) as c:
        yield c


@pytest.fixture(scope="session")
def pay() -> httpx.Client:
    with httpx.Client(base_url=PAY_URL, timeout=10) as c:
        yield c


def _make_user(auth: httpx.Client, label: str) -> dict:
    """Register a fresh user and log in. Returns {email, password, token}."""
    email = f"{label}-{uuid.uuid4().hex[:8]}@example.com"
    password = f"{label}-strong-passw0rd-{uuid.uuid4().hex[:6]}"
    r = auth.post("/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    r = auth.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"email": email, "password": password, "token": r.json()["access_token"]}


@pytest.fixture
def alice(auth):
    return _make_user(auth, "alice")


@pytest.fixture
def bob(auth):
    return _make_user(auth, "bob")


def bearer(user: dict) -> dict:
    return {"Authorization": f"Bearer {user['token']}"}


TEST_VISA = "4111111111111111"  # Standard test PAN, passes Luhn
