"""payment-service behaviour, including the IDOR test.

The IDOR test (test_user_cannot_read_another_users_transaction) is the one
no scanner in the pipeline can write for us: SAST has no model of ownership,
SCA looks only at dependencies, and DAST sees a 200 with valid JSON and
considers it success. Business-logic flaws need business-logic tests.
"""

import pytest

from conftest import TEST_VISA, bearer


def _tokenize(pay, user, pan=TEST_VISA) -> str:
    r = pay.post("/api/v1/cards/tokenize", json={"card_number": pan}, headers=bearer(user))
    assert r.status_code == 200, r.text
    return r.json()["card_token"]


def _pay(pay, user, card_token, amount="49.99") -> dict:
    body = {"amount": amount, "currency": "usd", "card_token": card_token, "merchant": "Coffee Co"}
    r = pay.post("/api/v1/payments", json=body, headers=bearer(user))
    assert r.status_code == 201, r.text
    return r.json()


def test_health(pay):
    assert pay.get("/health").status_code == 200


def test_security_headers_present(pay):
    h = pay.get("/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"


@pytest.mark.parametrize("path", ["/api/v1/transactions", "/api/v1/transactions/1"])
def test_endpoints_require_token(pay, path):
    assert pay.get(path).status_code in (401, 403)
    assert pay.get(path, headers={"Authorization": "Bearer junk"}).status_code == 401


def test_tokenize_returns_token_and_last4_only(pay, alice):
    r = pay.post("/api/v1/cards/tokenize", json={"card_number": TEST_VISA}, headers=bearer(alice))
    assert r.status_code == 200
    body = r.json()
    assert body["card_token"].startswith("tok_")
    assert body["card_last4"] == "1111"
    assert TEST_VISA not in r.text  # full PAN never echoed back


def test_tokenize_rejects_bad_luhn(pay, alice):
    r = pay.post("/api/v1/cards/tokenize", json={"card_number": "4111111111111112"}, headers=bearer(alice))
    assert r.status_code == 422


def test_create_and_read_own_payment(pay, alice):
    tok = _tokenize(pay, alice)
    tx = _pay(pay, alice, tok)
    assert tx["currency"] == "USD"  # normalised to upper case
    assert tx["card_last4"] == "1111"
    assert "card_token" not in tx  # token is internal, not part of the response

    listing = pay.get("/api/v1/transactions", headers=bearer(alice)).json()
    assert any(t["id"] == tx["id"] for t in listing)

    r = pay.get(f"/api/v1/transactions/{tx['id']}", headers=bearer(alice))
    assert r.status_code == 200
    assert r.json()["id"] == tx["id"]


def test_user_cannot_read_another_users_transaction(pay, alice, bob):
    """IDOR: seeded flaw #12. Must be 404 on main; the vulnerable branch returns 200."""
    tok = _tokenize(pay, alice)
    tx = _pay(pay, alice, tok)

    r = pay.get(f"/api/v1/transactions/{tx['id']}", headers=bearer(bob))
    assert r.status_code == 404, f"IDOR: bob read alice's transaction: {r.text}"

    bob_listing = pay.get("/api/v1/transactions", headers=bearer(bob)).json()
    assert all(t["id"] != tx["id"] for t in bob_listing)


def test_user_cannot_pay_with_another_users_card_token(pay, alice, bob):
    tok = _tokenize(pay, alice)
    body = {"amount": "5.00", "currency": "USD", "card_token": tok, "merchant": "Thief"}
    r = pay.post("/api/v1/payments", json=body, headers=bearer(bob))
    assert r.status_code == 404


@pytest.mark.parametrize("bad", [{"amount": "-1"}, {"amount": "0"}, {"currency": "us"}, {"currency": "123"}])
def test_payment_validation(pay, alice, bad):
    tok = _tokenize(pay, alice)
    body = {"amount": "10.00", "currency": "USD", "card_token": tok, "merchant": "Shop", **bad}
    r = pay.post("/api/v1/payments", json=body, headers=bearer(alice))
    assert r.status_code == 422
