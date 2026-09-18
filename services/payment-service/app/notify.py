"""Outbound receipt webhook.

SEEDED FLAW #5: TLS certificate verification disabled.
Expected detector: Semgrep community rule
python.requests.security.disabled-cert-validation + custom rule `tls-verify-disabled`.

With verify=False any machine on the network path can impersonate the
receipts server, read every payload, and return forged responses. This is
the classic "it failed in staging so I turned it off" fix that ships to prod.
"""

import logging
import os

import requests

log = logging.getLogger("payment.notify")

RECEIPTS_URL = os.getenv("RECEIPTS_WEBHOOK_URL")


def send_receipt_webhook(tx_id: int, amount: str, currency: str) -> None:
    if not RECEIPTS_URL:
        return
    try:
        requests.post(
            RECEIPTS_URL,
            json={"transaction_id": tx_id, "amount": amount, "currency": currency},
            timeout=3,
            verify=False,
        )
    except requests.RequestException as exc:
        log.warning("receipt webhook failed: %s", exc)
