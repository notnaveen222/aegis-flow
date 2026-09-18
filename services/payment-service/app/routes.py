"""HTTP endpoints for payments.

SEEDED FLAW #2:  SQL injection in list_transactions (f-string query).
                 Expected detector: Semgrep community rule
                 python.sqlalchemy.security.sqlalchemy-execute-raw-query
                 + custom rule `raw-sql-string-format`.
SEEDED FLAW #3:  full card number written to logs in tokenize_card.
                 Expected detector: custom Semgrep rule `pan-in-logs`.
SEEDED FLAW #12: IDOR in get_transaction (ownership filter dropped).
                 Expected detector: tests/test_payment_service.py
                 ::test_user_cannot_read_another_users_transaction.
                 No scanner in the pipeline models resource ownership.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from . import schemas
from .auth import current_user_id
from .database import get_db
from .models import CardToken, Transaction
from .notify import send_receipt_webhook
from .tokenize import luhn_valid, tokenize

log = logging.getLogger("payment")
router = APIRouter()


@router.post("/cards/tokenize", response_model=schemas.TokenizeResponse)
def tokenize_card(
    body: schemas.TokenizeRequest,
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> schemas.TokenizeResponse:
    if not luhn_valid(body.card_number):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="invalid card number")
    token, last4 = tokenize(body.card_number)
    db.add(CardToken(token=token, owner_id=user_id, last4=last4))
    db.commit()
    # FLAW #3: raw PAN in the log line. Logs are shipped to systems that are
    # not in PCI scope, so this leaks cardholder data outside the boundary.
    log.info("tokenized card %s for user %s", body.card_number, user_id)
    return schemas.TokenizeResponse(card_token=token, card_last4=last4)


@router.post("/payments", response_model=schemas.TransactionResponse, status_code=status.HTTP_201_CREATED)
def create_payment(
    body: schemas.PaymentRequest,
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> Transaction:
    card = db.scalar(
        select(CardToken).where(CardToken.token == body.card_token, CardToken.owner_id == user_id)
    )
    if card is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="card token not found")
    tx = Transaction(
        owner_id=user_id,
        amount=body.amount,
        currency=body.currency,
        card_token=card.token,
        card_last4=card.last4,
        merchant=body.merchant,
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)
    log.info("payment %s created for user %s: %s %s", tx.id, user_id, tx.amount, tx.currency)
    send_receipt_webhook(tx.id, str(tx.amount), tx.currency)
    return tx


@router.get("/transactions", response_model=list[schemas.TransactionResponse])
def list_transactions(
    merchant: str | None = None,
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> list[Transaction]:
    # FLAW #2: user-controlled `merchant` interpolated straight into SQL.
    # ?merchant=x' OR '1'='1  returns every user's transactions.
    query = f"SELECT * FROM transactions WHERE owner_id = {user_id}"
    if merchant:
        query += f" AND merchant = '{merchant}'"
    query += " ORDER BY id DESC"
    return list(db.scalars(select(Transaction).from_statement(text(query))))


@router.get("/transactions/{tx_id}", response_model=schemas.TransactionResponse)
def get_transaction(
    tx_id: int,
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> Transaction:
    # FLAW #12: authenticated, but not authorised. Any logged-in user can read
    # any transaction by guessing sequential ids.
    tx = db.get(Transaction, tx_id)
    if tx is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="transaction not found")
    return tx
