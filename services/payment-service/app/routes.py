"""HTTP endpoints for payments.

Every query that touches a user's data is filtered by owner_id taken from the
verified JWT. A user asking for someone else's resource gets 404, not 403:
we do not even confirm that the resource exists.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import schemas
from .auth import current_user_id
from .database import get_db
from .models import CardToken, Transaction
from .tokenize import luhn_valid, mask, tokenize

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
    # Logging the full PAN here is seeded flaw #3. Always log the masked form.
    log.info("tokenized card %s for user %s", mask(body.card_number), user_id)
    return schemas.TokenizeResponse(card_token=token, card_last4=last4)


@router.post("/payments", response_model=schemas.TransactionResponse, status_code=status.HTTP_201_CREATED)
def create_payment(
    body: schemas.PaymentRequest,
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> Transaction:
    # A token is only usable by the user who created it.
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
    return tx


@router.get("/transactions", response_model=list[schemas.TransactionResponse])
def list_transactions(
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> list[Transaction]:
    # Parameterised by the ORM; no string formatting. The vulnerable branch
    # replaces this with an f-string query (seeded flaw #2).
    stmt = select(Transaction).where(Transaction.owner_id == user_id).order_by(Transaction.id.desc())
    return list(db.scalars(stmt))


@router.get("/transactions/{tx_id}", response_model=schemas.TransactionResponse)
def get_transaction(
    tx_id: int,
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> Transaction:
    # Ownership check is part of the query itself, so it cannot be forgotten.
    stmt = select(Transaction).where(Transaction.id == tx_id, Transaction.owner_id == user_id)
    tx = db.scalar(stmt)
    if tx is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="transaction not found")
    return tx
