"""ORM models.

PCI DSS requirement 3: minimise stored cardholder data. We keep a random
token and the last four digits. The full PAN never touches either table, so a
database dump reveals nothing an attacker can charge.
"""

from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Integer, Numeric, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class CardToken(Base):
    """The token vault. In production this is a separate, hardened service."""

    __tablename__ = "card_tokens"

    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    last4: Mapped[str] = mapped_column(String(4), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    card_token: Mapped[str] = mapped_column(ForeignKey("card_tokens.token"), nullable=False)
    card_last4: Mapped[str] = mapped_column(String(4), nullable=False)
    merchant: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
