"""Request and response shapes."""

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field, field_validator


class TokenizeRequest(BaseModel):
    card_number: str = Field(min_length=12, max_length=19, pattern=r"^\d+$")


class TokenizeResponse(BaseModel):
    card_token: str
    card_last4: str


class PaymentRequest(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    currency: str = Field(min_length=3, max_length=3)
    card_token: str = Field(min_length=32, max_length=64)
    merchant: str = Field(min_length=1, max_length=120)

    @field_validator("currency")
    @classmethod
    def upper_iso(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError("currency must be an ISO 4217 alphabetic code")
        return v.upper()


class TransactionResponse(BaseModel):
    id: int
    amount: Decimal
    currency: str
    card_last4: str
    merchant: str
    created_at: datetime

    model_config = {"from_attributes": True}
