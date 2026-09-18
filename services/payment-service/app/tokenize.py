"""Card tokenization.

Tokenization swaps a real card number (PAN) for a random surrogate. The
surrogate is useless outside this system, so systems that store or log it
fall outside PCI scope. In production the PAN-to-token mapping lives in a
hardened vault; here we simply do not keep the mapping at all, which is
enough to demonstrate the boundary.
"""

import secrets


def luhn_valid(number: str) -> bool:
    """Checksum every card scheme uses. Rejects typos, not fraud."""
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def tokenize(pan: str) -> tuple[str, str]:
    """Return (token, last4). The PAN is not stored anywhere."""
    token = "tok_" + secrets.token_hex(24)
    return token, pan[-4:]


def mask(pan: str) -> str:
    """Safe representation for logs: only the last four digits survive."""
    return "*" * (len(pan) - 4) + pan[-4:]
