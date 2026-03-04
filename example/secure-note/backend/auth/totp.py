"""TOTP (Time-based One-Time Password) for Multi-Factor Authentication.

Demonstrates ch10 — Multi-Factor Authentication:
  - RFC 6238 TOTP algorithm
  - Base32-encoded shared secret
  - QR code generation for authenticator apps (Google Authenticator, Authy)
  - Recovery codes as backup MFA method

Security notes:
  - TOTP secret must be stored encrypted (or at minimum, server-side only)
  - Recovery codes are single-use and should be hashed after generation
  - Time window tolerance: ±1 interval (30s) to handle clock skew
"""

import secrets
import io
import base64
from typing import Optional

import pyotp
import qrcode

from config import settings
from auth.password import hash_password, verify_password


def generate_totp_secret() -> str:
    """Generate a new random TOTP secret (base32-encoded, 160 bits).

    This secret is shared between the server and the user's authenticator app.
    """
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Generate an otpauth:// URI for QR code scanning.

    Format: otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&digits=6&period=30
    """
    totp = pyotp.TOTP(
        secret,
        digits=settings.totp_digits,
        interval=settings.totp_interval,
    )
    return totp.provisioning_uri(
        name=username,
        issuer_name=settings.totp_issuer,
    )


def generate_qr_code_base64(uri: str) -> str:
    """Generate a QR code image as a base64-encoded PNG string.

    The frontend can display this directly in an <img> tag:
        <img src="data:image/png;base64,{result}" />
    """
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code.

    Allows ±1 time step tolerance (valid_window=1) to handle clock skew.
    """
    totp = pyotp.TOTP(
        secret,
        digits=settings.totp_digits,
        interval=settings.totp_interval,
    )
    return totp.verify(code, valid_window=1)


def generate_recovery_codes(count: Optional[int] = None) -> list[str]:
    """Generate single-use recovery codes.

    Each code is 8 hex characters (32 bits of entropy).
    Returns plaintext codes — the caller should:
      1. Show them to the user once
      2. Hash them before storing in the database

    Args:
        count: Number of codes to generate (default from settings)

    Returns:
        List of plaintext recovery code strings
    """
    n = count or settings.recovery_codes_count
    return [secrets.token_hex(4).upper() for _ in range(n)]


def hash_recovery_codes(codes: list[str]) -> list[str]:
    """Hash recovery codes for secure storage.

    Uses the same Argon2id hasher as passwords.
    """
    return [hash_password(code) for code in codes]


def verify_recovery_code(code: str, hashed_codes: list[str]) -> Optional[int]:
    """Verify a recovery code against the stored hashes.

    Returns the index of the matched code (so it can be removed), or None.
    Each recovery code is single-use.
    """
    for i, hashed in enumerate(hashed_codes):
        if verify_password(code, hashed):
            return i
    return None
