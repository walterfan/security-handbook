"""Tests for TOTP multi-factor authentication (ch10).

Verifies:
  - Secret generation (base32 format)
  - TOTP URI format (otpauth://)
  - QR code generation (base64 PNG)
  - Code verification (correct, wrong, time window)
  - Recovery code generation and verification
"""

import time

import pyotp
import pytest

from auth.totp import (
    generate_totp_secret,
    get_totp_uri,
    generate_qr_code_base64,
    verify_totp_code,
    generate_recovery_codes,
    hash_recovery_codes,
    verify_recovery_code,
)


class TestTOTPSecret:
    """Test TOTP secret generation."""

    def test_secret_is_base32(self):
        """Secret should be a valid base32 string."""
        secret = generate_totp_secret()
        import base64
        # base32 decode should not raise
        base64.b32decode(secret)

    def test_secrets_are_unique(self):
        """Each generated secret should be different."""
        secrets = {generate_totp_secret() for _ in range(10)}
        assert len(secrets) == 10

    def test_secret_length(self):
        """Secret should be at least 16 characters (80+ bits of entropy)."""
        secret = generate_totp_secret()
        assert len(secret) >= 16


class TestTOTPUri:
    """Test TOTP provisioning URI generation."""

    def test_uri_format(self):
        """URI should follow otpauth://totp/ format."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "alice")
        assert uri.startswith("otpauth://totp/")
        assert "alice" in uri
        assert secret in uri

    def test_uri_contains_issuer(self):
        """URI should contain the issuer name."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "bob")
        assert "SecureNote" in uri


class TestQRCode:
    """Test QR code generation."""

    def test_qr_code_is_base64_png(self):
        """QR code should be a valid base64 string."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "alice")
        qr = generate_qr_code_base64(uri)
        assert len(qr) > 100  # non-trivial content
        # Should be valid base64
        import base64
        decoded = base64.b64decode(qr)
        # PNG magic bytes
        assert decoded[:4] == b"\x89PNG"


class TestTOTPVerification:
    """Test TOTP code verification."""

    def test_verify_current_code(self):
        """Current TOTP code should verify successfully."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        assert verify_totp_code(secret, current_code) is True

    def test_reject_wrong_code(self):
        """An incorrect code should be rejected."""
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "000000") is False

    def test_reject_empty_code(self):
        """Empty code should be rejected."""
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "") is False

    def test_code_is_six_digits(self):
        """Generated TOTP code should be 6 digits."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert len(code) == 6
        assert code.isdigit()


class TestRecoveryCodes:
    """Test recovery code generation and verification."""

    def test_generate_default_count(self):
        """Should generate the configured number of recovery codes."""
        codes = generate_recovery_codes()
        assert len(codes) == 8  # default from settings

    def test_generate_custom_count(self):
        """Should generate the specified number of codes."""
        codes = generate_recovery_codes(count=5)
        assert len(codes) == 5

    def test_codes_are_unique(self):
        """All recovery codes should be unique."""
        codes = generate_recovery_codes(count=20)
        assert len(set(codes)) == 20

    def test_code_format(self):
        """Recovery codes should be uppercase hex strings."""
        codes = generate_recovery_codes()
        for code in codes:
            assert len(code) == 8
            assert all(c in "0123456789ABCDEF" for c in code)

    def test_hash_and_verify_recovery_code(self):
        """A recovery code should verify against its hash."""
        codes = generate_recovery_codes(count=3)
        hashed = hash_recovery_codes(codes)

        # First code should match
        idx = verify_recovery_code(codes[0], hashed)
        assert idx == 0

        # Second code should match
        idx = verify_recovery_code(codes[1], hashed)
        assert idx == 1

    def test_reject_wrong_recovery_code(self):
        """A wrong recovery code should not match any hash."""
        codes = generate_recovery_codes(count=3)
        hashed = hash_recovery_codes(codes)
        assert verify_recovery_code("ZZZZZZZZ", hashed) is None

    def test_single_use_pattern(self):
        """Demonstrate single-use: remove code after verification."""
        codes = generate_recovery_codes(count=3)
        hashed = hash_recovery_codes(codes)

        # Use first code
        idx = verify_recovery_code(codes[0], hashed)
        assert idx is not None
        hashed.pop(idx)  # remove used code

        # Same code should no longer work
        assert verify_recovery_code(codes[0], hashed) is None

        # Other codes still work
        assert verify_recovery_code(codes[1], hashed) is not None
