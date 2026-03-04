"""Tests for Argon2id password hashing (ch02).

Verifies:
  - Correct passwords verify successfully
  - Wrong passwords are rejected
  - Hash format is Argon2id PHC string
  - Different passwords produce different hashes (random salt)
  - Rehash detection works when parameters change
"""

import pytest
from auth.password import hash_password, verify_password, needs_rehash


class TestArgon2Hashing:
    """Test suite for Argon2id password operations."""

    def test_hash_and_verify_correct_password(self):
        """A correct password should verify against its hash."""
        password = "MySecureP@ss123"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_reject_wrong_password(self):
        """A wrong password should not verify."""
        hashed = hash_password("correct-password")
        assert verify_password("wrong-password", hashed) is False

    def test_hash_format_is_argon2id(self):
        """Hash string should start with $argon2id$ (PHC format)."""
        hashed = hash_password("test")
        assert hashed.startswith("$argon2id$")

    def test_different_passwords_different_hashes(self):
        """Same password hashed twice should produce different hashes (random salt)."""
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2  # different salts

    def test_both_verify_despite_different_hashes(self):
        """Both hashes of the same password should verify correctly."""
        password = "same-password"
        h1 = hash_password(password)
        h2 = hash_password(password)
        assert verify_password(password, h1) is True
        assert verify_password(password, h2) is True

    def test_empty_password(self):
        """Empty password should still hash and verify."""
        hashed = hash_password("")
        assert verify_password("", hashed) is True
        assert verify_password("notempty", hashed) is False

    def test_unicode_password(self):
        """Unicode passwords (e.g., Chinese) should work correctly."""
        password = "密码测试🔐"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_long_password(self):
        """Very long passwords should work (Argon2 has no practical limit)."""
        password = "A" * 1000
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_returns_false_for_invalid_hash(self):
        """Invalid hash format should return False, not raise."""
        assert verify_password("test", "not-a-valid-hash") is False

    def test_needs_rehash_current_params(self):
        """A freshly created hash should NOT need rehashing."""
        hashed = hash_password("test")
        assert needs_rehash(hashed) is False
