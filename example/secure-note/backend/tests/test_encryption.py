"""Tests for AES-256-GCM note encryption (ch02).

Verifies:
  - Encrypt → decrypt round-trip
  - Different users get different ciphertexts (per-user key derivation)
  - Unique nonce per encryption
  - Tampered ciphertext is detected (auth tag)
  - Associated data binding
  - Unicode content support
"""

import pytest
from cryptography.exceptions import InvalidTag

from crypto.encryption import encrypt_note, decrypt_note, derive_user_key


class TestKeyDerivation:
    """Test HKDF per-user key derivation."""

    def test_same_user_same_key(self):
        """Same user ID should always derive the same key."""
        k1 = derive_user_key("user-123")
        k2 = derive_user_key("user-123")
        assert k1 == k2

    def test_different_users_different_keys(self):
        """Different user IDs should derive different keys."""
        k1 = derive_user_key("user-123")
        k2 = derive_user_key("user-456")
        assert k1 != k2

    def test_key_length_256_bits(self):
        """Derived key should be 32 bytes (256 bits)."""
        key = derive_user_key("user-123")
        assert len(key) == 32


class TestEncryptDecrypt:
    """Test AES-256-GCM encrypt/decrypt round-trip."""

    def test_basic_round_trip(self):
        """Encrypt then decrypt should return original plaintext."""
        plaintext = "Hello, this is a secret note!"
        user_id = "user-123"

        ct, nonce, tag = encrypt_note(plaintext, user_id)
        result = decrypt_note(ct, nonce, tag, user_id)
        assert result == plaintext

    def test_unicode_content(self):
        """Chinese and emoji content should encrypt/decrypt correctly."""
        plaintext = "这是一条加密笔记 🔐📝"
        user_id = "user-123"

        ct, nonce, tag = encrypt_note(plaintext, user_id)
        result = decrypt_note(ct, nonce, tag, user_id)
        assert result == plaintext

    def test_empty_content(self):
        """Empty string should encrypt/decrypt correctly."""
        ct, nonce, tag = encrypt_note("", "user-123")
        result = decrypt_note(ct, nonce, tag, "user-123")
        assert result == ""

    def test_large_content(self):
        """Large content (1MB) should work."""
        plaintext = "A" * (1024 * 1024)
        ct, nonce, tag = encrypt_note(plaintext, "user-123")
        result = decrypt_note(ct, nonce, tag, "user-123")
        assert result == plaintext

    def test_unique_nonce_per_encryption(self):
        """Each encryption should use a different random nonce."""
        _, nonce1, _ = encrypt_note("same text", "user-123")
        _, nonce2, _ = encrypt_note("same text", "user-123")
        assert nonce1 != nonce2

    def test_different_ciphertext_per_encryption(self):
        """Same plaintext encrypted twice should produce different ciphertext."""
        ct1, _, _ = encrypt_note("same text", "user-123")
        ct2, _, _ = encrypt_note("same text", "user-123")
        assert ct1 != ct2  # different nonce → different ciphertext

    def test_nonce_is_96_bits(self):
        """Nonce should be 12 bytes (96 bits) as recommended for GCM."""
        _, nonce, _ = encrypt_note("test", "user-123")
        assert len(nonce) == 12

    def test_tag_is_128_bits(self):
        """Auth tag should be 16 bytes (128 bits)."""
        _, _, tag = encrypt_note("test", "user-123")
        assert len(tag) == 16


class TestIntegrity:
    """Test GCM authentication tag — tamper detection."""

    def test_tampered_ciphertext_detected(self):
        """Modifying ciphertext should cause InvalidTag on decrypt."""
        ct, nonce, tag = encrypt_note("secret data", "user-123")
        tampered_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]  # flip first byte

        with pytest.raises(InvalidTag):
            decrypt_note(tampered_ct, nonce, tag, "user-123")

    def test_tampered_tag_detected(self):
        """Modifying the auth tag should cause InvalidTag."""
        ct, nonce, tag = encrypt_note("secret data", "user-123")
        tampered_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]

        with pytest.raises(InvalidTag):
            decrypt_note(ct, nonce, tampered_tag, "user-123")

    def test_wrong_nonce_detected(self):
        """Using wrong nonce should cause InvalidTag."""
        ct, nonce, tag = encrypt_note("secret data", "user-123")
        wrong_nonce = bytes([nonce[0] ^ 0xFF]) + nonce[1:]

        with pytest.raises(InvalidTag):
            decrypt_note(ct, wrong_nonce, tag, "user-123")

    def test_wrong_user_cannot_decrypt(self):
        """A different user's key should fail to decrypt."""
        ct, nonce, tag = encrypt_note("secret data", "user-123")

        with pytest.raises(InvalidTag):
            decrypt_note(ct, nonce, tag, "user-456")


class TestAssociatedData:
    """Test Associated Data (AAD) binding."""

    def test_aad_round_trip(self):
        """Encrypt with AAD, decrypt with same AAD should work."""
        aad = b"note-id:abc123"
        ct, nonce, tag = encrypt_note("secret", "user-123", associated_data=aad)
        result = decrypt_note(ct, nonce, tag, "user-123", associated_data=aad)
        assert result == "secret"

    def test_wrong_aad_detected(self):
        """Decrypt with different AAD should fail."""
        aad = b"note-id:abc123"
        ct, nonce, tag = encrypt_note("secret", "user-123", associated_data=aad)

        with pytest.raises(InvalidTag):
            decrypt_note(ct, nonce, tag, "user-123", associated_data=b"note-id:WRONG")

    def test_missing_aad_detected(self):
        """Encrypt with AAD but decrypt without should fail."""
        aad = b"note-id:abc123"
        ct, nonce, tag = encrypt_note("secret", "user-123", associated_data=aad)

        with pytest.raises(InvalidTag):
            decrypt_note(ct, nonce, tag, "user-123", associated_data=None)
