"""AES-256-GCM authenticated encryption for note content.

Demonstrates ch02 — Cryptographic Fundamentals:
  - AES-256-GCM: Authenticated Encryption with Associated Data (AEAD)
  - Each note gets a unique random nonce (96-bit)
  - GCM provides both confidentiality AND integrity (auth tag)
  - HKDF for deriving per-user encryption keys from a master key

Security notes:
  - NEVER reuse a nonce with the same key (catastrophic for GCM)
  - 96-bit random nonce: collision probability < 2^-32 after 2^32 encryptions
  - The auth tag prevents tampering — any modification is detected
  - Associated data (AAD) binds the ciphertext to context (e.g., note ID)
"""

import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from config import settings

# ── Key Management ──────────────────────────────────────

_NONCE_SIZE = 12  # 96 bits — recommended for AES-GCM
_KEY_SIZE = 32    # 256 bits


def _get_master_key() -> bytes:
    """Load the master encryption key.

    In production, this should come from a KMS (e.g., AWS KMS, HashiCorp Vault).
    For this demo, it's loaded from an environment variable or derived from a passphrase.
    """
    if settings.master_key_env:
        return bytes.fromhex(settings.master_key_env)
    # Fallback: derive from a fixed passphrase (DEMO ONLY — not for production!)
    return hashlib.sha256(b"securenote-demo-key-change-me").digest()


def derive_user_key(user_id: str) -> bytes:
    """Derive a per-user encryption key using HKDF.

    HKDF (HMAC-based Key Derivation Function) derives unique keys from a master key.
    Each user gets a different key, so compromising one user's data doesn't
    expose other users' notes.

    Args:
        user_id: Unique user identifier (used as HKDF info parameter)

    Returns:
        32-byte derived key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=None,  # In production, use a stored random salt
        info=f"securenote:user:{user_id}".encode(),
    )
    return hkdf.derive(_get_master_key())


# ── Encrypt / Decrypt ──────────────────────────────────

def encrypt_note(
    plaintext: str,
    user_id: str,
    associated_data: bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Encrypt note content with AES-256-GCM.

    Args:
        plaintext: The note content to encrypt
        user_id: Owner's user ID (for key derivation)
        associated_data: Optional AAD (e.g., note ID) bound to ciphertext

    Returns:
        (ciphertext, nonce, tag) — all as bytes
        Note: In AES-GCM, the tag is appended to ciphertext by default.
              We split them for explicit storage.
    """
    key = derive_user_key(user_id)
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)

    # AESGCM.encrypt returns ciphertext + tag (last 16 bytes)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)

    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    return ciphertext, nonce, tag


def decrypt_note(
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    user_id: str,
    associated_data: bytes | None = None,
) -> str:
    """Decrypt note content with AES-256-GCM.

    Args:
        ciphertext: Encrypted content
        nonce: The 96-bit nonce used during encryption
        tag: The 128-bit authentication tag
        user_id: Owner's user ID (for key derivation)
        associated_data: Must match the AAD used during encryption

    Returns:
        Decrypted plaintext string

    Raises:
        cryptography.exceptions.InvalidTag: If ciphertext or AAD was tampered with
    """
    key = derive_user_key(user_id)
    aesgcm = AESGCM(key)

    # Reconstruct ciphertext + tag as expected by AESGCM.decrypt
    ct_with_tag = ciphertext + tag

    plaintext_bytes = aesgcm.decrypt(nonce, ct_with_tag, associated_data)
    return plaintext_bytes.decode("utf-8")
