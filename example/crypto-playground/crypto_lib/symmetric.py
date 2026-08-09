"""Symmetric encryption demos: AES-GCM, AES-CBC, ChaCha20-Poly1305, Fernet."""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SYMMETRIC_ALGOS = ["AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305", "Fernet"]


@dataclass
class SymResult:
    ciphertext_b64: str
    fields: dict  # extra params needed to decrypt (iv/nonce/tag/salt)


def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=200_000)
    return kdf.derive(password.encode())


def encrypt(algo: str, password: str, plaintext: str) -> SymResult:
    data = plaintext.encode()
    salt = os.urandom(16)

    if algo == "AES-256-GCM":
        key = _derive_key(password, salt)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, data, None)
        return SymResult(
            base64.b64encode(ct).decode(),
            {"salt": salt.hex(), "nonce": nonce.hex()},
        )

    if algo == "AES-256-CBC":
        key = _derive_key(password, salt)
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
        return SymResult(
            base64.b64encode(ct).decode(),
            {"salt": salt.hex(), "iv": iv.hex()},
        )

    if algo == "ChaCha20-Poly1305":
        key = _derive_key(password, salt)
        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(key).encrypt(nonce, data, None)
        return SymResult(
            base64.b64encode(ct).decode(),
            {"salt": salt.hex(), "nonce": nonce.hex()},
        )

    if algo == "Fernet":
        key = base64.urlsafe_b64encode(_derive_key(password, salt))
        ct = Fernet(key).encrypt(data)
        return SymResult(ct.decode(), {"salt": salt.hex()})

    raise ValueError(f"Unknown algorithm: {algo}")


def decrypt(algo: str, password: str, ciphertext_b64: str, fields: dict) -> str:
    salt = bytes.fromhex(fields["salt"])

    if algo == "AES-256-GCM":
        key = _derive_key(password, salt)
        nonce = bytes.fromhex(fields["nonce"])
        ct = base64.b64decode(ciphertext_b64)
        return AESGCM(key).decrypt(nonce, ct, None).decode()

    if algo == "AES-256-CBC":
        key = _derive_key(password, salt)
        iv = bytes.fromhex(fields["iv"])
        ct = base64.b64decode(ciphertext_b64)
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()

    if algo == "ChaCha20-Poly1305":
        key = _derive_key(password, salt)
        nonce = bytes.fromhex(fields["nonce"])
        ct = base64.b64decode(ciphertext_b64)
        return ChaCha20Poly1305(key).decrypt(nonce, ct, None).decode()

    if algo == "Fernet":
        key = base64.urlsafe_b64encode(_derive_key(password, salt))
        return Fernet(key).decrypt(ciphertext_b64.encode()).decode()

    raise ValueError(f"Unknown algorithm: {algo}")
