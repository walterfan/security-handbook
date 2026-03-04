"""Password hashing with Argon2id.

Demonstrates ch02 — Cryptographic Fundamentals:
  - Why Argon2id over bcrypt/scrypt (memory-hard, side-channel resistant)
  - Configurable cost parameters (time, memory, parallelism)
  - Automatic random salt generation

Security notes:
  - Argon2id combines Argon2i (side-channel resistant) and Argon2d (GPU resistant)
  - OWASP recommends: time_cost=3, memory_cost=64MB, parallelism=4
  - The salt is embedded in the hash string (no separate storage needed)
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from config import settings

# Initialize hasher with configurable parameters
_hasher = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
    hash_len=32,
    salt_len=16,
    type=PasswordHasher.Type.ID,  # Argon2id
)


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password with Argon2id.

    Returns a PHC-format string like:
        $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>

    The salt is auto-generated and embedded in the output.
    """
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2id hash.

    Returns True if the password matches, False otherwise.
    Never raises on wrong password — timing-safe comparison is built in.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Check if a hash was created with outdated parameters.

    Call this after successful login to transparently upgrade hashes
    when cost parameters are increased.
    """
    return _hasher.check_needs_rehash(hashed_password)
