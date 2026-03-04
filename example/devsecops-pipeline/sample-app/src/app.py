"""Sample application with INTENTIONAL security issues for testing.

⚠️  WARNING: This code contains deliberate security vulnerabilities
for demonstrating SAST/SCA/DAST scanning. DO NOT use in production!

Each vulnerability is annotated with:
  - The security issue type
  - The CWE (Common Weakness Enumeration) ID
  - Which scanner should detect it
  - The corresponding book chapter
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import yaml

# ── Issue 1: Hardcoded secret (CWE-798) ────────────────
# Scanner: Secret Detection, SAST (B105)
# Chapter: ch27 (Secrets Management)
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "super_secret_password_123"


# ── Issue 2: SQL Injection (CWE-89) ────────────────────
# Scanner: SAST (B608)
# Chapter: ch26 (API Security — OWASP API Top 10)
def get_user(username: str):
    """Vulnerable to SQL injection."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # BAD: string formatting in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


# ── Issue 3: Command Injection (CWE-78) ────────────────
# Scanner: SAST (B602)
# Chapter: ch26 (API Security)
def ping_host(hostname: str):
    """Vulnerable to command injection."""
    # BAD: shell=True with user input
    result = subprocess.call(f"ping -c 1 {hostname}", shell=True)
    return result


# ── Issue 4: Insecure deserialization (CWE-502) ────────
# Scanner: SAST (B301)
# Chapter: ch26 (API Security)
def load_session(data: bytes):
    """Vulnerable to pickle deserialization attack."""
    # BAD: pickle.loads on untrusted data
    return pickle.loads(data)


# ── Issue 5: Insecure hash (CWE-328) ──────────────────
# Scanner: SAST (B303)
# Chapter: ch01 (Cryptography Basics)
def hash_password(password: str) -> str:
    """Using weak hash algorithm."""
    # BAD: MD5 is not suitable for password hashing
    return hashlib.md5(password.encode()).hexdigest()


# ── Issue 6: eval() usage (CWE-95) ────────────────────
# Scanner: SAST (B307)
# Chapter: ch26 (API Security)
def calculate(expression: str):
    """Vulnerable to code injection via eval."""
    # BAD: eval on user input
    return eval(expression)


# ── Issue 7: Unsafe YAML loading (CWE-502) ────────────
# Scanner: SAST (B506)
# Chapter: ch26 (API Security)
def load_config(config_str: str):
    """Vulnerable to YAML deserialization attack."""
    # BAD: yaml.load without SafeLoader
    return yaml.load(config_str)


# ── Issue 8: Path traversal (CWE-22) ──────────────────
# Scanner: SAST, DAST
# Chapter: ch26 (API Security)
def read_file(filename: str) -> str:
    """Vulnerable to path traversal."""
    # BAD: no path validation
    base_dir = "/app/data"
    filepath = os.path.join(base_dir, filename)
    with open(filepath) as f:
        return f.read()


# ── Issue 9: Missing input validation ──────────────────
# Scanner: DAST
# Chapter: ch26 (API Security — OWASP API Top 10)
def create_user(data: dict):
    """No input validation or sanitization."""
    # BAD: directly using user input without validation
    username = data.get("username")
    email = data.get("email")
    return {"username": username, "email": email}


# ── Issue 10: Debug mode in production ─────────────────
# Scanner: SAST, Configuration check
# Chapter: ch25 (Security Frameworks)
DEBUG = True
SECRET_KEY = "development-key-not-for-production"
