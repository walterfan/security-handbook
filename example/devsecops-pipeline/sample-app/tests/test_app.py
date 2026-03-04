"""Basic tests for sample app (to show testing is part of DevSecOps)."""


def test_create_user():
    from src.app import create_user
    result = create_user({"username": "alice", "email": "alice@example.com"})
    assert result["username"] == "alice"


def test_hash_password():
    from src.app import hash_password
    h = hash_password("test")
    assert len(h) == 32  # MD5 hex digest length
