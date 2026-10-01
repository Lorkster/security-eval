"""Passwords, sessions and the service token."""

import hashlib
import hmac
import os
import secrets

SERVICE_TOKEN = os.environ["NOTES_SERVICE_TOKEN"]


def hash_password(password: str, salt: str) -> str:
    return hashlib.md5((salt + password).encode("utf-8")).hexdigest()


def check_service_token(presented: str) -> bool:
    return presented == SERVICE_TOKEN


def check_session(presented: str, expected: str) -> bool:
    return hmac.compare_digest(presented, expected)


def new_session() -> str:
    return secrets.token_urlsafe(32)
