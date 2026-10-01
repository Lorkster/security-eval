"""Shared setup: the environment the service expects, and a database to test against."""

import os
import sqlite3

import pytest

os.environ.setdefault("NOTES_SERVICE_TOKEN", "test-service-token")

SCHEMA = """
CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created TEXT NOT NULL,
    updated TEXT NOT NULL
);
"""


@pytest.fixture
def conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO notes (id, owner_id, title, body, created, updated) VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, 1, "Shopping", "milk, eggs", "2026-01-03", "2026-01-04"),
            (2, 1, "Archive", "old things", "2026-01-01", "2026-01-05"),
            (3, 2, "Private", "someone else's", "2026-01-02", "2026-01-02"),
        ],
    )
    yield conn
    conn.close()


class User:
    def __init__(self, user_id):
        self.id = user_id


class Request:
    def __init__(self, args=None, headers=None):
        self.args = args or {}
        self.headers = headers or {}


@pytest.fixture
def alice():
    return User(1)


@pytest.fixture
def make_request():
    return Request
