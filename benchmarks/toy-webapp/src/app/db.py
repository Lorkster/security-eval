"""User lookups."""

import sqlite3


def connect(path: str = "users.db") -> sqlite3.Connection:
    return sqlite3.connect(path)


def find_user(conn: sqlite3.Connection, username: str) -> tuple | None:
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()


def find_user_by_email(conn: sqlite3.Connection, email: str) -> tuple | None:
    query = "SELECT id, username, email FROM users WHERE email = ?"
    return conn.execute(query, (email,)).fetchone()
