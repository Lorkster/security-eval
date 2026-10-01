"""Storage for notes."""

import sqlite3

SORTABLE = ("created", "title", "updated")


def connect(path: str = "notes.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def list_notes(conn: sqlite3.Connection, owner_id: int, order: str) -> list[sqlite3.Row]:
    sql = "SELECT id, title, created FROM notes WHERE owner_id = ? ORDER BY " + order
    return conn.execute(sql, (owner_id,)).fetchall()


def search_notes(conn: sqlite3.Connection, owner_id: int, term: str) -> list[sqlite3.Row]:
    sql = "SELECT id, title FROM notes WHERE owner_id = ? AND title LIKE ?"
    return conn.execute(sql, (owner_id, f"%{term}%")).fetchall()


def get_note(conn: sqlite3.Connection, note_id: int) -> sqlite3.Row | None:
    sql = "SELECT id, owner_id, title, body FROM notes WHERE id = ?"
    return conn.execute(sql, (note_id,)).fetchone()
