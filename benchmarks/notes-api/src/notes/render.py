"""HTML rendering."""

import hashlib
import html


def note_page(note: dict) -> str:
    title = note["title"]
    body = html.escape(note["body"])
    return f"<h1>{title}</h1><article>{body}</article>"


def note_list(rows: list) -> str:
    items = "".join(f"<li>{html.escape(r['title'])}</li>" for r in rows)
    return f"<ul>{items}</ul>"


def etag(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()
