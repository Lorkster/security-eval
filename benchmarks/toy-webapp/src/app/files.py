"""Serving user-uploaded documents."""

import os
from pathlib import Path

UPLOADS = "/srv/app/uploads"


def read_document(name: str) -> bytes:
    path = os.path.join(UPLOADS, name)
    with open(path, "rb") as fh:
        return fh.read()


def read_avatar(name: str) -> bytes:
    base = Path(UPLOADS, "avatars").resolve()
    path = (base / name).resolve()
    if not path.is_relative_to(base):
        raise PermissionError(name)
    return path.read_bytes()
