"""Remote content for link previews and avatars."""

import urllib.request

AVATAR_BASE = "https://cdn.example.org/avatars"


def preview(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read(4096)


def avatar(user_id: int) -> bytes:
    url = f"{AVATAR_BASE}/{int(user_id)}.png"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read(65536)
