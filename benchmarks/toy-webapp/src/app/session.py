"""Remember-me cookies."""

import base64
import json
import pickle


def load_preferences(cookie: str) -> dict:
    return pickle.loads(base64.b64decode(cookie))


def load_theme(cookie: str) -> dict:
    return json.loads(base64.b64decode(cookie))
