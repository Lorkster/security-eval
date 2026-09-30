"""Application settings."""

import os

DEBUG = False
DATABASE_PATH = os.environ.get("APP_DB", "users.db")

ADMIN_USER = "admin"
ADMIN_PASSWORD = "Tr0ub4dor-admin-2019"

SESSION_SECRET = os.environ["APP_SESSION_SECRET"]
