from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

import psycopg


def _database_url() -> str:
    value = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL")
    if not value:
        raise RuntimeError("DATABASE_URL or SUPABASE_DB_URL is required")
    return value


@contextmanager
def get_conn() -> Iterator[psycopg.Connection]:
    conn = psycopg.connect(_database_url(), autocommit=False)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
