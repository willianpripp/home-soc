"""Database access and schema migration.

No ORM, matching the rest of this household's apps: the queries here are the
interesting part and hiding them behind a mapper would make the detection rules
harder to read, which is the opposite of the point.

Migrations are numbered SQL files applied in order and recorded in
`schema_version`. Alembic was considered and skipped: it earns its keep when
models drive the schema, and here the schema drives everything else. A file you
can read top to bottom is worth more in a repo whose whole argument is that the
logic should be legible.
"""
from __future__ import annotations

import os
import pathlib

import psycopg

SCHEMA_DIR = pathlib.Path(__file__).resolve().parent.parent / "schema"


def dsn() -> str:
    url = os.environ.get("HOMESOC_DATABASE_URL", "").strip()
    if not url:
        raise SystemExit(
            "HOMESOC_DATABASE_URL is not set. Copy .env.example to .env and fill it in."
        )
    return url


def connect() -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=False)


def applied_versions(conn: psycopg.Connection) -> set[int]:
    """Versions already applied, or an empty set on a virgin database.

    The table may not exist yet, and asking for it is how we find out. The
    rollback matters: in Postgres a failed statement poisons the whole
    transaction, so without it every later statement in this connection would
    fail with 'current transaction is aborted'.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("select version from schema_version")
            return {r[0] for r in cur.fetchall()}
    except psycopg.errors.UndefinedTable:
        conn.rollback()
        return set()


def migrate(conn: psycopg.Connection) -> list[str]:
    """Apply every migration not yet recorded. Safe to run on every start."""
    done = applied_versions(conn)
    applied: list[str] = []
    for path in sorted(SCHEMA_DIR.glob("*.sql")):
        version = int(path.name.split("_", 1)[0])
        if version in done:
            continue
        with conn.cursor() as cur:
            cur.execute(path.read_text())
        conn.commit()
        applied.append(path.name)
    return applied
