"""Shared test fixtures: a scratch database, migrated fresh, per test.

`ingest/` is a directory of scripts run by `python cli.py`, not an installed
package (see ruff.toml's known-first-party comment for why), so tests reach
its modules the same way cli.py's own imports do: sys.path gets the ingest/
directory prepended once, here, before any test module imports `db` or
`rules`.
"""
from __future__ import annotations

import os
import pathlib
import sys
import urllib.parse
import uuid

import psycopg
import pytest

INGEST_DIR = pathlib.Path(__file__).resolve().parent.parent / "ingest"
sys.path.insert(0, str(INGEST_DIR))

import db

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


def _base_url() -> str:
    """The connection used to create and drop scratch databases.

    Defaults to the throwaway Postgres instance this repo's own development
    environment runs on. HOMESOC_TEST_DATABASE_URL overrides it, so CI can
    point the whole suite at a service container instead without this file
    changing.
    """
    return os.environ.get(
        "HOMESOC_TEST_DATABASE_URL", "postgresql://homesoc@localhost:55492/homesoc"
    )


def _with_dbname(url: str, db_name: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, f"/{db_name}", parts.query, ""))


@pytest.fixture
def conn():
    """A freshly migrated scratch database, created before the test and
    dropped again after, so tests never share state or ordering with each
    other.
    """
    base_url = _base_url()
    db_name = f"homesoc_test_{uuid.uuid4().hex[:12]}"

    admin = psycopg.connect(base_url, autocommit=True)
    try:
        admin.execute(f'create database "{db_name}"')
    finally:
        admin.close()

    test_conn = psycopg.connect(_with_dbname(base_url, db_name), autocommit=False)
    db.migrate(test_conn)
    try:
        yield test_conn
    finally:
        test_conn.close()
        admin = psycopg.connect(base_url, autocommit=True)
        try:
            admin.execute(f'drop database "{db_name}"')
        finally:
            admin.close()
