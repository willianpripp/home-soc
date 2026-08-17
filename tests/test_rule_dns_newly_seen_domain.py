"""dns_newly_seen_domain: fires for a domain whose first_seen is recent."""
from __future__ import annotations

import pathlib
from datetime import datetime, timedelta, timezone

import rules
from helpers import insert_domain, insert_query

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


def _entities(conn):
    with conn.cursor() as cur:
        cur.execute("select entity from rule_hit where rule_id = 'dns_newly_seen_domain'")
        return {r[0] for r in cur.fetchall()}


def test_fires_for_a_domain_first_seen_within_24_hours(conn):
    now = datetime.now(timezone.utc)
    insert_domain(conn, "freshly-seen.example", now - timedelta(hours=2),
                   query_count=3, blocked_count=1)
    insert_query(conn, now - timedelta(hours=2), "192.168.1.10",
                 "freshly-seen.example", "freshly-seen.example")

    rules.run(conn, RULES_DIR)
    assert "freshly-seen.example" in _entities(conn)


def test_does_not_fire_for_a_domain_seen_long_ago(conn):
    now = datetime.now(timezone.utc)
    insert_domain(conn, "long-known.example", now - timedelta(days=30),
                   last_seen=now - timedelta(hours=1), query_count=100)

    rules.run(conn, RULES_DIR)
    assert "long-known.example" not in _entities(conn)
