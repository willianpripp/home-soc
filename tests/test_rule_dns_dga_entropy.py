"""dns_dga_entropy: fires for high-entropy, non-trivially-short qnames."""
from __future__ import annotations

import pathlib
from datetime import datetime, timezone

import rules
from helpers import insert_query

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


def _entities(conn):
    with conn.cursor() as cur:
        cur.execute("select entity from rule_hit where rule_id = 'dns_dga_entropy'")
        return {r[0] for r in cur.fetchall()}


def test_fires_for_a_high_entropy_long_label(conn):
    now = datetime.now(timezone.utc)
    # xk9qz3vd7hw2.top: the demo's own DGA-shaped domain, entropy well above
    # 3.5 and well past the 12-character floor.
    insert_query(conn, now, "192.168.1.34", "xk9qz3vd7hw2.top", "xk9qz3vd7hw2.top",
                 label_entropy=3.8)

    rules.run(conn, RULES_DIR)
    assert "xk9qz3vd7hw2.top" in _entities(conn)


def test_does_not_fire_for_low_entropy(conn):
    now = datetime.now(timezone.utc)
    # An ordinary English-ish hostname: long enough to clear the floor, but
    # nowhere near 3.5 bits/char.
    insert_query(conn, now, "192.168.1.20", "www.example-shopping-site.com",
                 "example-shopping-site.com", label_entropy=2.1)

    rules.run(conn, RULES_DIR)
    assert "example-shopping-site.com" not in _entities(conn)


def test_does_not_fire_for_a_short_high_entropy_qname(conn):
    now = datetime.now(timezone.utc)
    # High entropy but under the 12-character floor: a naive rule without the
    # floor would fire on this and drown in ordinary short hostnames, since a
    # tiny alphabet maxes out entropy with no room for real structure.
    insert_query(conn, now, "192.168.1.20", "zx7q.io", "zx7q.io", label_entropy=4.0)

    rules.run(conn, RULES_DIR)
    assert "zx7q.io" not in _entities(conn)
