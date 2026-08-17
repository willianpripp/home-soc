"""dns_tunnel_volume: fires per registrable_domain on high distinct-qname
cardinality AND high average label entropy; neither alone is enough."""
from __future__ import annotations

import pathlib
from datetime import datetime, timezone

import rules
from helpers import insert_query

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


def _entities(conn):
    with conn.cursor() as cur:
        cur.execute("select entity from rule_hit where rule_id = 'dns_tunnel_volume'")
        return {r[0] for r in cur.fetchall()}


def test_fires_for_high_cardinality_and_high_entropy(conn):
    now = datetime.now(timezone.utc)
    for i in range(55):
        insert_query(conn, now, "192.168.1.30", f"q{i}xk9zvd7.tunnel.example",
                     "tunnel.example", label_entropy=3.6)

    rules.run(conn, RULES_DIR)
    assert "tunnel.example" in _entities(conn)


def test_does_not_fire_for_high_cardinality_but_word_shaped_labels(conn):
    now = datetime.now(timezone.utc)
    # A big legitimate service: plenty of distinct subdomains (shard IDs,
    # region codes), but they are word-shaped, not random, so average entropy
    # stays under the line.
    for i in range(60):
        insert_query(conn, now, "192.168.1.31", f"shard-region-us-east-{i}.cdn.example",
                     "cdn.example", label_entropy=2.4)

    rules.run(conn, RULES_DIR)
    assert "cdn.example" not in _entities(conn)


def test_does_not_fire_for_high_entropy_under_the_cardinality_floor(conn):
    now = datetime.now(timezone.utc)
    # High entropy but nowhere near 50 distinct names: an ordinary DGA/tunnel
    # lookup or two, not the volume a real tunnel needs to move any data.
    for i in range(10):
        insert_query(conn, now, "192.168.1.32", f"q{i}xk9zvd7.small.example",
                     "small.example", label_entropy=3.8)

    rules.run(conn, RULES_DIR)
    assert "small.example" not in _entities(conn)
