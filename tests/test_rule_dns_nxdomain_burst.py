"""dns_nxdomain_burst: fires on a 3x-and-30-absolute burst of genuine
(unblocked) NXDOMAIN answers."""
from __future__ import annotations

import pathlib
from datetime import datetime, timedelta, timezone

import rules
from helpers import insert_query

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


def _entities(conn):
    with conn.cursor() as cur:
        cur.execute("select entity from rule_hit where rule_id = 'dns_nxdomain_burst'")
        return {r[0] for r in cur.fetchall()}


def _nxdomain_burst(conn, client, ts, count):
    for i in range(count):
        insert_query(conn, ts - timedelta(minutes=i), client,
                     f"random{i}92kx.example.net", "example.net",
                     blocked=False, status="NXDOMAIN")


def test_fires_for_a_client_spiking_past_3x_and_the_floor(conn):
    now = datetime.now(timezone.utc)
    # Baseline: 5 NXDOMAIN/day over the prior week (35 total). Last day: 40,
    # which is both >= 30 absolute and >= 3x the 5/day baseline.
    _nxdomain_burst(conn, "192.168.1.51", now - timedelta(days=4), 35)
    _nxdomain_burst(conn, "192.168.1.51", now - timedelta(hours=1), 40)

    rules.run(conn, RULES_DIR)
    assert "192.168.1.51" in _entities(conn)


def test_does_not_fire_for_high_but_proportionate_volume(conn):
    now = datetime.now(timezone.utc)
    # A client that always generates a lot of NXDOMAIN: last day roughly
    # matches the prior week's own daily average, so this is volume, not a
    # burst.
    _nxdomain_burst(conn, "192.168.1.61", now - timedelta(days=4), 280)  # 40/day
    _nxdomain_burst(conn, "192.168.1.61", now - timedelta(hours=1), 42)

    rules.run(conn, RULES_DIR)
    assert "192.168.1.61" not in _entities(conn)


def test_does_not_fire_under_the_absolute_floor(conn):
    now = datetime.now(timezone.utc)
    # A near-zero baseline jumping to a handful is an infinite multiple of the
    # baseline, but the floor exists exactly to keep that kind of jump quiet.
    _nxdomain_burst(conn, "192.168.1.71", now - timedelta(days=4), 7)  # 1/day
    _nxdomain_burst(conn, "192.168.1.71", now - timedelta(hours=1), 6)

    rules.run(conn, RULES_DIR)
    assert "192.168.1.71" not in _entities(conn)


def test_blocked_nxdomain_answers_do_not_count_toward_the_burst(conn):
    now = datetime.now(timezone.utc)
    # AdGuard blocks answer NXDOMAIN too, but that is the household's own
    # filtering working as intended, not a client grinding through DGA
    # candidates. A burst built entirely out of blocked queries must not fire.
    for i in range(40):
        insert_query(conn, now - timedelta(minutes=i), "192.168.1.81",
                     f"tracker{i}.example.net", "example.net", blocked=True)

    rules.run(conn, RULES_DIR)
    assert "192.168.1.81" not in _entities(conn)
