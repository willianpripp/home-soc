"""dns_blocked_spike: fires on a 3x-and-20-absolute jump in blocked queries."""
from __future__ import annotations

import pathlib
from datetime import datetime, timedelta, timezone

import rules
from helpers import insert_query

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


def _entities(conn):
    with conn.cursor() as cur:
        cur.execute("select entity from rule_hit where rule_id = 'dns_blocked_spike'")
        return {r[0] for r in cur.fetchall()}


def _summary(conn, entity):
    with conn.cursor() as cur:
        cur.execute(
            "select summary from rule_hit where rule_id = 'dns_blocked_spike' and entity = %s",
            (entity,),
        )
        return cur.fetchone()[0]


def _blocked_burst(conn, client, ts, count, client_name=None):
    for i in range(count):
        insert_query(conn, ts - timedelta(minutes=i), client,
                     f"tracker{i}.example.net", "example.net", blocked=True,
                     client_name=client_name)


def test_fires_for_a_client_spiking_past_3x_and_the_floor(conn):
    now = datetime.now(timezone.utc)
    # Baseline: 5 blocked/day over the prior week (35 total). Last day: 30,
    # which is both >= 20 absolute and >= 3x the 5/day baseline. The device
    # is named, same as AdGuard would carry for a client it recognises.
    _blocked_burst(conn, "192.168.1.50", now - timedelta(days=4), 35,
                    client_name="living-room-tv")
    _blocked_burst(conn, "192.168.1.50", now - timedelta(hours=1), 30,
                    client_name="living-room-tv")
    # Same spike, but a client AdGuard never got a name for: the summary must
    # stay clean, no dangling ", device" for a name that is not there.
    _blocked_burst(conn, "192.168.1.51", now - timedelta(days=4), 35)
    _blocked_burst(conn, "192.168.1.51", now - timedelta(hours=1), 30)

    rules.run(conn, RULES_DIR)
    assert "192.168.1.50" in _entities(conn)
    assert "192.168.1.51" in _entities(conn)
    assert "living-room-tv" in _summary(conn, "192.168.1.50")
    assert "device" not in _summary(conn, "192.168.1.51")


def test_does_not_fire_for_high_but_proportionate_volume(conn):
    now = datetime.now(timezone.utc)
    # A client that is simply noisy every day: last day roughly matches the
    # prior week's own daily average, so this is volume, not a spike. Left
    # nameless, same as a client AdGuard has never been told a name for.
    _blocked_burst(conn, "192.168.1.60", now - timedelta(days=4), 210)  # 30/day
    _blocked_burst(conn, "192.168.1.60", now - timedelta(hours=1), 32)

    rules.run(conn, RULES_DIR)
    assert "192.168.1.60" not in _entities(conn)


def test_does_not_fire_under_the_absolute_floor(conn):
    now = datetime.now(timezone.utc)
    # 1/day baseline jumping to 3 is an infinite multiple of the baseline, but
    # the floor exists exactly to keep a 0-to-3 style jump from firing.
    _blocked_burst(conn, "192.168.1.70", now - timedelta(days=4), 7)  # 1/day
    _blocked_burst(conn, "192.168.1.70", now - timedelta(hours=1), 3)

    rules.run(conn, RULES_DIR)
    assert "192.168.1.70" not in _entities(conn)
